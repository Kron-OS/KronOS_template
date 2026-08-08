"""IntegrationSourceIngestService: orchestrates one PUSH webhook call or one
POLL cycle end-to-end for a registered ``IntegrationSource`` (roadmap Q1).

Mirrors ``CollectorIngestService``'s own real, already-verified
backpressure -> dedup -> produce pipeline (``src/application/collector_ingest.py``)
onto D1's ``StreamIngestAdapter`` -- deliberately reusing that same real
transport rather than inventing a second one, per the roadmap's own SS4
"delegate ECS mapping to the existing pipeline" design (see
``src/application/integration_source.py``'s own module docstring for the
full "why fetch is separate from mapping" argument this service is the
concrete other half of).

Genuinely different from ``CollectorIngestService`` in one respect: this
service's raw events are already opaque ``bytes`` (an ``IntegrationSource``
already split them out of a webhook body or a poll response), not
``dict[str, Any]`` event objects needing canonical-JSON serialization
first -- so the content-hash dedup key here is SHA-256 over the raw bytes
directly. This is not a shortcut: a webhook/poll payload is not guaranteed
to be JSON at all (Wazuh's ``alert_format json`` is, but the ABC does not
assume it), so re-serializing would be dishonest for a non-JSON source.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from src.adapter.queue.event_dedup import EventDedupChecker
from src.adapter.queue.stream_ingest import StreamIngestAdapter
from src.adapter.repository.source_cursor import SourceCursorRepository
from src.application.audit_log import AuditLogService
from src.application.integration_source import (
    IntegrationSource,
    IntegrationSourceError,
    IntegrationSourceRegistry,
)
from src.domain.audit import AuditEventType
from src.domain.integration_source import (
    IntegrationDeliveryMode,
    IntegrationSourceIdentity,
    SourceCursor,
)
from src.exceptions import KronOSException

logger = logging.getLogger(__name__)


class IntegrationSourceBackpressureError(KronOSException):
    """Raised when a (org, source) stream is at/over its configured max
    length -- same real, enforced (not advisory) semantics as
    ``CollectorIngestService.BackpressureError``, checked once per call."""


@dataclass(frozen=True)
class EventOutcome:
    accepted: bool
    duplicate: bool
    message_id: str | None


@dataclass(frozen=True)
class PollCycleResult:
    """One completed poll cycle's real outcome."""

    outcomes: list[EventOutcome]
    cursor_advanced: bool


class IntegrationSourceIngestService:
    """Per-call: look up the registered source, fetch/split raw events,
    dedup + backpressure + produce onto the stream transport, persist a
    poll cursor if applicable, audit the whole batch once."""

    def __init__(
        self,
        registry: IntegrationSourceRegistry,
        stream_ingest_adapter: StreamIngestAdapter,
        dedup_checker: EventDedupChecker,
        cursor_repository: SourceCursorRepository,
        audit_log: AuditLogService,
        *,
        max_stream_length: int,
        dedup_ttl_seconds: int,
    ) -> None:
        self._registry = registry
        self._stream = stream_ingest_adapter
        self._dedup = dedup_checker
        self._cursors = cursor_repository
        self._audit = audit_log
        self._max_stream_length = max_stream_length
        self._dedup_ttl_seconds = dedup_ttl_seconds

    async def ingest_push(
        self, identity: IntegrationSourceIdentity, raw_body: bytes
    ) -> list[EventOutcome]:
        """Split *raw_body* into events via the registered source and
        produce each onto ``identity``'s own (org_id, source_id) stream.

        Raises :class:`IntegrationSourceError` if no PUSH-mode source is
        registered under ``identity.source_type``.
        """
        source = self._require_source(identity.source_type, IntegrationDeliveryMode.PUSH)
        raw_events = await source.parse_push_event(raw_body)

        outcomes = await self._produce_batch(identity, raw_events)
        accepted = sum(1 for o in outcomes if o.accepted)
        await self._audit.log(
            AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED,
            org_id=identity.org_id,
            details={
                "source_id": identity.source_id,
                "source_type": identity.source_type,
                "auth_method": identity.auth_method,
                "event_count": len(raw_events),
                "accepted_count": accepted,
                "duplicate_count": len(raw_events) - accepted,
            },
        )
        return outcomes

    async def run_poll_cycle(self, identity: IntegrationSourceIdentity) -> PollCycleResult:
        """Fetch one page of new events from the registered POLL source
        since this (org, source)'s persisted cursor, produce them, and
        persist the returned watermark.

        Raises :class:`IntegrationSourceError` if no POLL-mode source is
        registered, or if the real poll call itself fails -- a
        ``POLL_FAILED`` audit event is written first so a failed cycle is
        never silently invisible in the audit trail, then the exception is
        re-raised (CLAUDE.md invariant #8: fail loudly).
        """
        source = self._require_source(identity.source_type, IntegrationDeliveryMode.POLL)
        cursor = await self._cursors.get(identity.org_id, identity.source_id)

        try:
            result = await source.poll(identity, cursor)
        except IntegrationSourceError as exc:
            await self._audit.log(
                AuditEventType.INTEGRATION_SOURCE_POLL_FAILED,
                org_id=identity.org_id,
                details={
                    "source_id": identity.source_id,
                    "source_type": identity.source_type,
                    "error": str(exc),
                },
            )
            raise

        outcomes = await self._produce_batch(identity, result.raw_events)

        cursor_advanced = result.next_cursor is not None
        if result.next_cursor is not None:
            await self._cursors.upsert(
                SourceCursor(
                    org_id=identity.org_id,
                    source_id=identity.source_id,
                    cursor_value=result.next_cursor,
                    updated_at=datetime.now(UTC),
                )
            )

        accepted = sum(1 for o in outcomes if o.accepted)
        await self._audit.log(
            AuditEventType.INTEGRATION_SOURCE_POLL_COMPLETED,
            org_id=identity.org_id,
            details={
                "source_id": identity.source_id,
                "source_type": identity.source_type,
                "auth_method": identity.auth_method,
                "event_count": len(result.raw_events),
                "accepted_count": accepted,
                "duplicate_count": len(result.raw_events) - accepted,
                "cursor_advanced": cursor_advanced,
            },
        )
        return PollCycleResult(outcomes=outcomes, cursor_advanced=cursor_advanced)

    def _require_source(
        self, source_type: str, expected_mode: IntegrationDeliveryMode
    ) -> IntegrationSource:
        source = self._registry.get(source_type)
        if source is None:
            raise IntegrationSourceError(
                f"No IntegrationSource registered for source_type={source_type!r}"
            )
        if source.delivery_mode != expected_mode:
            raise IntegrationSourceError(
                f"IntegrationSource {source_type!r} is {source.delivery_mode!r}-mode, "
                f"cannot be used as a {expected_mode!r} source"
            )
        return source

    async def _produce_batch(
        self, identity: IntegrationSourceIdentity, raw_events: list[bytes]
    ) -> list[EventOutcome]:
        if not raw_events:
            return []

        current_length = await self._stream.approximate_length(identity.org_id, identity.source_id)
        if current_length >= self._max_stream_length:
            logger.warning(
                "integration_source_backpressure_rejected",
                extra={
                    "org_id": str(identity.org_id),
                    "source_id": identity.source_id,
                    "current_length": current_length,
                    "max_stream_length": self._max_stream_length,
                },
            )
            raise IntegrationSourceBackpressureError(
                f"Stream kronos:stream:{identity.org_id}:{identity.source_id} at capacity "
                f"({current_length} >= {self._max_stream_length})"
            )

        return [
            await self._produce_one(identity.org_id, identity.source_id, raw) for raw in raw_events
        ]

    async def _produce_one(
        self, org_id: uuid.UUID, source_id: str, raw_event: bytes
    ) -> EventOutcome:
        content_hash = hashlib.sha256(raw_event).hexdigest()

        if await self._dedup.is_duplicate(
            org_id, source_id, content_hash, ttl_seconds=self._dedup_ttl_seconds
        ):
            logger.info(
                "integration_source_duplicate_skipped",
                extra={"org_id": str(org_id), "source_id": source_id, "content_hash": content_hash},
            )
            return EventOutcome(accepted=False, duplicate=True, message_id=None)

        message_id = await self._stream.produce(org_id, source_id, raw_event)
        return EventOutcome(accepted=True, duplicate=False, message_id=message_id)
