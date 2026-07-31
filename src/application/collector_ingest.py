"""CollectorIngestService: backpressure + dedup, then produce onto D1's stream
transport (roadmap M3/D2).

``org_id``/``source_id`` always come from the ``CollectorIdentity`` the
caller already authenticated (``src/external/middleware/collector_mtls.py``)
-- this service never reads either off the event payload itself (see
``CollectorIdentity``'s own docstring for the invariant this upholds). This
is the one place D1's ``StreamIngestAdapter`` and the dedup/backpressure
checks meet; the route (``src/external/routes/collector_ingest.py``) is a
thin DTO/HTTP-status translation layer only.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from src.adapter.queue.event_dedup import EventDedupChecker
from src.adapter.queue.stream_ingest import StreamIngestAdapter
from src.domain.collector import CollectorIdentity
from src.exceptions import KronOSException

logger = logging.getLogger(__name__)


class BackpressureError(KronOSException):
    """Raised when a (org, source) stream is at/over its configured max length.

    Checked once per request, up front, against the *current* stream
    length -- a real, enforced limit (not advisory): a very large single
    batch could still push the stream slightly past the threshold before
    the next request is rejected. Tightening this to a per-event check is
    a reasonable follow-up (D5's observability scope), not done here to
    avoid one Redis round trip per event on the common, non-saturated path.
    """


@dataclass(frozen=True)
class EventOutcome:
    accepted: bool
    duplicate: bool
    message_id: str | None


class CollectorIngestService:
    """Per-event: canonicalize -> hash -> dedup check -> produce.

    Backpressure is checked once per call, before any event in the batch is
    processed, so a saturated stream is rejected outright rather than
    partially accepted.
    """

    def __init__(
        self,
        stream_ingest_adapter: StreamIngestAdapter,
        dedup_checker: EventDedupChecker,
        *,
        max_stream_length: int,
        dedup_ttl_seconds: int,
    ) -> None:
        self._stream = stream_ingest_adapter
        self._dedup = dedup_checker
        self._max_stream_length = max_stream_length
        self._dedup_ttl_seconds = dedup_ttl_seconds

    async def ingest_events(
        self, identity: CollectorIdentity, events: list[dict[str, Any]]
    ) -> list[EventOutcome]:
        """Ingest *events* onto ``identity``'s own (org_id, source_id) stream.

        Raises :class:`BackpressureError` if the stream is already at
        capacity -- a collector should back off and retry later rather than
        have events silently accepted and then dropped somewhere downstream.
        """
        current_length = await self._stream.approximate_length(identity.org_id, identity.source_id)
        if current_length >= self._max_stream_length:
            logger.warning(
                "collector_ingest_backpressure_rejected",
                extra={
                    "org_id": str(identity.org_id),
                    "source_id": identity.source_id,
                    "current_length": current_length,
                    "max_stream_length": self._max_stream_length,
                },
            )
            raise BackpressureError(
                f"Stream kronos:stream:{identity.org_id}:{identity.source_id} at capacity "
                f"({current_length} >= {self._max_stream_length})"
            )

        return [await self._ingest_one(identity, event) for event in events]

    async def _ingest_one(self, identity: CollectorIdentity, event: dict[str, Any]) -> EventOutcome:
        payload = _canonical_bytes(event)
        content_hash = hashlib.sha256(payload).hexdigest()

        if await self._dedup.is_duplicate(
            identity.org_id, identity.source_id, content_hash, ttl_seconds=self._dedup_ttl_seconds
        ):
            logger.info(
                "collector_ingest_duplicate_skipped",
                extra={
                    "org_id": str(identity.org_id),
                    "source_id": identity.source_id,
                    "content_hash": content_hash,
                },
            )
            return EventOutcome(accepted=False, duplicate=True, message_id=None)

        message_id = await self._stream.produce(identity.org_id, identity.source_id, payload)
        return EventOutcome(accepted=True, duplicate=False, message_id=message_id)


def _canonical_bytes(event: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding so identical logical events hash identically
    regardless of key insertion order (a real retry may re-serialize)."""
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
