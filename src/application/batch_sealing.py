"""BatchSealingService: seals stream segments into immutable, WORM-protected,
TSA-anchored, Merkle-provable batches (roadmap M3/D3).

Structural sibling of ``AuditLogService.anchor_day()``
(``src/application/audit_log.py``): collect events -> compute a Merkle root
over per-event hashes -> optionally/here-mandatorily call the TSA -> persist
an anchor (here, a full ``SealedBatch`` row, not just a root+token) -> emit
one audit event. It differs from ``anchor_day()`` in three deliberate ways,
each justified by what this item actually needs:

1. Operates on *stream events* (opaque ``StreamMessage`` payloads consumed
   off D1's ``StreamIngestAdapter``), not already-audited ``AuditEvent``
   rows -- there is no pre-existing hash chain to lean on here, so the
   per-event hash IS the leaf (``sha256(payload)``), computed fresh.
2. Seals *segments* (time- or size-bounded, via ``SealingTriggerPolicy``),
   not once a day -- continuous telemetry cannot wait a day for custody.
3. The TSA token is **mandatory, not best-effort**. ``anchor_day()``
   deliberately treats a TSA outage as non-fatal (Postgres's own hash chain
   is already durable custody; the TSA token is an enhancement). Here, the
   roadmap's own objective lists "one WORM object, one TSA token, one audit
   event, a Merkle root" as the *exactly four* things one sealed batch must
   produce -- a batch missing its TSA token is not "sealed with an
   enhancement pending", it is not sealed at all. So a TSA failure here
   aborts the whole seal (see ``_seal``): the WORM write may have already
   happened (an orphaned WORM object is an acceptable, documented trade-off
   -- see this module's own docstring section below -- since it contains no
   data that is not *also* safely captured by the eventual successful
   re-seal of the same still-unacked messages), but nothing is acked, no
   Postgres row is written, and no success audit event is logged.

Failure semantics (the two binding, non-negotiable requirements this item's
brief states):

- **Sealing failure never acks the stream.** ``ack()`` is the very last
  call in ``_seal`` -- it only runs after the WORM write, the TSA call, the
  repository save, and the audit-log write have all succeeded. Any
  exception before that point propagates as ``BatchSealFailedError``
  (wrapping the real cause) with the source messages left exactly as they
  were: delivered to this consumer, unacked, pending in the consumer
  group's PEL (D1's own at-least-once mechanism -- ``reclaim_stale()``,
  called at the top of every ``seal_pending()`` cycle with
  ``min_idle_ms=0``, re-collects them for the next attempt automatically;
  see that method's docstring for why ``min_idle_ms=0`` is the right choice
  for a single-sealer-per-source design).
- **A MAXLEN trim of unsealed events pages, not warns.** ``_check_watermark_gap``
  compares the stream's real, current ``earliest_message_id()`` against the
  last successfully sealed batch's ``last_message_id`` watermark. Since
  MAXLEN always evicts the *oldest* entries first, the earliest retained id
  ever exceeding the last-sealed watermark can only mean trimming has eaten
  into events that were never sealed -- real, silent evidence loss. This
  codebase has no real external paging/alerting integration anywhere
  (verified by grep -- no PagerDuty/Opsgenie/webhook hook exists in
  ``src/``), so "page" here honestly means: a ``logger.critical`` structured
  log line (the single most severe level this codebase's logging ever
  uses -- every existing call site tops out at ``.warning``/``.error``), a
  dedicated ``AuditEventType.BATCH_SEAL_WATERMARK_GAP_DETECTED`` audit
  event (the gap belongs in the tamper-evident chain itself, not only a
  log), and ``EvidenceLossDetectedError`` raised so no caller can silently
  swallow it -- the concrete hook point a real paging integration (e.g. a
  log-based alert rule, or a future ``AlertSink`` ABC) would attach to.

Sealer fall-behind alerting (roadmap M3/D5): ``_check_sealer_fall_behind``
reuses the exact same idiom (``logger.critical`` + a dedicated
``AuditEventType.SEALER_FALL_BEHIND_DETECTED`` + a dedicated
``SealerFallBehindDetectedError`` exception class exists) for a distinctly
*different* condition than the watermark gap above: "the oldest pending
event has waited past ``stall_alert_after_seconds`` -- a threshold that must
be set well above ``SealingTriggerPolicy``'s own trigger threshold, since a
healthy sealer running on schedule would have already sealed this segment
long before reaching it. Crossing it is real evidence the seal cycle itself
isn't being invoked/isn't keeping up (no beat task calling
``seal_pending()``, a stuck process, etc.), a liveness problem. Deliberately
**not raised** from ``seal_pending()``'s own automatic path, unlike
``EvidenceLossDetectedError`` above: the watermark gap describes data
already, irreversibly trimmed by the time it's detected -- there is nothing
left to do but refuse to silently continue. The fall-behind condition
describes data that is still fully present and pending, and this very
``seal_pending()`` call is about to attempt to seal exactly that data (per
the normal ``trigger.should_seal`` check right after) -- raising here would
abort the one call that could resolve the staleness, which is the wrong
failure mode for a liveness signal. So this pages (log + audit event) and
continues; see ``SealerFallBehindDetectedError``'s own docstring for the
deliberate hook point left for a future caller that DOES want to raise on
this (e.g. an admin liveness/health-check route).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from src.adapter.queue.stream_ingest import StreamIngestAdapter, StreamMessage
from src.adapter.repository.sealed_batch import SealedBatchRepository
from src.adapter.storage.sealed_batch_storage import SealedBatchStorage
from src.application.audit_log import AuditLogService
from src.application.sealing_trigger_policy import SealingTriggerPolicy
from src.application.timestamping import RFC3161TimestampService
from src.domain.audit import AuditEventType
from src.domain.merkle import build_merkle_root
from src.domain.sealed_batch import SealedBatch
from src.exceptions import BatchSealFailedError, EvidenceLossDetectedError

# SealerFallBehindDetectedError (src/exceptions.py) is deliberately NOT
# raised anywhere in this module -- see _check_sealer_fall_behind's own
# docstring for why. It exists as a hook point for a future caller (e.g. an
# admin liveness/health-check route) that DOES want to raise on this
# condition.

logger = logging.getLogger(__name__)


def _message_id_ms(message_id: str) -> int:
    """Parse a Redis Streams id ("<ms>-<seq>") into its millisecond component."""
    return int(message_id.split("-", 1)[0])


def _message_id_tuple(message_id: str) -> tuple[int, int]:
    ms, _, seq = message_id.partition("-")
    return int(ms), int(seq or 0)


class BatchSealingService:
    """Consumes pending stream events for one (org_id, source_id) and, once
    the trigger policy fires, seals them into one ``SealedBatch``."""

    def __init__(
        self,
        stream_adapter: StreamIngestAdapter,
        storage: SealedBatchStorage,
        timestamp_service: RFC3161TimestampService | None,
        audit_log: AuditLogService,
        repository: SealedBatchRepository,
        trigger_policy: SealingTriggerPolicy,
        *,
        consumer_group: str = "kronos-sealer",
        consumer_name: str = "sealer-1",
        poll_count: int = 1000,
        poll_block_ms: int = 1000,
        stall_alert_after_seconds: float | None = None,
    ) -> None:
        self._stream = stream_adapter
        self._storage = storage
        self._timestamp_service = timestamp_service
        self._audit_log = audit_log
        self._repository = repository
        self._trigger = trigger_policy
        self._group = consumer_group
        self._consumer_name = consumer_name
        self._poll_count = poll_count
        self._poll_block_ms = poll_block_ms
        # None (the default) disables the check entirely -- an operator
        # opts in with a real value, deliberately set well above whatever
        # SealingTriggerPolicy threshold is in use for the same (org,
        # source) (see this class's module docstring for why the two
        # thresholds are, and must stay, distinct).
        self._stall_alert_after_seconds = stall_alert_after_seconds

    async def seal_pending(self, org_id: uuid.UUID, source_id: str) -> SealedBatch | None:
        """One full seal cycle for (org_id, source_id).

        Returns the newly sealed ``SealedBatch``, or ``None`` if there was
        nothing to seal yet (no pending events) or the trigger policy says
        it is not time yet (events remain pending, picked up again next
        cycle -- see ``reclaim_stale(min_idle_ms=0)`` below).
        """
        await self._stream.ensure_consumer_group(org_id, source_id, self._group, start="0")
        await self._check_watermark_gap(org_id, source_id)

        # min_idle_ms=0 re-collects THIS consumer's own previously-delivered,
        # still-unacked backlog (a prior cycle that decided not to seal yet,
        # or a prior attempt that failed before acking) alongside anything
        # left pending by a genuinely dead consumer -- the real, existing D1
        # primitive this design reuses instead of adding new stream-adapter
        # surface for "re-read my own pending entries". Documented
        # simplification: assumes a single active sealer per (org, source);
        # true multi-sealer concurrency would need per-message ownership
        # leases beyond this, flagged as follow-up, not attempted here.
        carry_over = await self._stream.reclaim_stale(
            org_id, source_id, self._group, self._consumer_name, min_idle_ms=0
        )
        fresh = await self._stream.consume(
            org_id,
            source_id,
            self._group,
            self._consumer_name,
            count=self._poll_count,
            block_ms=self._poll_block_ms,
        )
        messages = [*carry_over, *fresh]
        if not messages:
            return None

        oldest_age_seconds = (
            datetime.now(UTC).timestamp() * 1000 - _message_id_ms(messages[0].message_id)
        ) / 1000
        await self._check_sealer_fall_behind(org_id, source_id, len(messages), oldest_age_seconds)
        if not self._trigger.should_seal(
            pending_event_count=len(messages), oldest_pending_age_seconds=oldest_age_seconds
        ):
            logger.info(
                "batch_sealing_deferred",
                extra={
                    "org_id": str(org_id),
                    "source_id": source_id,
                    "pending_event_count": len(messages),
                    "oldest_pending_age_seconds": oldest_age_seconds,
                },
            )
            return None

        return await self._seal(org_id, source_id, messages)

    async def _seal(
        self, org_id: uuid.UUID, source_id: str, messages: list[StreamMessage]
    ) -> SealedBatch:
        batch_id = uuid.uuid4()
        leaf_hashes = [hashlib.sha256(m.payload).hexdigest() for m in messages]
        message_ids = [m.message_id for m in messages]
        merkle_root = build_merkle_root(leaf_hashes)
        manifest = _build_manifest(batch_id, org_id, source_id, messages, leaf_hashes)

        try:
            worm_bucket, worm_key = await self._storage.put_batch(
                org_id, source_id, batch_id, manifest
            )

            tsa_token: bytes | None = None
            if self._timestamp_service is not None:
                # Mandatory, not best-effort -- see module docstring point 3.
                # A failure here propagates and aborts the whole seal.
                tsa_token = await self._timestamp_service.timestamp(bytes.fromhex(merkle_root))

            sealed = SealedBatch(
                batch_id=batch_id,
                org_id=org_id,
                source_id=source_id,
                sealed_at=datetime.now(UTC),
                event_count=len(messages),
                leaf_hashes=tuple(leaf_hashes),
                message_ids=tuple(message_ids),
                merkle_root=merkle_root,
                worm_bucket=worm_bucket,
                worm_object_key=worm_key,
                tsa_token=tsa_token,
                first_message_id=message_ids[0],
                last_message_id=message_ids[-1],
            )
            await self._repository.save(sealed)
            await self._audit_log.log(
                AuditEventType.BATCH_SEALED,
                org_id=org_id,
                details={
                    "batch_id": str(batch_id),
                    "source_id": source_id,
                    "event_count": len(messages),
                    "merkle_root": merkle_root,
                    "worm_bucket": worm_bucket,
                    "worm_object_key": worm_key,
                    "first_message_id": message_ids[0],
                    "last_message_id": message_ids[-1],
                    "tsa_token": tsa_token.hex() if tsa_token else None,
                },
            )
        except Exception as exc:
            logger.critical(
                "batch_seal_failed_events_remain_unacked",
                extra={
                    "org_id": str(org_id),
                    "source_id": source_id,
                    "event_count": len(messages),
                    "first_message_id": message_ids[0],
                    "last_message_id": message_ids[-1],
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
            try:
                await self._audit_log.log(
                    AuditEventType.BATCH_SEAL_FAILED,
                    org_id=org_id,
                    details={
                        "source_id": source_id,
                        "event_count": len(messages),
                        "first_message_id": message_ids[0],
                        "last_message_id": message_ids[-1],
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    },
                )
            except Exception:  # noqa: BLE001 -- best-effort, must not mask the real cause
                logger.warning("batch_seal_failure_audit_write_also_failed")
            raise BatchSealFailedError(
                "Batch sealing failed; source events remain unacked for retry",
                context={
                    "org_id": str(org_id),
                    "source_id": source_id,
                    "event_count": len(messages),
                    "error": str(exc),
                },
            ) from exc

        await self._stream.ack(org_id, source_id, self._group, *message_ids)
        logger.info(
            "batch_sealed",
            extra={
                "org_id": str(org_id),
                "source_id": source_id,
                "batch_id": str(batch_id),
                "event_count": len(messages),
                "merkle_root": merkle_root,
            },
        )
        return sealed

    async def _check_watermark_gap(self, org_id: uuid.UUID, source_id: str) -> None:
        """Detect whether MAXLEN trimming has evicted events that were never
        sealed. See module docstring for what "page" means in this codebase."""
        last_sealed = await self._repository.get_last_sealed(org_id, source_id)
        if last_sealed is None:
            return  # nothing sealed yet for this (org, source) -- no watermark to violate

        earliest = await self._stream.earliest_message_id(org_id, source_id)
        if earliest is None:
            # Stream is completely empty. Ambiguous on its own (could be a
            # brand-new stream key, or everything including recent unsealed
            # data was trimmed) -- flagged, not resolved, since D1's adapter
            # has no way to distinguish "never had more data" from "all of
            # it, including unsealed data, is gone" once the stream is
            # empty. Real follow-up: a persistent last-produced-id watermark
            # independent of the stream itself (e.g. written by
            # CollectorIngestService on every produce()) would close this.
            return

        if _message_id_tuple(earliest) > _message_id_tuple(last_sealed.last_message_id):
            logger.critical(
                "sealing_watermark_gap_detected",
                extra={
                    "org_id": str(org_id),
                    "source_id": source_id,
                    "last_sealed_message_id": last_sealed.last_message_id,
                    "earliest_retained_message_id": earliest,
                },
            )
            await self._audit_log.log(
                AuditEventType.BATCH_SEAL_WATERMARK_GAP_DETECTED,
                org_id=org_id,
                details={
                    "source_id": source_id,
                    "last_sealed_message_id": last_sealed.last_message_id,
                    "earliest_retained_message_id": earliest,
                },
            )
            raise EvidenceLossDetectedError(
                "Stream retention has trimmed events that were never sealed",
                context={
                    "org_id": str(org_id),
                    "source_id": source_id,
                    "last_sealed_message_id": last_sealed.last_message_id,
                    "earliest_retained_message_id": earliest,
                },
            )

    async def _check_sealer_fall_behind(
        self,
        org_id: uuid.UUID,
        source_id: str,
        pending_event_count: int,
        oldest_pending_age_seconds: float,
    ) -> None:
        """Page (log + audit event, do NOT raise) if the oldest pending event
        has aged past ``stall_alert_after_seconds`` -- see module docstring
        for why this is a liveness signal, not evidence loss, and therefore
        does not abort the seal attempt this same cycle is about to make."""
        if self._stall_alert_after_seconds is None:
            return
        if oldest_pending_age_seconds < self._stall_alert_after_seconds:
            return

        logger.critical(
            "sealer_fall_behind_detected",
            extra={
                "org_id": str(org_id),
                "source_id": source_id,
                "pending_event_count": pending_event_count,
                "oldest_pending_age_seconds": oldest_pending_age_seconds,
                "stall_alert_after_seconds": self._stall_alert_after_seconds,
            },
        )
        await self._audit_log.log(
            AuditEventType.SEALER_FALL_BEHIND_DETECTED,
            org_id=org_id,
            details={
                "source_id": source_id,
                "pending_event_count": pending_event_count,
                "oldest_pending_age_seconds": oldest_pending_age_seconds,
                "stall_alert_after_seconds": self._stall_alert_after_seconds,
            },
        )


def _build_manifest(
    batch_id: uuid.UUID,
    org_id: uuid.UUID,
    source_id: str,
    messages: list[StreamMessage],
    leaf_hashes: list[str],
) -> bytes:
    """Build the one WORM object's real content: the batch's real event
    payloads plus enough metadata to independently recompute every leaf hash."""
    doc: dict[str, Any] = {
        "batch_id": str(batch_id),
        "org_id": str(org_id),
        "source_id": source_id,
        "event_count": len(messages),
        "events": [
            {
                "message_id": m.message_id,
                "leaf_hash": leaf_hashes[i],
                "payload_base64": _b64(m.payload),
            }
            for i, m in enumerate(messages)
        ],
    }
    return json.dumps(doc, sort_keys=True).encode("utf-8")


def _b64(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")
