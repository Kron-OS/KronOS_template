"""DetectionSinkPushService: orchestrates pushing ``Detection``s to one
``IntegrationSink``, via one ``DetectionEventMapper``, with full audit
discipline (KAFKA_AND_INTEGRATIONS_ROADMAP.md R1).

**Audit discipline mirrors ``ContainmentAction``/``SyncDetectionTicketAction``
exactly** (roadmap invariant #4): ``SINK_PUSH_ATTEMPTED`` is logged, per
real batch, BEFORE the real outbound ``IntegrationSink.push_events()`` call
is even made, so a crash inside that call can never erase the fact an
attempt happened. ``SINK_PUSH_FAILED`` is a distinct, specific record
(mapping failure, auth failure, or transport failure all surface through
the same real exception path and are all audited the same honest way --
"this batch did not confirm delivery," never silently absorbed).

**This is deliberately NOT a ``PlaybookAction``.** Building the concrete
``SyncDetectionToSiemAction`` (or per-vendor equivalents) that would wrap
this service inside a ``Playbook`` step is explicit R2-R4 scope -- this
class exists so those future actions (and any other caller, e.g. a
scheduled bulk-export job) can all reuse the identical map -> batch ->
push -> audit sequence without re-deriving it, per this roadmap's own
"foundation only" framing for R1.

**Fail-fast, not partial-success (mirrors ``TicketingSystem``/
``ContainmentAction``'s own "raise, don't return a partial result"
idiom).** If any batch fails, the exception propagates immediately after
being audited -- ``SinkPushResult`` is only ever returned for a fully
successful ``push()`` where every batch got a real, non-exceptional
``SinkAck`` back (its own honest ``ACKNOWLEDGED``/``UNACKNOWLEDGED``
status per batch, surfaced via ``SinkPushResult.all_acknowledged``).
"""

from __future__ import annotations

from collections.abc import Sequence

from src.adapter.integration_sink.batching import chunk_events
from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.application.audit_log import AuditLogService
from src.application.detection_sink_mapper import DetectionEventMapper
from src.domain.audit import AuditEventType
from src.domain.detection import Detection
from src.domain.integration_sink import SinkAck, SinkPushResult
from src.domain.user import TenantContext


class DetectionSinkPushService:
    """Maps, batches, pushes, and audits *detections* against one *sink*.

    *mapper* and *sink* are both injected (never constructed here) -- a new
    target is a new ``(DetectionEventMapper, IntegrationSink)`` pair handed
    to a new ``DetectionSinkPushService`` instance, zero edits to this
    class (roadmap invariant #1).
    """

    def __init__(
        self,
        sink: IntegrationSink,
        mapper: DetectionEventMapper,
        audit_log: AuditLogService,
    ) -> None:
        self._sink = sink
        self._mapper = mapper
        self._audit = audit_log

    async def push(self, detections: Sequence[Detection], tenant: TenantContext) -> SinkPushResult:
        """Map, batch, and push every one of *detections* to the configured sink.

        *tenant* is always the authenticated caller's own ``TenantContext``
        (roadmap invariant #3) -- used only for audit attribution here;
        which Detections are visible to push is the caller's own
        responsibility (mirrors ``SyncDetectionTicketAction``'s own
        division of labor: this service does not itself look Detections
        up by id/org).
        """
        # Gap Audit Milestone LL: a per-batch case_id, so these audit rows
        # are visible to case-scoped views (kronos-attest case-report,
        # GET /api/cases/{case_id}/audit) exactly like
        # DetectionTriageService.transition() already is. Only set when a
        # batch is unambiguously all-one-case (today's only real caller,
        # SyncDetectionToSiemAction, always pushes a single Detection, so
        # this is always unambiguous in practice) -- a batch straddling
        # multiple cases gets an honest ``None`` rather than a guessed value.
        case_by_detection_id = {
            str(detection.detection_id): detection.case_id for detection in detections
        }

        mapped_events = [self._mapper.map(detection) for detection in detections]
        batches = list(
            chunk_events(
                mapped_events,
                max_batch_events=self._sink.max_batch_events,
                max_batch_bytes=self._sink.max_batch_bytes,
            )
        )

        acks: list[SinkAck] = []
        for batch_index, batch in enumerate(batches):
            detection_ids = [event.source_detection_id for event in batch]
            batch_case_ids = {case_by_detection_id[did] for did in detection_ids}
            case_id = batch_case_ids.pop() if len(batch_case_ids) == 1 else None
            await self._audit.log(
                AuditEventType.SINK_PUSH_ATTEMPTED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                case_id=case_id,
                details={
                    "batch_index": batch_index,
                    "batch_count": len(batches),
                    "event_count": len(batch),
                    "detection_ids": detection_ids,
                },
            )
            try:
                ack = await self._sink.push_events(batch)
            except Exception as exc:  # noqa: BLE001 -- audited below, then re-raised unchanged
                await self._audit.log(
                    AuditEventType.SINK_PUSH_FAILED,
                    org_id=tenant.org_id,
                    actor_user_id=tenant.user_id,
                    actor_username=tenant.username,
                    case_id=case_id,
                    details={
                        "batch_index": batch_index,
                        "batch_count": len(batches),
                        "event_count": len(batch),
                        "detection_ids": detection_ids,
                        "error": str(exc),
                    },
                )
                raise

            await self._audit.log(
                AuditEventType.SINK_PUSH_EXECUTED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                case_id=case_id,
                details={
                    "batch_index": batch_index,
                    "batch_count": len(batches),
                    "event_count": len(batch),
                    "detection_ids": detection_ids,
                    "ack_status": ack.status.value,
                    "ack_detail": ack.detail,
                },
            )
            acks.append(ack)

        return SinkPushResult(
            detection_count=len(detections),
            batch_count=len(batches),
            acks=tuple(acks),
        )
