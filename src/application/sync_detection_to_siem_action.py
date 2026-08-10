"""SyncDetectionToSiemAction: a ``PlaybookAction`` that pushes a real
``Detection`` to one configured external SIEM sink via
``DetectionSinkPushService`` (Gap Audit 2026-08 P1-1 / roadmap Milestone V2,
item a).

**The gap this closes.** ``DetectionSinkPushService``/``SplunkHecSink``/
``CefSyslogSink``/``SentinelHttpSink`` (roadmap R1-R4) were all real, tested,
and dev/prod-wired for config -- but zero routes and zero ``PlaybookAction``s
ever called ``DetectionSinkPushService.push()``. The whole R-series sink
work was unreachable from any real KronOS workflow. This is the concrete
action ``DetectionSinkPushService``'s own module docstring named as R2-R4's
explicit follow-up scope.

**Mirrors ``SyncDetectionTicketAction``'s exact shape (H4's own precedent
for "a PlaybookAction that pushes a Detection to an external system"), not
a new pattern:** collaborators injected via constructor, never constructed
here; the Detection is looked up scoped to ``(detection_id, tenant.org_id)``
-- a cross-tenant or nonexistent id is a real, loud ``PlaybookError``;
tenant isolation is computed from ``tenant``, never supplied via ``params``
(invariant #3).

**Audit discipline reused, not duplicated (roadmap invariant #4).** Unlike
``SyncDetectionTicketAction`` (which audits its own
``TICKET_SYNC_ATTEMPTED``/``_EXECUTED``/``_FAILED`` because
``TicketingSystem`` itself has no audit discipline of its own), this
action's ``execute()`` audits nothing directly -- ``DetectionSinkPushService
.push()`` already logs ``SINK_PUSH_ATTEMPTED``/``_EXECUTED``/``_FAILED``
around the real outbound call (see that class's own docstring), so this
action is a thin adapter: resolve the Detection, delegate, return the real
result. Mirrors ``TransitionDetectionTriageAction``'s own "collaborator
already audits itself, don't duplicate" division of labor exactly.

**One instance per configured sink, not one instance switching on a
``params`` field.** ``action_name`` is derived from the constructor's own
``sink_name`` (e.g. ``"sync_detection_to_siem_splunk"``) so a deployment
with more than one sink configured (e.g. Splunk AND Sentinel) can register
one ``SyncDetectionToSiemAction`` per sink into the same
``PlaybookActionRegistry`` without a second registration silently replacing
the first (see that registry's own docstring on why a repeated
``action_name`` replaces, not errors) -- a playbook step names exactly
which sink it wants by using that sink's own action_name, the same
explicit-by-name contract every other registered action already uses.
"""

from __future__ import annotations

import uuid
from typing import Any

from src.adapter.repository.detection import DetectionRepository
from src.application.detection_sink_push import DetectionSinkPushService
from src.application.playbook import PlaybookAction
from src.domain.user import TenantContext
from src.exceptions import PlaybookError


class SyncDetectionToSiemAction(PlaybookAction):
    """Pushes one Detection to *push_service*'s configured sink.

    Params:
      - ``detection_id`` (str UUID, required).
    """

    def __init__(
        self,
        sink_name: str,
        detection_repository: DetectionRepository,
        push_service: DetectionSinkPushService,
    ) -> None:
        self._sink_name = sink_name
        self._detections = detection_repository
        self._push_service = push_service

    @property
    def action_name(self) -> str:
        return f"sync_detection_to_siem_{self._sink_name}"

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        try:
            detection_id = uuid.UUID(params["detection_id"])
        except (KeyError, ValueError) as exc:
            raise PlaybookError(
                f"{self.action_name} requires a real detection_id (UUID str)",
                context={"params": params, "error": str(exc)},
            ) from exc

        detection = await self._detections.get_by_id(detection_id, tenant.org_id)
        if detection is None:
            raise PlaybookError(
                f"{self.action_name}: no Detection with this id in the caller's own org",
                context={"detection_id": str(detection_id), "org_id": str(tenant.org_id)},
            )

        # DetectionSinkPushService.push() audits SINK_PUSH_ATTEMPTED/
        # _EXECUTED/_FAILED around this call and raises unchanged on any
        # batch failure (its own "fail-fast, not partial-success" idiom) --
        # nothing here needs to catch/re-audit that outcome.
        result = await self._push_service.push([detection], tenant)

        return {
            "detection_id": str(detection_id),
            "sink": self._sink_name,
            "batch_count": result.batch_count,
            "all_acknowledged": result.all_acknowledged,
            "ack_statuses": [ack.status.value for ack in result.acks],
        }
