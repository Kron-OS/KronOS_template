"""SyncDetectionToSiemAction: a ``PlaybookAction`` that pushes a real
``Detection`` to one org's own configured external SIEM sink (connector
marketplace, `/admin/connectors`), via ``DetectionSinkPushService`` (Gap
Audit 2026-08 P1-1 / roadmap Milestone V2, item a).

**Per-org rewrite (connector marketplace).** This used to be constructed
with one fixed, process-wide ``DetectionSinkPushService`` built once at
DI-startup time from global ``Settings`` -- every org's detections pushed
to the SAME configured Splunk/CEF/Sentinel destination regardless of
tenant. It now resolves *this org's own* config at execute() time via
``ConnectorConfigService.resolve_runtime_config(tenant.org_id, sink_name)``
and builds a fresh sink/mapper pair from it
(``build_sink_and_mapper_from_config`` in ``src/external/dependencies.py``)
-- so each org's detections only ever reach that org's own destination,
and an org with no config for this sink gets a loud, clear
``PlaybookError`` instead of silently using (or silently no-op-ing on)
whatever global sink used to be configured. This is a deliberate,
recorded decision (no silent global-Settings fallback), matching the
plan's own "no collision, independent per client" requirement exactly the
same way ``celery_defender.py``'s per-org rewrite does.

**Mirrors ``SyncDetectionTicketAction``'s exact shape (H4's own precedent
for "a PlaybookAction that pushes a Detection to an external system"), not
a new pattern:** collaborators injected via constructor, never constructed
here; the Detection is looked up scoped to ``(detection_id, tenant.org_id)``
-- a cross-tenant or nonexistent id is a real, loud ``PlaybookError``;
tenant isolation is computed from ``tenant``, never supplied via ``params``
(invariant #3).

**Audit discipline reused, not duplicated (roadmap invariant #4).** This
action's ``execute()`` does not itself audit the push -- ``DetectionSinkPushService
.push()`` already logs ``SINK_PUSH_ATTEMPTED``/``_EXECUTED``/``_FAILED``
around the real outbound call. It DOES call
``ConnectorConfigService.record_success``/``record_failure`` after each
attempt (same circuit-breaker bookkeeping the Defender poll loop uses) --
that is genuinely new responsibility this action owns, not a duplicate of
anything ``DetectionSinkPushService`` already does.

**One instance per sink type, not one instance switching on a ``params``
field.** ``action_name`` is derived from the constructor's own
``sink_name`` (e.g. ``"sync_detection_to_siem_splunk-hec"``) so
``PlaybookActionRegistry`` can register one ``SyncDetectionToSiemAction``
per sink type unconditionally now (whether any org has actually configured
it yet is a runtime, per-org question resolved inside ``execute()``, not a
boot-time registration question) -- a playbook step names exactly which
sink it wants by using that sink's own action_name.
"""

from __future__ import annotations

import uuid
from typing import Any, Callable

from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.adapter.repository.detection import DetectionRepository
from src.application.audit_log import AuditLogService
from src.application.connector_config import ConnectorConfigService
from src.application.detection_sink_mapper import DetectionEventMapper
from src.application.detection_sink_push import DetectionSinkPushService
from src.application.playbook import PlaybookAction
from src.domain.user import TenantContext
from src.exceptions import PlaybookError

SinkFactory = Callable[[str, dict[str, str]], tuple[IntegrationSink, DetectionEventMapper]]


class SyncDetectionToSiemAction(PlaybookAction):
    """Pushes one Detection to the caller's own org's configured *sink_name*.

    Params:
      - ``detection_id`` (str UUID, required).
    """

    def __init__(
        self,
        sink_name: str,
        detection_repository: DetectionRepository,
        connector_config_service: ConnectorConfigService,
        sink_factory: SinkFactory,
        audit_log: AuditLogService,
    ) -> None:
        self._sink_name = sink_name
        self._detections = detection_repository
        self._connector_config_service = connector_config_service
        self._sink_factory = sink_factory
        self._audit_log = audit_log

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

        resolved = await self._connector_config_service.resolve_runtime_config(
            tenant.org_id, self._sink_name
        )
        if resolved is None:
            raise PlaybookError(
                f"{self.action_name}: {self._sink_name} is not configured (or is disabled) "
                "for this organization",
                context={"org_id": str(tenant.org_id), "sink_name": self._sink_name},
            )

        sink, mapper = self._sink_factory(self._sink_name, resolved)
        push_service = DetectionSinkPushService(sink, mapper, self._audit_log)

        # DetectionSinkPushService.push() audits SINK_PUSH_ATTEMPTED/
        # _EXECUTED/_FAILED around this call and raises unchanged on any
        # batch failure (its own "fail-fast, not partial-success" idiom) --
        # this action's own job on top of that is the per-org circuit
        # breaker bookkeeping (record_success/record_failure), mirroring
        # celery_defender.py's identical Defender-poll pattern.
        try:
            result = await push_service.push([detection], tenant)
        except Exception:
            await self._connector_config_service.record_failure(tenant.org_id, self._sink_name)
            raise
        await self._connector_config_service.record_success(tenant.org_id, self._sink_name)

        return {
            "detection_id": str(detection_id),
            "sink": self._sink_name,
            "batch_count": result.batch_count,
            "all_acknowledged": result.all_acknowledged,
            "ack_statuses": [ack.status.value for ack in result.acks],
        }
