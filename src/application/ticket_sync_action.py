"""SyncDetectionTicketAction: a ``PlaybookAction`` that creates or updates a
real ticket in an external ITSM/ticketing system for a ``Detection``, and
records the external ticket id back on KronOS's own side for traceability
(roadmap M7/H4 -- closes Milestone M7).

**Audit discipline mirrors H2's ``ContainmentAction`` exactly** (roadmap
invariant #4): ``TICKET_SYNC_ATTEMPTED`` is logged BEFORE the real outbound
``TicketingSystem`` call is even made, so a crash inside that call can never
erase the fact an attempt happened; ``TICKET_SYNC_FAILED`` is a distinct,
specific record from the generic ``PLAYBOOK_STEP_FAILED``
``PlaybookExecutionService`` also logs for any failed step.

**Derived opinions never mutate primary evidence (invariant #5).** A
successful response from the external system updates ONLY
``Detection.external_ticket_id`` -- a pure traceability pointer -- via
``Detection.with_external_ticket_id()``. It is written with
``expected_state=`` the ``triage_state`` this action itself read, so a
triage transition racing concurrently with this action is detected as a
real optimistic-concurrency conflict (``StorageError``, audited as
``TICKET_SYNC_FAILED``) rather than this action's stale in-memory
``Detection`` silently overwriting a newer triage_state when the whole row
is rewritten -- this action never once calls ``with_triage_state`` or
otherwise touches the FSM itself.

**Tenant isolation (invariant #3): computed, never supplied.** ``org_id``
is always *tenant*'s own authenticated context; the Detection looked up is
scoped to ``(detection_id, tenant.org_id)`` exactly like
``CollectForensicArtifactAction``/``DetectionTriageService`` -- a
cross-tenant or nonexistent id is a real, loud ``PlaybookError``.
"""

from __future__ import annotations

import uuid
from typing import Any

from src.adapter.repository.detection import DetectionRepository
from src.adapter.ticketing.ticketing_system import TicketingSystem
from src.application.audit_log import AuditLogService
from src.application.playbook import PlaybookAction
from src.domain.audit import AuditEventType
from src.domain.user import TenantContext
from src.exceptions import PlaybookError

_DEFAULT_UPDATE_NOTE = "KronOS detection re-synced (no note supplied)."


class SyncDetectionTicketAction(PlaybookAction):
    """Creates a ticket the first time a Detection is synced, and appends
    an update note on every subsequent sync -- decided purely from whether
    ``Detection.external_ticket_id`` is already set, never from a
    caller-supplied ``params`` flag (so a step can't be tricked into
    "creating" a second, duplicate ticket for an already-tracked Detection).

    Params:
      - ``detection_id`` (str UUID, required).
      - ``note`` (str, optional): extra context for an UPDATE call only
        (e.g. "escalated by playbook X"); ignored on the first CREATE call,
        where the description is always freshly composed from the real
        Detection fields instead.
    """

    def __init__(
        self,
        detection_repository: DetectionRepository,
        ticketing_system: TicketingSystem,
        audit_log: AuditLogService,
    ) -> None:
        self._detections = detection_repository
        self._ticketing = ticketing_system
        self._audit = audit_log

    @property
    def action_name(self) -> str:
        return "sync_detection_ticket"

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        try:
            detection_id = uuid.UUID(params["detection_id"])
        except (KeyError, ValueError) as exc:
            raise PlaybookError(
                "sync_detection_ticket requires a real detection_id (UUID str)",
                context={"params": params, "error": str(exc)},
            ) from exc

        detection = await self._detections.get_by_id(detection_id, tenant.org_id)
        if detection is None:
            raise PlaybookError(
                "sync_detection_ticket: no Detection with this id in the caller's own org",
                context={"detection_id": str(detection_id), "org_id": str(tenant.org_id)},
            )

        operation = "update" if detection.external_ticket_id else "create"
        metadata = {
            "detection_id": str(detection.detection_id),
            "org_id": str(tenant.org_id),
            "org_alias": tenant.org_alias,
            "case_id": str(detection.case_id) if detection.case_id else None,
            "finding_id": detection.finding_id,
            "detector_name": detection.detector_name,
            "triage_state": detection.triage_state.value,
            "attack_tags": list(detection.attack_tags),
            "risk_score": detection.risk_score,
        }

        await self._audit.log(
            AuditEventType.TICKET_SYNC_ATTEMPTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            case_id=detection.case_id,
            details={
                "detection_id": str(detection_id),
                "operation": operation,
                "existing_ticket_id": detection.external_ticket_id,
            },
        )

        try:
            if operation == "create":
                ticket = await self._ticketing.create_ticket(
                    title=f"KronOS detection {detection.finding_id} ({detection.detector_name})",
                    description=(
                        f"Rules matched: {[m.rule_id for m in detection.rule_matches]}. "
                        f"ATT&CK: {list(detection.attack_tags)}. "
                        f"Triage state: {detection.triage_state.value}."
                    ),
                    severity=detection.rule_severity,
                    metadata=metadata,
                )
            else:
                assert detection.external_ticket_id is not None  # narrowed by `operation` above
                ticket = await self._ticketing.update_ticket(
                    detection.external_ticket_id,
                    note=params.get("note", _DEFAULT_UPDATE_NOTE),
                    metadata=metadata,
                )
        except Exception as exc:  # noqa: BLE001 -- audited below, then re-raised unchanged
            await self._audit.log(
                AuditEventType.TICKET_SYNC_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                case_id=detection.case_id,
                details={
                    "detection_id": str(detection_id),
                    "operation": operation,
                    "error": str(exc),
                },
            )
            raise

        updated = detection.with_external_ticket_id(ticket.ticket_id)
        try:
            await self._detections.update(updated, expected_state=detection.triage_state)
        except Exception as exc:  # noqa: BLE001 -- audited below, then re-raised unchanged
            # The real external ticket call above already succeeded -- this
            # is a real, honest partial-failure mode (e.g. a concurrent
            # triage transition raced this action's own stale read), not a
            # KronOS-side ticketing bug. Reported loudly, never silently
            # dropped (CLAUDE.md SS1#8); a future reconciliation pass that
            # re-reads the current row and retries the persist is real
            # follow-up scope, not built speculatively here.
            await self._audit.log(
                AuditEventType.TICKET_SYNC_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                case_id=detection.case_id,
                details={
                    "detection_id": str(detection_id),
                    "operation": operation,
                    "external_ticket_id": ticket.ticket_id,
                    "error": str(exc),
                    "note": (
                        "external ticket call succeeded but persisting "
                        "external_ticket_id locally failed"
                    ),
                },
            )
            raise

        await self._audit.log(
            AuditEventType.TICKET_SYNC_EXECUTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            case_id=detection.case_id,
            details={
                "detection_id": str(detection_id),
                "operation": operation,
                "external_ticket_id": ticket.ticket_id,
                "ticket_url": ticket.url,
            },
        )
        return {
            "detection_id": str(detection_id),
            "operation": operation,
            "external_ticket_id": ticket.ticket_id,
            "ticket_url": ticket.url,
        }
