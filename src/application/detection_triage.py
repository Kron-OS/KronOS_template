"""DetectionTriageService: applies the triage FSM to a Detection, audited.

Roadmap M2/C4. Every transition -- success or rejection -- goes through
AuditLogService (CLAUDE.md SS A.2); mirrors the explicit try/except +
audit.log idiom ParsingOrchestrationService.start_parsing already
establishes (rather than the audit_context contextmanager, so the illegal-
transition case can be distinguished from a real error and re-raised as the
original DetectionStateError, not wrapped generically).
"""

from __future__ import annotations

import logging
import uuid

from src.adapter.repository.detection import DetectionRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.detection import Detection, DetectionTriageState
from src.domain.user import TenantContext
from src.exceptions import DetectionStateError, ValidationError

logger = logging.getLogger(__name__)


class DetectionTriageService:
    """Validates and applies triage FSM transitions on a Detection."""

    def __init__(self, detection_repository: DetectionRepository, audit_log: AuditLogService) -> None:
        self._repo = detection_repository
        self._audit = audit_log

    async def transition(
        self,
        detection_id: uuid.UUID,
        target_state: DetectionTriageState,
        tenant: TenantContext,
    ) -> Detection:
        """Move *detection_id* to *target_state*, or raise DetectionStateError.

        Both the successful transition and the rejection are audited --
        a rejected attempt is itself a fact worth a permanent record (e.g.
        "analyst X tried to mark a NEW finding TRUE_POSITIVE without
        investigating it first").
        """
        detection = await self._repo.get_by_id(detection_id, tenant.org_id)
        if detection is None:
            raise ValidationError(
                "Detection not found",
                context={"detection_id": str(detection_id), "org_id": str(tenant.org_id)},
            )

        from_state = detection.triage_state
        try:
            updated = detection.with_triage_state(target_state)
        except DetectionStateError as exc:
            await self._audit.log(
                AuditEventType.DETECTION_TRIAGE_TRANSITION_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                case_id=detection.case_id,
                details={
                    "detection_id": str(detection_id),
                    "from_state": from_state.value,
                    "to_state": target_state.value,
                    "error": str(exc),
                },
            )
            raise

        await self._repo.update(updated, expected_state=from_state)
        await self._audit.log(
            AuditEventType.DETECTION_TRIAGE_TRANSITIONED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            case_id=detection.case_id,
            details={
                "detection_id": str(detection_id),
                "from_state": from_state.value,
                "to_state": target_state.value,
            },
        )
        logger.info(
            "detection_triage_transitioned",
            extra={
                "detection_id": str(detection_id),
                "from_state": from_state.value,
                "to_state": target_state.value,
            },
        )
        return updated
