"""Concrete, non-destructive ``PlaybookAction`` implementations shipped with
roadmap H1 -- see ``src/application/playbook.py``'s own module docstring
for why nothing here has a real external side effect (that is H2's
explicitly separate, gated scope).

Two actions, deliberately heterogeneous, to prove the registry genuinely
needs zero core-engine changes to add either kind: one that drives a real,
already-audited KronOS state change (``TransitionDetectionTriageAction``),
and one that is entirely stateless (``LogNotificationAction``).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from src.application.detection_triage import DetectionTriageService
from src.application.playbook import PlaybookAction
from src.domain.detection import DetectionTriageState
from src.domain.user import TenantContext
from src.exceptions import PlaybookError

logger = logging.getLogger(__name__)


class TransitionDetectionTriageAction(PlaybookAction):
    """Drives the REAL, already-existing ``DetectionTriageService.transition()``
    -- a real, non-destructive, already-audited FSM move entirely within
    KronOS's own data (roadmap C4). Proves the playbook engine can drive
    something genuinely real end-to-end, not a fabricated example built
    only to exercise the framework.

    ``DetectionTriageService`` audits the underlying transition itself
    (``DETECTION_TRIAGE_TRANSITIONED``/``_FAILED``) -- this action's own
    ``execute()`` does not duplicate that audit call; ``PlaybookExecutionService``
    separately audits the playbook-level step outcome
    (``PLAYBOOK_STEP_EXECUTED``/``_FAILED``), so one real transition
    produces two distinct, complementary audit rows: "the FSM moved" and
    "this playbook step ran," never one masquerading as the other.
    """

    def __init__(self, triage_service: DetectionTriageService) -> None:
        self._triage = triage_service

    @property
    def action_name(self) -> str:
        return "transition_detection_triage"

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        """*params* must carry ``detection_id`` (str UUID) and
        ``target_state`` (one of ``DetectionTriageState``'s own values).
        Raises ``PlaybookError`` for a malformed params dict; a legal-but-
        rejected FSM transition raises the underlying ``DetectionStateError``
        unchanged (the caller's own audit trail already distinguishes the
        two failure kinds by exception type)."""
        try:
            detection_id = uuid.UUID(params["detection_id"])
            target_state = DetectionTriageState(params["target_state"])
        except (KeyError, ValueError) as exc:
            raise PlaybookError(
                "transition_detection_triage requires a real detection_id (UUID str) "
                "and a real target_state (DetectionTriageState value)",
                context={"params": params, "error": str(exc)},
            ) from exc

        updated = await self._triage.transition(detection_id, target_state, tenant)
        return {
            "detection_id": str(updated.detection_id),
            "triage_state": updated.triage_state.value,
        }


class LogNotificationAction(PlaybookAction):
    """A trivial, entirely stateless action -- no repository, no external
    call, structured-logs *params["message"]* and returns it verbatim.

    Exists specifically to prove "new action = registration, not an edit"
    concretely: this action shares nothing with
    ``TransitionDetectionTriageAction`` beyond the same ``PlaybookAction``
    contract, yet ``PlaybookExecutionService`` runs both identically.
    """

    @property
    def action_name(self) -> str:
        return "log_notification"

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        message = params.get("message")
        if not isinstance(message, str) or not message:
            raise PlaybookError(
                "log_notification requires a non-empty string params['message']",
                context={"params": params},
            )
        logger.info(
            "playbook_notification",
            extra={"org_id": str(tenant.org_id), "message": message},
        )
        return {"message": message}
