"""PlaybookExecutionService: runs a declarative ``Playbook`` step by step,
auditing every step's input, output, and decision (roadmap M7/H1).

Same orchestration shape as ``DetectionSyncService``/``CorrelationSyncService``:
resolve real state (here, the registered action for each step), execute the
real work, audit the outcome. Strictly the audit boundary for playbook
execution -- individual ``PlaybookAction``s never audit anything themselves
(see ``src/application/playbook.py``'s own docstring), so there is exactly
one place a step's audit trail can be produced, never two competing copies.

**Design decision: fail-fast, not continue-on-error.** A playbook step
often depends causally on the one before it (e.g. a later notification
step describing "what was done" would be actively misleading if an
earlier step silently failed but execution continued as if nothing
happened). Halting on the first failure is the conservative default this
codebase's own precedent already favors for anything response-adjacent
(roadmap H2's own "no destructive action without explicit authorization"
theme is the same instinct: prefer stopping over guessing). A future
per-step "continue on failure" flag is real, legitimate follow-up scope
(see this item's own roadmap STATUS note), not built speculatively here.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from src.application.audit_log import AuditLogService
from src.application.playbook import PlaybookActionRegistry
from src.domain.audit import AuditEventType
from src.domain.playbook import (
    Playbook,
    PlaybookExecutionResult,
    PlaybookStepOutcome,
    PlaybookStepResult,
)
from src.domain.user import TenantContext

logger = logging.getLogger(__name__)


class PlaybookExecutionService:
    """Executes a ``Playbook`` against *tenant*'s own org, step by step, fully audited."""

    def __init__(self, registry: PlaybookActionRegistry, audit_log: AuditLogService) -> None:
        self._registry = registry
        self._audit = audit_log

    async def execute(self, playbook: Playbook, tenant: TenantContext) -> PlaybookExecutionResult:
        started_at = datetime.now(UTC)
        await self._audit.log(
            AuditEventType.PLAYBOOK_EXECUTION_STARTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={
                "playbook_id": str(playbook.playbook_id),
                "playbook_name": playbook.name,
                "step_count": len(playbook.steps),
            },
        )

        step_results: list[PlaybookStepResult] = []
        halted_early = False
        for step in playbook.steps:
            action = self._registry.get_action(step.action_name)
            if action is None:
                error = f"No PlaybookAction registered for action_name '{step.action_name}'"
                step_results.append(
                    PlaybookStepResult(
                        step_id=step.step_id,
                        action_name=step.action_name,
                        params=step.params,
                        outcome=PlaybookStepOutcome.FAILED,
                        error=error,
                    )
                )
                await self._audit.log(
                    AuditEventType.PLAYBOOK_STEP_FAILED,
                    org_id=tenant.org_id,
                    actor_user_id=tenant.user_id,
                    actor_username=tenant.username,
                    details={
                        "playbook_id": str(playbook.playbook_id),
                        "step_id": step.step_id,
                        "action_name": step.action_name,
                        "params": step.params,
                        "error": error,
                    },
                )
                halted_early = True
                break

            try:
                output = await action.execute(step.params, tenant)
            except Exception as exc:  # noqa: BLE001 -- audited below, then this halts the run
                step_results.append(
                    PlaybookStepResult(
                        step_id=step.step_id,
                        action_name=step.action_name,
                        params=step.params,
                        outcome=PlaybookStepOutcome.FAILED,
                        error=str(exc),
                    )
                )
                await self._audit.log(
                    AuditEventType.PLAYBOOK_STEP_FAILED,
                    org_id=tenant.org_id,
                    actor_user_id=tenant.user_id,
                    actor_username=tenant.username,
                    details={
                        "playbook_id": str(playbook.playbook_id),
                        "step_id": step.step_id,
                        "action_name": step.action_name,
                        "params": step.params,
                        "error": str(exc),
                    },
                )
                halted_early = True
                break

            step_results.append(
                PlaybookStepResult(
                    step_id=step.step_id,
                    action_name=step.action_name,
                    params=step.params,
                    outcome=PlaybookStepOutcome.SUCCESS,
                    output=output,
                )
            )
            await self._audit.log(
                AuditEventType.PLAYBOOK_STEP_EXECUTED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={
                    "playbook_id": str(playbook.playbook_id),
                    "step_id": step.step_id,
                    "action_name": step.action_name,
                    "params": step.params,
                    "output": output,
                },
            )

        result = PlaybookExecutionResult(
            playbook_id=playbook.playbook_id,
            playbook_name=playbook.name,
            step_results=tuple(step_results),
            halted_early=halted_early,
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )
        await self._audit.log(
            AuditEventType.PLAYBOOK_EXECUTION_COMPLETED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={
                "execution_id": str(result.execution_id),
                "playbook_id": str(playbook.playbook_id),
                "halted_early": halted_early,
                "step_count": len(playbook.steps),
                "completed_step_count": len(step_results),
                "succeeded": result.succeeded,
            },
        )
        logger.info(
            "playbook_execution_completed",
            extra={
                "execution_id": str(result.execution_id),
                "playbook_id": str(playbook.playbook_id),
                "halted_early": halted_early,
                "succeeded": result.succeeded,
            },
        )
        return result
