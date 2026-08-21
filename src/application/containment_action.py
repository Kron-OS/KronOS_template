"""ContainmentAction: template-method base for destructive ``PlaybookAction``s
gated by an ``ApprovalGate`` (roadmap M7/H2 -- the milestone's own binding
gate: "prove no destructive action can execute without either an explicit
policy authorization or human approval, and that every attempt is audited
whether or not it succeeded").

Mirrors ``PlaybookAction``'s own "one interface, registration not edits"
idiom, specialized for the destructive case: a concrete containment
adapter (e.g. ``RevokeKeycloakSessionAction``) implements ONLY
``_perform()`` -- the real, external side effect; this base class owns the
gate-consult-then-audit sequence once, so every future destructive action
reuses it verbatim instead of re-deriving its own approval/audit logic
(the "design the approval gate as its own abstraction... so future gated
actions reuse it without bespoke per-action approval logic" requirement
from the roadmap brief).

Audit ordering is deliberate: ``CONTAINMENT_ACTION_ATTEMPTED`` is logged
BEFORE the gate is even consulted, so a bug or crash inside the gate
itself can never erase the fact an attempt was made -- "every attempt is
audited whether or not it succeeded" literally includes attempts the gate
itself fails to evaluate cleanly. ``CONTAINMENT_ACTION_DENIED`` is a
distinct event from ``CONTAINMENT_ACTION_FAILED``: "no approval was
present" and "the real backend rejected the call" are different facts a
court-facing audit trail must not conflate.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from typing import Any

from src.application.approval_gate import ApprovalGate
from src.application.audit_log import AuditLogService
from src.application.playbook import PlaybookAction
from src.domain.audit import AuditEventType
from src.domain.user import TenantContext
from src.exceptions import ContainmentActionDeniedError

logger = logging.getLogger(__name__)


class ContainmentAction(PlaybookAction):
    """Base for any ``PlaybookAction`` with a real, external, destructive side effect."""

    def __init__(self, approval_gate: ApprovalGate, audit_log: AuditLogService) -> None:
        self._gate = approval_gate
        self._audit = audit_log

    @abstractmethod
    def _resource_id(self, params: dict[str, Any]) -> str:
        """Derive the REAL identifier of the resource this action will
        operate on, from *params* -- e.g. the actual Keycloak
        ``session_id`` being revoked, for ``RevokeKeycloakSessionAction``.

        This is what ``ApprovalGate.authorize()`` actually scopes its
        decision against (Gap Audit Milestone JJ). Never derive this from
        a separate, caller-supplied "which resource does my ticket cover"
        field -- a real, reproduced attack (`poc/stepup_ticket_resource_mismatch/`)
        showed that a caller-supplied field only had to match the ticket,
        with no binding to the actual target of the destructive action,
        letting a ticket minted "for" resource A authorize acting on a
        completely different resource B. Raise the same exception
        ``_perform()`` would for malformed/missing params (e.g.
        ``ValidationError``) -- this runs BEFORE the gate is consulted, so
        params must already be validated here, not deferred to
        ``_perform()``.
        """

    @abstractmethod
    async def _perform(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        """The real, destructive side effect against the real backend.

        Raise on any failure to reach or apply the change on the real
        backend -- never return a fabricated success (CLAUDE.md SS1#8).
        """

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        await self._audit.log(
            AuditEventType.CONTAINMENT_ACTION_ATTEMPTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={"action_name": self.action_name, "params": params},
        )

        try:
            resource_id = self._resource_id(params)
        except Exception as exc:  # noqa: BLE001 -- audited below, then re-raised unchanged
            await self._audit.log(
                AuditEventType.CONTAINMENT_ACTION_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={
                    "action_name": self.action_name,
                    "params": params,
                    "error": str(exc),
                    "step": "resource_id_derivation",
                },
            )
            raise

        decision = await self._gate.authorize(self.action_name, resource_id, params, tenant)
        if not decision.authorized:
            await self._audit.log(
                AuditEventType.CONTAINMENT_ACTION_DENIED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={
                    "action_name": self.action_name,
                    "params": params,
                    "policy_name": decision.policy_name,
                    "reason": decision.reason,
                },
            )
            raise ContainmentActionDeniedError(
                f"{self.action_name} denied by {decision.policy_name}: {decision.reason}",
                context={"action_name": self.action_name, "reason": decision.reason},
            )

        try:
            output = await self._perform(params, tenant)
        except Exception as exc:  # noqa: BLE001 -- audited below, then re-raised unchanged
            await self._audit.log(
                AuditEventType.CONTAINMENT_ACTION_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"action_name": self.action_name, "params": params, "error": str(exc)},
            )
            raise

        await self._audit.log(
            AuditEventType.CONTAINMENT_ACTION_EXECUTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={
                "action_name": self.action_name,
                "params": params,
                "policy_name": decision.policy_name,
                "output": output,
            },
        )
        logger.info(
            "containment_action_executed",
            extra={"action_name": self.action_name, "org_id": str(tenant.org_id)},
        )
        return output
