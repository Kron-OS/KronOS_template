"""ApprovalGate: the pluggable authorization check a destructive
``ContainmentAction`` (``src/application/containment_action.py``) consults
before its real, external side effect ever runs (roadmap M7/H2 -- the
gate's own binding requirement: "prove no destructive action can execute
without either an explicit policy authorization or human approval").

Mirrors this codebase's established ABC extensibility idiom (``PlaybookAction``,
``Enricher``, ``CostGateHeuristic``): a new approval mechanism is a new
``ApprovalGate`` subclass, constructed and injected wherever a
``ContainmentAction`` needs it -- zero edits to ``ContainmentAction`` itself
or to any other already-registered gate. Unlike ``PlaybookActionRegistry``,
there is deliberately no shared registry here: each ``ContainmentAction``
is wired (via DI, at construction) with exactly the ``ApprovalGate`` its
own operational policy requires -- there is exactly one gate consulted per
action, not a lookup-by-name (a containment action's approval requirement
is a fixed property of that action, decided by whoever deploys it, not
declarative playbook-step data an untrusted step could redirect).
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from typing import Any

from src.domain.approval import ApprovalDecision
from src.domain.user import TenantContext

# TicketStore/ConsumeResult have zero framework imports of their own (pure
# uuid/dataclass/enum logic) despite living under external/middleware/ -- a
# pre-existing placement, not this module's choice. Reusing them directly
# here (rather than StepUpAuth, which raises fastapi.HTTPException and
# would leak a framework dependency into this application-layer module,
# CLAUDE.md SS A.3) is the smaller layering compromise versus inventing a
# second, parallel ticket-store abstraction for the same real concept.
from src.external.middleware.step_up_store import ConsumeResult, TicketStore

logger = logging.getLogger(__name__)


class ApprovalGate(ABC):
    """One pluggable authorization check for a gated destructive action."""

    @abstractmethod
    async def authorize(
        self, action_name: str, params: dict[str, Any], tenant: TenantContext
    ) -> ApprovalDecision:
        """Decide whether *tenant* may run *action_name* with *params* right now.

        Never raises for an ordinary "not authorized" outcome -- that is a
        normal, expected ``ApprovalDecision(authorized=False, ...)``, not an
        error. Only a genuine infrastructure failure (e.g. the ticket store
        itself unreachable) should raise, mirroring CLAUDE.md SS1#8's "fail
        loudly" for real backend failures specifically, never for an
        ordinary denial.
        """


class StepUpApprovalGate(ApprovalGate):
    """Human approval via a real, already-issued step-up ticket (RFC 9470).

    Ties into the EXISTING, already-working step-up mechanism
    (``POST /api/step-up/ticket``, ``src/external/routes/step_up.py``)
    rather than inventing a second approval-ticket concept: an analyst who
    already holds an aal2 session obtains a ticket scoped to
    ``(operation=action_name, resource_id=<caller-chosen>)`` through that
    real route, then whoever constructs the playbook step embeds the
    resulting ticket id and resource id in the step's own ``params`` (the
    human-approval step happens out of band, before the gated step is
    ever executed). Consuming a ticket is one-shot
    (``TicketStore.consume``'s own atomic guarantee) -- a second attempt to
    run the same step with the same ticket is correctly denied, not
    silently re-authorized.
    """

    _POLICY_NAME = "step_up_mfa"

    def __init__(self, ticket_store: TicketStore) -> None:
        self._tickets = ticket_store

    async def authorize(
        self, action_name: str, params: dict[str, Any], tenant: TenantContext
    ) -> ApprovalDecision:
        ticket_id_raw = params.get("approval_ticket_id")
        resource_id = params.get("approval_resource_id")
        if not ticket_id_raw or not resource_id:
            return ApprovalDecision(
                authorized=False,
                policy_name=self._POLICY_NAME,
                reason="no approval_ticket_id/approval_resource_id supplied in step params",
            )
        try:
            ticket_id = uuid.UUID(str(ticket_id_raw))
        except ValueError:
            return ApprovalDecision(
                authorized=False,
                policy_name=self._POLICY_NAME,
                reason="approval_ticket_id is not a valid UUID",
            )

        result = self._tickets.consume(ticket_id, tenant.user_id, action_name, str(resource_id))
        if result is ConsumeResult.CONSUMED:
            return ApprovalDecision(
                authorized=True,
                policy_name=self._POLICY_NAME,
                reason=f"step-up ticket {ticket_id} consumed for {action_name}/{resource_id}",
            )
        reason = (
            "step-up ticket does not match this user/action/resource"
            if result is ConsumeResult.MISMATCH
            else "step-up ticket missing, expired, or already used"
        )
        return ApprovalDecision(authorized=False, policy_name=self._POLICY_NAME, reason=reason)


class StaticPolicyApprovalGate(ApprovalGate):
    """Explicit, admin-configured policy authorization -- no human ticket.

    Authorizes purely from a fixed allow-list of ``(org_id, action_name)``
    pairs supplied at construction (e.g. an org's own pre-approved
    automation policy, configured out of band by an org admin). Proves the
    gate's "explicit policy authorization" branch for real -- roadmap H2's
    binding requirement is "either... or", not human approval exclusively
    -- with a second, genuinely different ``ApprovalGate`` needing zero
    changes to ``ContainmentAction`` or ``StepUpApprovalGate``.
    """

    _POLICY_NAME = "static_policy_allowlist"

    def __init__(self, allowed: frozenset[tuple[uuid.UUID, str]]) -> None:
        self._allowed = allowed

    async def authorize(
        self, action_name: str, params: dict[str, Any], tenant: TenantContext
    ) -> ApprovalDecision:
        if (tenant.org_id, action_name) in self._allowed:
            return ApprovalDecision(
                authorized=True,
                policy_name=self._POLICY_NAME,
                reason=f"org {tenant.org_id} has a standing policy authorization for {action_name}",
            )
        return ApprovalDecision(
            authorized=False,
            policy_name=self._POLICY_NAME,
            reason=f"no standing policy authorization for org {tenant.org_id}/{action_name}",
        )
