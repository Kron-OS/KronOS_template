"""Concrete ``ContainmentAction`` implementations (roadmap M7/H2).

``RevokeKeycloakSessionAction`` is the one containment action this pass
ships with a genuinely real, destructive backend -- see this module's own
PoC (``poc/containment_approval_gate/README.md``) for why "block IP" and
"isolate host" (the roadmap's other two named examples) do NOT ship here:
neither has a real, safely-reachable enforcement point in this repo's
actual dev stack today (confirmed by investigation, not assumed --
``docker-nginx-1`` bakes its config into the image at build time with no
live-editable mount, and no host-management/EDR/agent component exists
anywhere in ``src/``). Shipping a no-op/fake adapter for either would be
exactly the "plausible code with no captured real run" failure CLAUDE.md
SS F exists to prevent.
"""

from __future__ import annotations

import uuid
from typing import Any

from src.adapter.keycloak.admin_client import KeycloakAdminClient
from src.application.approval_gate import ApprovalGate
from src.application.audit_log import AuditLogService
from src.application.containment_action import ContainmentAction
from src.domain.user import TenantContext
from src.exceptions import AuthorizationError, ValidationError


class RevokeKeycloakSessionAction(ContainmentAction):
    """Destructively revokes one real, live Keycloak user session.

    Params: ``user_id`` (str UUID, the session's owning account) and
    ``session_id`` (str, the real Keycloak session id -- e.g. from a
    Detection's own enrichment data identifying the session an attacker's
    credentials are actively using), plus whatever ``ApprovalGate``-specific
    keys the injected gate requires (e.g. ``approval_ticket_id``/
    ``approval_resource_id`` for ``StepUpApprovalGate``).

    Tenant isolation (roadmap invariant #3): the target user's org
    membership is checked against *tenant*'s own ``org_id`` via a REAL,
    independent Keycloak Admin API call -- never trusted from ``params``
    alone, so a malicious or buggy playbook step naming another org's
    session_id is rejected here, not just hoped not to happen. The
    session_id is also independently confirmed to actually belong to
    ``user_id``'s own real, live session list before revocation -- a
    caller cannot revoke an arbitrary session id merely by pairing it with
    a user_id who happens to be a real member of the acting org.
    """

    def __init__(
        self,
        admin_client: KeycloakAdminClient,
        approval_gate: ApprovalGate,
        audit_log: AuditLogService,
    ) -> None:
        super().__init__(approval_gate, audit_log)
        self._admin = admin_client

    @property
    def action_name(self) -> str:
        return "revoke_keycloak_session"

    async def _perform(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        try:
            user_id = uuid.UUID(str(params["user_id"]))
            session_id = str(params["session_id"])
        except (KeyError, ValueError) as exc:
            raise ValidationError(
                "revoke_keycloak_session requires a real user_id (UUID str) and session_id",
                context={"params": params, "error": str(exc)},
            ) from exc
        if not session_id:
            raise ValidationError(
                "revoke_keycloak_session requires a non-empty session_id",
                context={"params": params},
            )

        is_member = await self._admin.is_org_member(tenant.org_id, user_id)
        if not is_member:
            raise AuthorizationError(
                "Target user does not belong to the acting tenant's own organization",
                context={"org_id": str(tenant.org_id), "user_id": str(user_id)},
            )

        sessions = await self._admin.list_user_sessions(user_id)
        if not any(s.session_id == session_id for s in sessions):
            raise ValidationError(
                "session_id does not belong to a real, currently-live session for this user",
                context={"user_id": str(user_id), "session_id": session_id},
            )

        await self._admin.revoke_session(session_id)
        return {"user_id": str(user_id), "session_id": session_id, "revoked": True}
