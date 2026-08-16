"""Admin routes for provisioning/revoking IntegrationSource inbound-push API
keys (Milestone W8, Gap Audit P1-7).

Closes a real, previously-confirmed gap: ``StaticApiKeyProvisioning``
records used to only ever be seeded once, at process boot, from
``Settings``/Vault into a static in-memory dict -- there was no route an
operator could call to issue an org a real key for
``POST /api/integrations/push/{source_type}`` without restarting the whole
backend (``configure_static_api_key_provisioning`` had zero real callers
anywhere in ``src/``, confirmed via a direct grep before this module was
written). These routes are the real provisioning surface.

Mirrors ``admin.py``'s own conventions (role-gating via
``requires_role(*_ADMIN_ROLES)``, camelCase request/response DTOs per this
repo's own convention for routes -- see ``pyproject.toml``'s ``N815``/
``B008`` per-file-ignore for ``admin.py``, reused here for the same
reason). Step-up gating mirrors ``evidence.py``'s
``DELETE /api/evidence/{id}`` route exactly (``step_up_auth.assert_acr`` +
``X-Step-Up-Ticket`` header + ``step_up_auth.consume_ticket``) -- API-key
issuance/revocation is credential-issuance, at least as sensitive as
evidence deletion, so it gets the identical aal2 + one-time-ticket bar.

Route shape deliberately deviates in one place from the milestone's own
strawman suggestion (``DELETE /api/admin/integration-sources/{source_type}``
with no source_id): ``IntegrationSourceKeyRepository`` is keyed by
``(org_id, source_id)``, not ``(org_id, source_type)`` -- an org can have
more than one connector instance of the same source_type (e.g. two
independent Wazuh managers), so both provision and revoke take an explicit
``source_id`` to stay unambiguous.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.adapter.repository.integration_source_key import IntegrationSourceKeyRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_audit_log_service,
    get_integration_source_key_repository,
    get_step_up_auth,
)
from src.external.middleware.rbac import requires_role
from src.external.middleware.step_up_auth import StepUpAuth

router = APIRouter(prefix="/api/admin/integration-sources", tags=["admin"])

_ADMIN_ROLES = (Role.ORG_ADMIN,)


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class ProvisionIntegrationSourceKeyIn(BaseModel):
    """Request DTO — field names match this repo's camelCase route convention."""

    sourceId: str = Field(min_length=1, max_length=256)


class IntegrationSourceKeyOut(BaseModel):
    """Full provisioning record, INCLUDING the plaintext key -- returned
    exactly once, from the provision response only. Never reconstructed or
    re-returned by any other route (standard "shown once" API-key issuance
    UX)."""

    sourceId: str
    sourceType: str
    apiKey: str
    createdAt: str


class IntegrationSourceKeySummaryOut(BaseModel):
    """Admin-listing-safe view — NEVER carries plaintext key material (see
    ``ProvisionedApiKeySummary``'s own docstring: the domain type this is
    built from structurally has no field to put it in)."""

    sourceId: str
    sourceType: str
    createdAt: str
    revokedAt: str | None


class IntegrationSourceKeyListOut(BaseModel):
    items: list[IntegrationSourceKeySummaryOut]
    total: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/{source_type}/provision",
    response_model=IntegrationSourceKeyOut,
    status_code=status.HTTP_201_CREATED,
)
async def provision_integration_source_key(
    source_type: str,
    body: ProvisionIntegrationSourceKeyIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    repository: Annotated[
        IntegrationSourceKeyRepository, Depends(get_integration_source_key_repository)
    ],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> IntegrationSourceKeyOut:
    """Provision (or rotate) a real, random API key for
    ``(tenant.org_id, body.sourceId)``, scoped to *source_type*.

    Credential issuance -- requires org-admin + aal2 step-up, identical bar
    to ``DELETE /api/evidence/{id}``. Clients must first obtain a step-up
    ticket via ``POST /api/step-up/ticket`` (operation=
    ``"integration_source_key.provision"``, resource_id=
    ``f"{source_type}:{sourceId}"``) and pass it in ``X-Step-Up-Ticket``.

    The plaintext key is returned exactly once, in this response body --
    it is never persisted in the clear and never retrievable again after
    this call returns (see ``IntegrationSourceKeyRepository.provision``'s
    own docstring). Calling this again for the same (org, sourceId) rotates
    the key: the previous key stops authenticating immediately.
    """
    step_up_auth.assert_acr(tenant)
    resource_id = f"{source_type}:{body.sourceId}"
    try:
        ticket_id = uuid.UUID(x_step_up_ticket)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Step-Up-Ticket header",
            headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'},
        ) from exc
    step_up_auth.consume_ticket(
        ticket_id=ticket_id,
        user_id=tenant.user_id,
        operation="integration_source_key.provision",
        resource_id=resource_id,
    )

    provisioning = await repository.provision(
        org_id=tenant.org_id, source_id=body.sourceId, source_type=source_type
    )

    # Never log the plaintext key (CLAUDE.md SS B.4: no credentials in logs).
    await audit_svc.log(
        AuditEventType.INTEGRATION_SOURCE_KEY_PROVISIONED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        actor_username=tenant.username,
        details={"source_id": body.sourceId, "source_type": source_type},
    )

    return IntegrationSourceKeyOut(
        sourceId=provisioning.source_id,
        sourceType=provisioning.source_type,
        apiKey=provisioning.api_key,
        createdAt=provisioning.created_at.isoformat(),
    )


@router.get("", response_model=IntegrationSourceKeyListOut)
async def list_integration_source_keys(
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    repository: Annotated[
        IntegrationSourceKeyRepository, Depends(get_integration_source_key_repository)
    ],
) -> IntegrationSourceKeyListOut:
    """List every key ever provisioned for the caller's org (including
    revoked ones, for audit visibility) -- org-scoped from
    ``tenant.org_id``, never a client-supplied org (standing invariant).
    Plaintext key material is NEVER included (see
    ``IntegrationSourceKeySummaryOut``'s own docstring)."""
    summaries = await repository.list_by_org(tenant.org_id)
    items = [
        IntegrationSourceKeySummaryOut(
            sourceId=s.source_id,
            sourceType=s.source_type,
            createdAt=s.created_at.isoformat(),
            revokedAt=s.revoked_at.isoformat() if s.revoked_at is not None else None,
        )
        for s in summaries
    ]
    return IntegrationSourceKeyListOut(items=items, total=len(items))


@router.delete(
    "/{source_type}/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_integration_source_key(
    source_type: str,
    source_id: str,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    repository: Annotated[
        IntegrationSourceKeyRepository, Depends(get_integration_source_key_repository)
    ],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> None:
    """Revoke the (tenant.org_id, source_id) key -- idempotent, and scoped
    to the caller's own org (an org can never revoke another org's key).

    Also credential-related and step-up gated, mirroring the provision
    route above. Clients obtain a ticket with operation=
    ``"integration_source_key.revoke"``, resource_id=
    ``f"{source_type}:{source_id}"``.
    """
    step_up_auth.assert_acr(tenant)
    resource_id = f"{source_type}:{source_id}"
    try:
        ticket_id = uuid.UUID(x_step_up_ticket)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Step-Up-Ticket header",
            headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'},
        ) from exc
    step_up_auth.consume_ticket(
        ticket_id=ticket_id,
        user_id=tenant.user_id,
        operation="integration_source_key.revoke",
        resource_id=resource_id,
    )

    await repository.revoke(org_id=tenant.org_id, source_id=source_id)

    await audit_svc.log(
        AuditEventType.INTEGRATION_SOURCE_KEY_REVOKED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        actor_username=tenant.username,
        details={"source_id": source_id, "source_type": source_type},
    )
