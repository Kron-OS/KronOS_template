"""Admin routes for the connector marketplace (`/admin/connectors`): browse
the connector catalog and configure/revoke per-org connector settings.

Distinct from the two existing connector-related route modules by design,
not by accident:
  - ``admin_connector_status.py`` stays read-only (status table).
  - ``admin_integration_sources.py`` stays PUSH-key-only (Wazuh/Suricata/
    Zeek API-key provisioning) -- this file never touches that table.
This file owns the NEW mutation surface: per-org config for POLL/SINK
connectors (Defender/Sentinel/Splunk HEC/CEF syslog) that previously had
no admin-facing config at all (global env vars only).

Step-up gating mirrors ``admin_integration_sources.py`` exactly (org-admin
+ aal2 + one-time ``X-Step-Up-Ticket``) -- setting/revoking a connector's
outbound credentials is at least as sensitive as API-key issuance. Catalog
browsing (``GET /catalog``) is read-only and not step-up gated, same as
``GET`` on the integration-source-keys list.

Rate limiting: the four mutation routes below sit behind
``connector_config_rate_limiter`` (``src/external/middleware/
org_rate_limit.py``) -- no rate-limiting middleware exists anywhere else in
this codebase; scoped here specifically because these calls write to both
Postgres and Vault.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from src.application.connector_catalog import ConnectorCatalog
from src.application.connector_config import ConnectorConfigService
from src.domain.connector import ConnectorConfigSummary, ConnectorDefinition
from src.domain.user import Role, TenantContext
from src.exceptions import ValidationError
from src.external.dependencies import (
    get_connector_catalog,
    get_connector_config_service,
    get_step_up_auth,
)
from src.external.middleware.org_rate_limit import connector_config_rate_limiter
from src.external.middleware.rbac import requires_role
from src.external.middleware.step_up_auth import StepUpAuth

router = APIRouter(prefix="/api/admin/connectors", tags=["admin"])

_ADMIN_ROLES = (Role.ORG_ADMIN,)


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class ConnectorParameterOut(BaseModel):
    name: str
    label: str
    secret: bool
    required: bool
    default: str | None


class ConnectorDefinitionOut(BaseModel):
    sourceType: str
    displayName: str
    mode: str
    description: str
    parameters: list[ConnectorParameterOut]
    assetSetupNotes: str


class ConnectorCatalogOut(BaseModel):
    items: list[ConnectorDefinitionOut]


class SetConnectorConfigIn(BaseModel):
    values: dict[str, str]


class ConnectorConfigOut(BaseModel):
    sourceType: str
    enabled: bool
    nonSecretFields: dict[str, str]
    secretFieldNames: list[str]
    secretsSet: bool
    consecutiveFailureCount: int
    autoDisabledAt: str | None
    createdAt: str
    updatedAt: str


class ConnectorConfigListOut(BaseModel):
    items: list[ConnectorConfigOut]


def _to_definition_out(d: ConnectorDefinition) -> ConnectorDefinitionOut:
    return ConnectorDefinitionOut(
        sourceType=d.source_type,
        displayName=d.display_name,
        mode=d.mode.value,
        description=d.description,
        parameters=[
            ConnectorParameterOut(
                name=p.name, label=p.label, secret=p.secret, required=p.required, default=p.default
            )
            for p in d.parameters
        ],
        assetSetupNotes=d.asset_setup_notes,
    )


def _to_config_out(s: ConnectorConfigSummary) -> ConnectorConfigOut:
    return ConnectorConfigOut(
        sourceType=s.source_type,
        enabled=s.enabled,
        nonSecretFields=s.non_secret_fields,
        secretFieldNames=list(s.secret_field_names),
        secretsSet=s.secrets_set,
        consecutiveFailureCount=s.consecutive_failure_count,
        autoDisabledAt=s.auto_disabled_at.isoformat() if s.auto_disabled_at is not None else None,
        createdAt=s.created_at.isoformat(),
        updatedAt=s.updated_at.isoformat(),
    )


def _consume_step_up_ticket(
    step_up_auth: StepUpAuth,
    tenant: TenantContext,
    x_step_up_ticket: str,
    *,
    operation: str,
    resource_id: str,
) -> None:
    """Shared step-up verification for this file's four mutation routes --
    same real check as ``admin_integration_sources.py``'s inline version,
    factored out once within this module since it repeats four times here
    (twice there)."""
    step_up_auth.assert_acr(tenant)
    try:
        ticket_id = uuid.UUID(x_step_up_ticket)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Step-Up-Ticket header",
            headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'},
        ) from exc
    step_up_auth.consume_ticket(
        ticket_id=ticket_id, user_id=tenant.user_id, operation=operation, resource_id=resource_id
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/catalog", response_model=ConnectorCatalogOut)
async def get_connector_catalog_route(
    _tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    catalog: Annotated[ConnectorCatalog, Depends(get_connector_catalog)],
) -> ConnectorCatalogOut:
    """Browse every known connector type and its required parameters --
    read-only, no step-up (mirrors the integration-source-keys list route)."""
    return ConnectorCatalogOut(items=[_to_definition_out(d) for d in catalog.all()])


@router.get("", response_model=ConnectorConfigListOut)
async def list_connector_configs(
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    service: Annotated[ConnectorConfigService, Depends(get_connector_config_service)],
) -> ConnectorConfigListOut:
    """List every connector configured for the caller's org -- org-scoped
    from ``tenant.org_id``, never a client-supplied org."""
    summaries = await service.list_configs(tenant.org_id)
    return ConnectorConfigListOut(items=[_to_config_out(s) for s in summaries])


@router.get("/{source_type}/config", response_model=ConnectorConfigOut)
async def get_connector_config(
    source_type: str,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    service: Annotated[ConnectorConfigService, Depends(get_connector_config_service)],
) -> ConnectorConfigOut:
    """Redacted read -- never contains secret values (see
    ``ConnectorConfigSummary``'s own docstring: the type has no field to
    put them in)."""
    summary = await service.get_config(tenant.org_id, source_type)
    if summary is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not configured")
    return _to_config_out(summary)


@router.put("/{source_type}/config", response_model=ConnectorConfigOut)
async def set_connector_config(
    source_type: str,
    body: SetConnectorConfigIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    service: Annotated[ConnectorConfigService, Depends(get_connector_config_service)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> ConnectorConfigOut:
    """Set (or replace) this org's config for *source_type*.

    Credential-bearing for POLL/SINK connectors -- requires org-admin +
    aal2 step-up, identical bar to integration-source-key provisioning.
    Clients obtain a ticket via ``POST /api/step-up/ticket``
    (operation=``"connector_config.set"``, resource_id=*source_type*).
    """
    connector_config_rate_limiter.check(tenant.org_id, "connector_config_mutate")
    _consume_step_up_ticket(
        step_up_auth, tenant, x_step_up_ticket, operation="connector_config.set", resource_id=source_type
    )
    try:
        summary = await service.set_config(
            tenant.org_id,
            source_type,
            body.values,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
        )
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return _to_config_out(summary)


@router.delete("/{source_type}/config", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector_config(
    source_type: str,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    service: Annotated[ConnectorConfigService, Depends(get_connector_config_service)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> None:
    """Permanently remove this org's config + Vault secret for *source_type*
    ("remove an endpoint") -- idempotent, step-up gated."""
    connector_config_rate_limiter.check(tenant.org_id, "connector_config_mutate")
    _consume_step_up_ticket(
        step_up_auth,
        tenant,
        x_step_up_ticket,
        operation="connector_config.delete",
        resource_id=source_type,
    )
    await service.delete_config(tenant.org_id, source_type, actor_user_id=tenant.user_id, actor_username=tenant.username)


@router.post("/{source_type}/config/disable", response_model=ConnectorConfigOut)
async def disable_connector_config(
    source_type: str,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    service: Annotated[ConnectorConfigService, Depends(get_connector_config_service)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> ConnectorConfigOut:
    """Reversible kill switch -- pauses this connector without deleting its
    config/secrets (useful mid-incident). Distinct from DELETE's permanent
    removal."""
    connector_config_rate_limiter.check(tenant.org_id, "connector_config_mutate")
    _consume_step_up_ticket(
        step_up_auth,
        tenant,
        x_step_up_ticket,
        operation="connector_config.disable",
        resource_id=source_type,
    )
    summary = await service.set_enabled(
        tenant.org_id, source_type, False, actor_user_id=tenant.user_id, actor_username=tenant.username
    )
    if summary is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not configured")
    return _to_config_out(summary)


@router.post("/{source_type}/config/enable", response_model=ConnectorConfigOut)
async def enable_connector_config(
    source_type: str,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    service: Annotated[ConnectorConfigService, Depends(get_connector_config_service)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> ConnectorConfigOut:
    """Re-enable a disabled/auto-disabled connector -- clears any
    system-set circuit-breaker state (``autoDisabledAt``)."""
    connector_config_rate_limiter.check(tenant.org_id, "connector_config_mutate")
    _consume_step_up_ticket(
        step_up_auth,
        tenant,
        x_step_up_ticket,
        operation="connector_config.enable",
        resource_id=source_type,
    )
    summary = await service.set_enabled(
        tenant.org_id, source_type, True, actor_user_id=tenant.user_id, actor_username=tenant.username
    )
    if summary is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not configured")
    return _to_config_out(summary)
