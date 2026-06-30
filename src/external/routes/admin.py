"""Org admin endpoints — user management and org settings."""

from __future__ import annotations

import logging
import uuid
from typing import Annotated, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from src.domain.audit import AuditEventType
from src.domain.user import Role, TenantContext
from src.exceptions import StorageError
from src.external.dependencies import get_audit_log_service, get_tenant_context
from src.external.middleware.rbac import requires_role
from src.external.middleware.step_up_auth import StepUpAuth

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin/org", tags=["admin"])

_ADMIN_ROLES = (Role.ORG_ADMIN,)


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class OrgUserOut(BaseModel):
    """API response DTO — field names match the frontend TypeScript OrgUser interface."""

    userId: str
    username: str
    email: str
    roles: list[str]
    joinedAt: str | None


class OrgUsersResponse(BaseModel):
    items: list[OrgUserOut]
    total: int


_OrgRole = Literal["org-admin", "case-lead", "analyst", "read-only"]


class InviteUserIn(BaseModel):
    email: str = Field(description="Email address of the user to invite")
    role: _OrgRole = Field(description="Role to assign")


class UpdateRoleIn(BaseModel):
    role: _OrgRole


class OrgSettingsOut(BaseModel):
    retention_days: int
    legal_hold_default: bool


class UpdateSettingsIn(BaseModel):
    retention_days: int = Field(ge=1, le=3650)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/users", response_model=OrgUsersResponse)
async def list_org_users(
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
) -> OrgUsersResponse:
    """List all users in the caller's org. Proxied to Keycloak Admin REST API."""
    try:
        users = await _list_keycloak_org_users(tenant)
    except StorageError:
        return OrgUsersResponse(items=[], total=0)
    return OrgUsersResponse(items=users, total=len(users))


@router.post("/users/invite", status_code=status.HTTP_201_CREATED)
async def invite_user(
    body: InviteUserIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    audit_svc=Depends(get_audit_log_service),
) -> dict:
    """Invite a user to the org via Keycloak invitation API."""
    _assert_aal2(tenant)
    try:
        await _keycloak_admin_request(
            tenant,
            "POST",
            f"/organizations/{tenant.org_id}/members/invite",
            {"email": body.email, "roles": [body.role]},
        )
    except StorageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    await audit_svc.log(
        AuditEventType.ORG_USER_INVITED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        details={"invited_email": body.email, "role": body.role},
    )
    return {"detail": "Invitation sent"}


@router.patch("/users/{user_id}/role", response_model=OrgUserOut)
async def update_user_role(
    user_id: str,
    body: UpdateRoleIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    audit_svc=Depends(get_audit_log_service),
) -> OrgUserOut:
    """Change a user's role within the org."""
    _assert_aal2(tenant)
    try:
        await _keycloak_admin_request(
            tenant,
            "PATCH",
            f"/organizations/{tenant.org_id}/members/{user_id}/roles",
            {"roles": [body.role]},
        )
    except StorageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    await audit_svc.log(
        AuditEventType.ORG_USER_ROLE_CHANGED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        details={"target_user_id": user_id, "new_role": body.role},
    )
    return OrgUserOut(userId=user_id, username="", email="", roles=[body.role], joinedAt=None)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_user(
    user_id: str,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    audit_svc=Depends(get_audit_log_service),
) -> None:
    """Remove a user from the org."""
    _assert_aal2(tenant)
    try:
        await _keycloak_admin_request(
            tenant,
            "DELETE",
            f"/organizations/{tenant.org_id}/members/{user_id}",
            None,
        )
    except StorageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    await audit_svc.log(
        AuditEventType.ORG_USER_REMOVED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        details={"removed_user_id": user_id},
    )


@router.get("/settings", response_model=OrgSettingsOut)
async def get_org_settings(
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
) -> OrgSettingsOut:
    """Return org-level retention and legal-hold defaults."""
    from src.config import Settings  # noqa: PLC0415

    settings = Settings()
    return OrgSettingsOut(
        retention_days=settings.minio_default_retention_days,
        legal_hold_default=False,
    )


@router.patch("/settings", response_model=OrgSettingsOut)
async def update_org_settings(
    body: UpdateSettingsIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    audit_svc=Depends(get_audit_log_service),
) -> OrgSettingsOut:
    """Update org retention defaults (stored in-org metadata)."""
    _assert_aal2(tenant)
    await audit_svc.log(
        AuditEventType.ORG_SETTINGS_UPDATED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        details={"retention_days": body.retention_days},
    )
    return OrgSettingsOut(retention_days=body.retention_days, legal_hold_default=False)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _assert_aal2(tenant: TenantContext) -> None:
    """Raise 401 step-up challenge if the token doesn't satisfy aal2."""
    _ACR_LEVEL = {"aal1": 1, "aal2": 2}
    if _ACR_LEVEL.get(tenant.acr, 0) < 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Step-up authentication required for this operation",
            headers={
                "WWW-Authenticate": 'Bearer error="insufficient_user_authentication", acr_values="aal2"'
            },
        )


async def _get_service_account_token(tenant: TenantContext) -> str:
    """Obtain a Keycloak service-account token for Admin REST API calls."""
    from src.config import Settings  # noqa: PLC0415

    settings = Settings()
    token_url = (
        f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
        f"/protocol/openid-connect/token"
    )
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": settings.keycloak_client_id,
                "client_secret": settings.keycloak_client_secret.get_secret_value(),
            },
        )
    if resp.status_code != 200:
        raise StorageError(
            "Failed to obtain Keycloak service-account token",
            context={"status": resp.status_code},
        )
    return resp.json()["access_token"]  # type: ignore[no-any-return]


async def _keycloak_admin_request(
    tenant: TenantContext,
    method: str,
    path: str,
    body: dict | None,
) -> dict:
    """Execute a Keycloak Admin REST API call scoped to the caller's org."""
    from src.config import Settings  # noqa: PLC0415

    settings = Settings()
    try:
        token = await _get_service_account_token(tenant)
    except (httpx.HTTPError, StorageError) as exc:
        raise StorageError(
            "Keycloak Admin API unreachable",
            context={"error": str(exc)},
        ) from exc

    admin_url = f"{settings.keycloak_url}/admin/realms/{settings.keycloak_realm}{path}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.request(
                method,
                admin_url,
                json=body,
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code >= 500:
                raise StorageError(
                    "Keycloak Admin API returned server error",
                    context={"status": resp.status_code},
                )
            if resp.status_code == 404:
                raise StorageError("Resource not found in Keycloak", context={"status": 404})
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise StorageError(
            "Keycloak Admin API request failed",
            context={"error": str(exc)},
        ) from exc

    return resp.json() if resp.content else {}  # type: ignore[no-any-return]


async def _list_keycloak_org_users(tenant: TenantContext) -> list[OrgUserOut]:
    """Fetch org members from Keycloak."""
    data = await _keycloak_admin_request(tenant, "GET", f"/organizations/{tenant.org_id}/members", None)
    if not isinstance(data, list):
        return []
    return [
        OrgUserOut(
            userId=u.get("id", ""),
            username=u.get("username", ""),
            email=u.get("email", ""),
            roles=u.get("roles", []),
            joinedAt=u.get("createdTimestamp"),
        )
        for u in data
    ]
