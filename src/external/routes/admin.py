"""Org admin endpoints — user management and org settings."""

from __future__ import annotations

import asyncio
import logging
import urllib.parse
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.domain.audit import AuditEventType
from src.domain.user import Role, TenantContext
from src.exceptions import StorageError
from src.external.dependencies import get_audit_log_service
from src.external.middleware.rbac import requires_role

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
    """Create a user, assign their role, and add them to the caller's org.

    This is a direct-create flow (no email): Keycloak has no SMTP configured
    in dev, so rather than send an invitation link we provision the user with
    a temporary password and an UPDATE_PASSWORD required action. The realm
    role is assigned immediately and the user is linked as an org member.
    """
    _assert_aal2(tenant)
    try:
        user_id = await _create_or_get_user(tenant, body.email)
        await _assign_realm_role(tenant, user_id, body.role)
        await _add_org_member(tenant, user_id)
    except StorageError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    await audit_svc.log(
        AuditEventType.ORG_USER_INVITED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        details={"invited_email": body.email, "role": body.role, "user_id": user_id},
    )
    return {
        "detail": "User created and added to organization",
        "user_id": user_id,
        "temporary_password": _DEV_TEMP_PASSWORD,
    }


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
        await _set_realm_role(tenant, user_id, body.role)
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


# Dev-only initial credential for users created via the admin page. Keycloak has
# no SMTP configured in dev, so we cannot email a reset link; the user is forced
# to change this on first login (UPDATE_PASSWORD). Prod should switch to an
# email-based invitation flow instead of a shared temporary password.
_DEV_TEMP_PASSWORD = "ChangeMe#2026!"

# Realm roles the org-admin page is allowed to assign/manage.
_MANAGED_ROLES = frozenset({"org-admin", "case-lead", "analyst", "read-only"})


async def _keycloak_admin_request(
    tenant: TenantContext,
    method: str,
    path: str,
    body: Any = None,
    *,
    allow: tuple[int, ...] = (),
) -> httpx.Response:
    """Execute a Keycloak Admin REST API call and return the raw response.

    Raises :class:`StorageError` on transport failure, any 5xx, or any 4xx whose
    status is not listed in *allow* (e.g. ``allow=(409,)`` to tolerate conflicts).
    """
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
    except httpx.HTTPError as exc:
        raise StorageError(
            "Keycloak Admin API request failed",
            context={"error": str(exc)},
        ) from exc

    if resp.status_code >= 500:
        raise StorageError(
            "Keycloak Admin API returned server error",
            context={"status": resp.status_code},
        )
    if resp.status_code >= 400 and resp.status_code not in allow:
        raise StorageError(
            "Keycloak Admin API request failed",
            context={"status": resp.status_code},
        )
    return resp


async def _create_or_get_user(tenant: TenantContext, email: str) -> str:
    """Create a Keycloak user for *email* (idempotent); return their user id."""
    representation = {
        "username": email,
        "email": email,
        "enabled": True,
        "emailVerified": True,
        "requiredActions": ["UPDATE_PASSWORD"],
        "credentials": [
            {"type": "password", "value": _DEV_TEMP_PASSWORD, "temporary": True}
        ],
    }
    resp = await _keycloak_admin_request(tenant, "POST", "/users", representation, allow=(409,))
    if resp.status_code == 201:
        # 201 Created returns no body; the new id is the last path segment of Location.
        location = resp.headers.get("location", "")
        return location.rstrip("/").rsplit("/", 1)[-1]

    # 409 Conflict: a user with this email/username already exists — reuse it.
    existing = await _find_user_by_email(tenant, email)
    if existing is None:
        raise StorageError("User already exists but could not be located", context={"email": email})
    return str(existing["id"])


async def _find_user_by_email(tenant: TenantContext, email: str) -> dict | None:
    """Return the Keycloak user with an exact email match, or None."""
    query = urllib.parse.urlencode({"email": email, "exact": "true"})
    resp = await _keycloak_admin_request(tenant, "GET", f"/users?{query}", None)
    users = resp.json()
    return users[0] if isinstance(users, list) and users else None


async def _assign_realm_role(tenant: TenantContext, user_id: str, role_name: str) -> None:
    """Add a single realm role to a user (no-op if already assigned)."""
    role = (await _keycloak_admin_request(tenant, "GET", f"/roles/{role_name}", None)).json()
    await _keycloak_admin_request(
        tenant,
        "POST",
        f"/users/{user_id}/role-mappings/realm",
        [{"id": role["id"], "name": role["name"]}],
        allow=(409,),
    )


async def _set_realm_role(tenant: TenantContext, user_id: str, role_name: str) -> None:
    """Make *role_name* the user's sole managed org role (remove the others)."""
    current = (
        await _keycloak_admin_request(tenant, "GET", f"/users/{user_id}/role-mappings/realm", None)
    ).json()
    stale = [
        {"id": r["id"], "name": r["name"]}
        for r in current
        if r.get("name") in _MANAGED_ROLES and r.get("name") != role_name
    ]
    if stale:
        await _keycloak_admin_request(
            tenant, "DELETE", f"/users/{user_id}/role-mappings/realm", stale
        )
    await _assign_realm_role(tenant, user_id, role_name)


async def _add_org_member(tenant: TenantContext, user_id: str) -> None:
    """Link an existing user to the caller's org (no-op if already a member)."""
    # Keycloak 26 adds a member via POST .../members with the user id as a
    # quoted JSON string body; 409 means they are already a member.
    await _keycloak_admin_request(
        tenant,
        "POST",
        f"/organizations/{tenant.org_id}/members",
        user_id,
        allow=(409,),
    )


def _iso_from_epoch_millis(value: Any) -> str | None:
    """Convert a Keycloak epoch-millis timestamp (int or numeric str) to ISO-8601."""
    if isinstance(value, bool):  # bool is an int subclass; never a timestamp
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000, tz=UTC).isoformat()
    if isinstance(value, str) and value.isdigit():
        return datetime.fromtimestamp(int(value) / 1000, tz=UTC).isoformat()
    return value if isinstance(value, str) else None


async def _member_managed_roles(tenant: TenantContext, user_id: str) -> list[str]:
    """Return the member's realm roles filtered to the managed org roles.

    Org member records carry no role data, so realm role-mappings are fetched
    per user. Resilient: a lookup failure yields an empty list rather than
    failing the whole listing.
    """
    if not user_id:
        return []
    try:
        mappings = (
            await _keycloak_admin_request(
                tenant, "GET", f"/users/{user_id}/role-mappings/realm", None
            )
        ).json()
    except StorageError:
        return []
    if not isinstance(mappings, list):
        return []
    return [r["name"] for r in mappings if r.get("name") in _MANAGED_ROLES]


async def _list_keycloak_org_users(tenant: TenantContext) -> list[OrgUserOut]:
    """Fetch org members from Keycloak, with their managed roles and join date."""
    path = f"/organizations/{tenant.org_id}/members"
    data = (await _keycloak_admin_request(tenant, "GET", path, None)).json()
    if not isinstance(data, list):
        return []
    roles_per_member = await asyncio.gather(
        *(_member_managed_roles(tenant, u.get("id", "")) for u in data)
    )
    return [
        OrgUserOut(
            userId=u.get("id", ""),
            username=u.get("username", ""),
            email=u.get("email", ""),
            roles=roles,
            joinedAt=_iso_from_epoch_millis(u.get("createdTimestamp")),
        )
        for u, roles in zip(data, roles_per_member, strict=True)
    ]
