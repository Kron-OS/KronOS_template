"""Org admin endpoints — user management and org settings."""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator

from src.adapter.queue.task_queue import TaskQueue
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.repository.quota import OrgQuotaRepository
from src.application.audit_log import AuditLogService
from src.application.quota_gate import StorageQuotaGate
from src.domain.audit import AuditEventType
from src.domain.quota import OrgQuota
from src.domain.user import Role, TenantContext
from src.exceptions import StorageError
from src.external.dependencies import (
    get_audit_log_service,
    get_evidence_repository,
    get_org_quota_repository,
    get_storage_quota_gate,
    get_task_queue,
)
from src.external.middleware.rbac import requires_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin/org", tags=["admin"])

_ADMIN_ROLES = (Role.ORG_ADMIN,)
_ACR_LEVEL = {"aal1": 1, "aal2": 2}


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

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class InviteUserIn(BaseModel):
    """Direct-create payload: the org-admin sets the new user's identity and
    initial password up front (no SMTP in dev) and communicates the password
    out of band. The user must change it on first login."""

    email: str = Field(description="Email address of the new user (also their username)")
    firstName: str = Field(min_length=1, max_length=255, description="Given name")
    lastName: str = Field(min_length=1, max_length=255, description="Family name")
    password: str = Field(
        min_length=12,
        max_length=255,
        description="Initial password; the user must change it on first login",
    )
    role: _OrgRole = Field(description="Role to assign")

    @field_validator("email")
    @classmethod
    def _validate_email_format(cls, value: str) -> str:
        if not _EMAIL_RE.match(value):
            raise ValueError("must be a valid email address")
        return value

    @model_validator(mode="after")
    def _validate_password_not_email(self) -> InviteUserIn:
        local_part = self.email.split("@", 1)[0].lower()
        password_lower = self.password.lower()
        if self.email.lower() in password_lower or (local_part and local_part in password_lower):
            raise ValueError("password must not contain the user's email or username")
        return self


class UpdateRoleIn(BaseModel):
    role: _OrgRole


class OrgSettingsOut(BaseModel):
    """API response DTO — field names match the frontend TypeScript OrgSettings interface."""

    retentionDays: int
    legalHoldDefault: bool


class UpdateSettingsIn(BaseModel):
    retentionDays: int = Field(ge=1, le=3650)


class OrgQuotaOut(BaseModel):
    """API response DTO for the org's storage quota + real current usage
    (docs/TENANT_USAGE_QUOTA.md). A dedicated shape from OrgSettingsOut --
    see the module-level note on the /quota routes below for why."""

    storageQuotaBytes: int | None
    currentUsageBytes: int
    updatedAt: str | None


class UpdateQuotaIn(BaseModel):
    # None explicitly means "unlimited" -- a real, valid value (see
    # OrgQuota's own docstring), not "field omitted"; Pydantic's Optional
    # field with no default-omission special case is exactly what's wanted
    # here (the frontend must send null, not just leave the key out, to
    # clear a quota).
    storageQuotaBytes: int | None = Field(default=None, ge=0)


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
    except StorageError as exc:
        # A Keycloak Admin API failure (auth, permissions, connectivity) is
        # not "this org has zero users" — returning an empty 200 here hid
        # the real error behind a misleading empty state instead of the
        # frontend's existing "Failed to load users" error banner.
        raise _to_http_error(exc) from exc
    return OrgUsersResponse(items=users, total=len(users))


@router.post("/users/invite", status_code=status.HTTP_201_CREATED)
async def invite_user(
    body: InviteUserIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> dict[str, Any]:
    """Create a user, add them to the caller's org, and assign their role.

    This is a direct-create flow (no email): Keycloak has no SMTP configured
    in dev, so rather than send an invitation link the org-admin sets the
    user's name and initial password directly and shares it out of band. The
    new user must change this password on first login (UPDATE_PASSWORD). If
    a user with this email already exists **and already belongs to the
    caller's org**, they are reused and their role is REPLACED with the
    requested one (their name/password are untouched) — Gap Audit Milestone
    NN: this used to call ``_assign_realm_role`` (add-only), so re-inviting
    an existing member with a *different* role left them with BOTH the old
    and new managed role simultaneously — e.g. attempting to demote an
    org-admin to read-only via this route silently left them still a real,
    live org-admin. Confirmed real against a live Keycloak 26.2.5
    (``poc/admin_reinvite_role_escalation/``). Now uses ``_set_realm_role``
    (the same replace-not-add helper ``update_user_role`` already used
    correctly), so a re-invite's role is authoritative, matching this
    docstring's own "re-assigned" claim. An email that already exists under
    a *different* org is never reused, re-roled, or acknowledged as existing
    (AUTH-003/AUTH-011) — see ``_find_user_by_email``.

    Org membership is established (``_add_org_member``) *before* any
    realm-role-mapping call, so ``_set_realm_role`` never touches a user
    who isn't confirmed as a member of ``tenant.org_id`` (AUTH-003).
    """
    _assert_aal2(tenant)
    try:
        user_id, created = await _create_or_get_user(
            tenant, body.email, body.firstName, body.lastName, body.password
        )
        await _add_org_member(tenant, user_id)
        await _assert_user_in_org(tenant, user_id)
        await _set_realm_role(tenant, user_id, body.role)
    except StorageError as exc:
        raise _to_http_error(exc) from exc

    await audit_svc.log(
        AuditEventType.ORG_USER_INVITED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        details={
            "invited_email": body.email,
            "first_name": body.firstName,
            "last_name": body.lastName,
            "role": body.role,
            "user_id": user_id,
            "created_new_user": created,
        },
    )
    return {
        "detail": (
            "User created and added to organization"
            if created
            else "Existing user added to organization"
        ),
        "userId": user_id,
        "created": created,
    }


@router.patch("/users/{user_id}/role", response_model=OrgUserOut)
async def update_user_role(
    user_id: str,
    body: UpdateRoleIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> OrgUserOut:
    """Change a user's role within the org."""
    _assert_aal2(tenant)
    try:
        await _assert_user_in_org(tenant, user_id)
        await _set_realm_role(tenant, user_id, body.role)
    except StorageError as exc:
        raise _to_http_error(exc) from exc

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
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
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
        raise _to_http_error(exc) from exc

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

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars
    return OrgSettingsOut(
        retentionDays=settings.minio_default_retention_days,
        legalHoldDefault=False,
    )


@router.patch("/settings", response_model=OrgSettingsOut)
async def update_org_settings(
    body: UpdateSettingsIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> OrgSettingsOut:
    """Update org retention defaults (stored in-org metadata)."""
    _assert_aal2(tenant)
    await audit_svc.log(
        AuditEventType.ORG_SETTINGS_UPDATED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        details={"retention_days": body.retentionDays},
    )
    return OrgSettingsOut(retentionDays=body.retentionDays, legalHoldDefault=False)


# ---------------------------------------------------------------------------
# Storage quota (docs/TENANT_USAGE_QUOTA.md) -- a DEDICATED route, not an
# extension of /settings above. /settings's own DTOs
# (OrgSettingsOut/UpdateSettingsIn) are shaped 1:1 around a specific,
# already-shipped frontend TypeScript interface (retentionDays/
# legalHoldDefault) that this feature has no reason to touch, and that
# stub's pre-existing "doesn't persist anywhere real" gap is explicitly
# out of scope to fix in this pass (docs/TENANT_USAGE_QUOTA.md §0) --
# bolting a third, unrelated field onto that payload/audit-event would
# conflate two independent admin concerns (retention defaults vs. a
# storage ceiling) in one contract and one audit event type. A dedicated
# route keeps its own real persistence (OrgQuotaRepository), its own audit
# event (QUOTA_UPDATED), and can evolve (e.g. surfacing usage history)
# without touching the settings stub -- mirroring how /users and /settings
# are already separate route groups under this same router despite both
# being "admin" concerns.
# ---------------------------------------------------------------------------


@router.get("/quota", response_model=OrgQuotaOut)
async def get_org_quota(
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    quota_repo: Annotated[OrgQuotaRepository, Depends(get_org_quota_repository)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
) -> OrgQuotaOut:
    """Return the org's configured storage quota and real current usage."""
    quota = await quota_repo.get(tenant.org_id)
    usage = await evidence_repo.get_total_size_bytes(tenant.org_id)
    return OrgQuotaOut(
        storageQuotaBytes=quota.storage_quota_bytes if quota is not None else None,
        currentUsageBytes=usage,
        updatedAt=quota.updated_at.isoformat() if quota is not None else None,
    )


@router.patch("/quota", response_model=OrgQuotaOut)
async def update_org_quota(
    body: UpdateQuotaIn,
    tenant: Annotated[TenantContext, Depends(requires_role(*_ADMIN_ROLES))],
    quota_repo: Annotated[OrgQuotaRepository, Depends(get_org_quota_repository)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    quota_gate: Annotated[StorageQuotaGate, Depends(get_storage_quota_gate)],
    task_queue: Annotated[TaskQueue, Depends(get_task_queue)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> OrgQuotaOut:
    """Set (or clear, via null) the org's storage quota.

    Direct-trigger resume: docs/TENANT_USAGE_QUOTA.md §2 asks for "a beat-
    task sweep, plus a direct trigger on the PATCH that raises a quota" --
    implemented here as belt-and-braces alongside auto_resume_quota_held
    (src/external/celery_app.py). If the new quota drops usage back under
    the soft ceiling, any evidence this org already has held is
    re-enqueued immediately rather than making analysts wait for the next
    beat sweep; the beat sweep remains the safety net for org quota
    increases that happen to race a broker hiccup, and for the
    non-PATCH path (usage dropping because evidence was deleted).
    """
    _assert_aal2(tenant)
    existing = await quota_repo.get(tenant.org_id)
    new_quota = (existing or OrgQuota(org_id=tenant.org_id)).with_quota_bytes(
        body.storageQuotaBytes
    )
    await quota_repo.upsert(new_quota)

    await audit_svc.log(
        AuditEventType.QUOTA_UPDATED,
        org_id=tenant.org_id,
        actor_user_id=tenant.user_id,
        actor_username=tenant.username,
        details={"storage_quota_bytes": body.storageQuotaBytes},
    )

    if not await quota_gate.is_ingestion_held(tenant.org_id):
        async for ev in evidence_repo.stream_quota_held(tenant.org_id):
            try:
                await task_queue.enqueue_dispatch(ev.evidence_id, tenant)
            except Exception as exc:  # noqa: BLE001 -- best-effort; beat sweep is the safety net
                logger.warning(
                    "quota_patch_resume_enqueue_failed",
                    extra={"evidence_id": str(ev.evidence_id), "error": str(exc)},
                )

    usage = await evidence_repo.get_total_size_bytes(tenant.org_id)
    return OrgQuotaOut(
        storageQuotaBytes=new_quota.storage_quota_bytes,
        currentUsageBytes=usage,
        updatedAt=new_quota.updated_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _keycloak_error_message(body: Any) -> str | None:
    """Extract a human-readable message from a Keycloak ErrorRepresentation body.

    Keycloak reports validation failures (e.g. password policy) as
    ``{"errorMessage": "..."}``, sometimes with the real message nested one
    level down in ``{"errors": [{"errorMessage": "..."}]}``.
    """
    if not isinstance(body, dict):
        return None
    if isinstance(body.get("errorMessage"), str):
        return body["errorMessage"]
    nested = body.get("errors")
    if isinstance(nested, list) and nested and isinstance(nested[0], dict):
        return nested[0].get("errorMessage")
    return None


def _to_http_error(exc: StorageError) -> HTTPException:
    """Map a Keycloak StorageError to a client-appropriate HTTPException.

    400 (bad request body — e.g. a password-policy violation Keycloak itself
    rejects) surfaces as 422 with Keycloak's own error message so the admin
    can correct their input. 409 (email already registered to an account
    outside the caller's org — see ``_find_user_by_email``) surfaces as a
    plain 409 with a message that does not confirm which org the email
    belongs to (AUTH-011). 404 (the target user/org-membership genuinely
    doesn't exist -- e.g. a cross-org ``remove_user``/``update_user_role``
    call, which Keycloak itself rejects as "not found" rather than the
    route pre-checking membership) surfaces as a plain 404, not a
    misleading 503 -- confirmed real, not assumed, via
    ``poc/admin_routes_real_keycloak/output.txt``'s standalone probe (Gap
    Audit V5's own finding, closed here). Anything else means the Admin
    API is down or misbehaving, which is a 503.
    """
    status_code = exc.context.get("status")
    if status_code == 400:
        message = _keycloak_error_message(exc.context.get("body"))
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=message or "Keycloak rejected the request (check the password policy)",
        )
    if status_code == 409:
        message = _keycloak_error_message(exc.context.get("body"))
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=message or "This email is already registered to a different account",
        )
    if status_code == 404:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in this organization",
        )
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))


def _assert_aal2(tenant: TenantContext) -> None:
    """Raise 401 step-up challenge if the token doesn't satisfy aal2."""
    if _ACR_LEVEL.get(tenant.acr, 0) < 2:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Step-up authentication required for this operation",
            headers={
                "WWW-Authenticate": (
                    'Bearer error="insufficient_user_authentication", acr_values="aal2"'
                )
            },
        )


async def _get_service_account_token(tenant: TenantContext) -> str:
    """Obtain a Keycloak service-account token for Admin REST API calls."""
    from src.config import Settings  # noqa: PLC0415

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars
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
    return resp.json()["access_token"]


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

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars
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
        error_body: Any
        try:
            error_body = resp.json()
        except ValueError:
            error_body = resp.text[:500]
        raise StorageError(
            "Keycloak Admin API request failed",
            context={"status": resp.status_code, "body": error_body},
        )
    return resp


async def _create_or_get_user(
    tenant: TenantContext, email: str, first_name: str, last_name: str, password: str
) -> tuple[str, bool]:
    """Create a Keycloak user for *email* (idempotent); return (user_id, created).

    *created* is False when a user with this email already existed **and
    already belonged to the caller's org** and was reused instead — in that
    case their name and password are left untouched. A 409 whose existing
    account is *not* a member of the caller's org is surfaced as a generic
    conflict, never reused or attributed to another tenant (AUTH-003/AUTH-011).
    """
    representation = {
        "username": email,
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "enabled": True,
        "emailVerified": True,
        "requiredActions": ["UPDATE_PASSWORD"],
        "credentials": [{"type": "password", "value": password, "temporary": True}],
    }
    resp = await _keycloak_admin_request(tenant, "POST", "/users", representation, allow=(409,))
    if resp.status_code == 201:
        # 201 Created returns no body; the new id is the last path segment of Location.
        location = resp.headers.get("location", "")
        return location.rstrip("/").rsplit("/", 1)[-1], True

    # 409 Conflict: a user with this email/username already exists somewhere in
    # the realm. Only reuse it if it's already a member of the caller's org.
    existing = await _find_user_by_email(tenant, email)
    if existing is None:
        raise StorageError(
            "Email already registered to a different account",
            context={
                "status": 409,
                "body": {
                    "errorMessage": (
                        "This email is already registered to a different account. "
                        "Contact an administrator if you believe this is an error."
                    )
                },
            },
        )
    return str(existing["id"]), False


async def _find_user_by_email(tenant: TenantContext, email: str) -> dict[str, Any] | None:
    """Return the Keycloak user with an exact email match, scoped to the caller's org.

    A realm-wide email search would let any org-admin discover — and, via
    ``_create_or_get_user``'s reuse path, silently attach a role to — an
    account that belongs to a completely different tenant (AUTH-003). It
    would also let them enumerate account existence outside their own org
    (AUTH-011). So this only returns a match that is already confirmed as a
    member of ``tenant.org_id``; a match belonging to any other org (or no
    org) is treated identically to "no such user".
    """
    query = urllib.parse.urlencode({"email": email, "exact": "true"})
    resp = await _keycloak_admin_request(tenant, "GET", f"/users?{query}", None)
    users = resp.json()
    if not (isinstance(users, list) and users):
        return None
    candidate = users[0]
    user_id = str(candidate.get("id", ""))
    if not user_id or not await _is_org_member(tenant, user_id):
        return None
    return candidate


async def _is_org_member(tenant: TenantContext, user_id: str) -> bool:
    """Return True if *user_id* is a member of ``tenant.org_id``.

    Uses the same org-membership endpoint ``remove_user`` already relies on
    for its (correctly) org-scoped delete, just as a read instead of a
    DELETE: 200 means the user is a member, 404 means they are not.
    """
    resp = await _keycloak_admin_request(
        tenant,
        "GET",
        f"/organizations/{tenant.org_id}/members/{user_id}",
        None,
        allow=(404,),
    )
    return resp.status_code == 200


async def _assert_user_in_org(tenant: TenantContext, user_id: str) -> None:
    """Raise 403 unless *user_id* is a member of the caller's org.

    This is the mandatory guard before any realm-role-mapping Admin API call
    (AUTH-003): those endpoints are realm-wide and have no built-in org
    scoping, so without this check any org-admin could grant or revoke any
    realm role — including org-admin itself — on a user in a different
    tenant.
    """
    if not await _is_org_member(tenant, user_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target user is not a member of your organization",
        )


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
