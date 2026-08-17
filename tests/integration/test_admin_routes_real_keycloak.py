"""Real-Keycloak verification for org-admin membership routes.

Gap Audit P1-15 / Milestone V, item V5
(docs/GAP_AUDIT_2026-08.md): `src/external/routes/admin.py`'s
``invite_user``/``update_user_role``/``remove_user`` were, before this file,
only exercised against a mocked ``httpx`` (tests/unit/test_admin_routes.py).
CLAUDE.md §F's verification-first bar requires these org-membership-granting
routes to actually be run against a real Keycloak instance, with real state
read back afterward -- never trusted from the route's own response.

Instance used: the shared, already-running dev stack's real Keycloak 26.2
(`docker-compose.dev.yml`'s `keycloak` service, reachable at
``http://localhost:8080`` on this host) -- confirmed already up via
``docker ps`` per this initiative's own standing instructions, with the real
``kronos`` realm and its real ``kronos-dev`` org already imported/provisioned.
This suite creates its OWN two throwaway orgs (``kronos-v5-test-a``,
``kronos-v5-test-b``, mirroring poc/ci_security_enabled_stack's org-A/org-B
pattern) and throwaway users, and deletes every one of them in a
session-scoped fixture teardown -- the shared ``kronos-dev`` org and its
three realm-imported users (admin/analyst/case-lead) are never touched.

The routes under test are called directly as Python coroutines (matching
tests/unit/test_admin_routes.py's own convention of bypassing FastAPI's
``Depends`` wiring and passing an already-constructed ``TenantContext``) --
what's swapped out for this suite is not the transport, it's ``httpx``
itself: unit tests monkeypatch ``_keycloak_admin_request``; this suite lets
every one of the module's private helpers make a REAL HTTP call to the REAL
Keycloak Admin REST API. Every claim the route makes is independently
re-verified via a second, direct Admin API call from this test file itself
(never trusted from the route's return value alone), and every mutation's
audit trail is read back from a fresh ``AuditLogService``/testcontainers
Postgres connection (never from the in-process object that wrote it).

Skipped entirely (module-level) when the real dev-stack Keycloak isn't
reachable at ``KRONOS_ADMIN_ROUTES_KC_BASE`` (default
``http://localhost:8080``), mirroring tests/integration/conftest.py's
Docker-availability skip convention and
tests/integration/test_security_enabled_stack.py's env-gated skip.

Real captured evidence of the last run: poc/admin_routes_real_keycloak/output.txt.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from fastapi import HTTPException, status

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.user import Role, TenantContext
from src.external.routes.admin import (
    InviteUserIn,
    UpdateRoleIn,
    invite_user,
    remove_user,
    update_user_role,
)

pytestmark = pytest.mark.admin_routes_real_keycloak

_KC_BASE = os.environ.get("KRONOS_ADMIN_ROUTES_KC_BASE", "http://localhost:8080")
_KC_REALM = os.environ.get("KRONOS_ADMIN_ROUTES_KC_REALM", "kronos")
_KC_ADMIN_USER = os.environ.get("KRONOS_ADMIN_ROUTES_KC_ADMIN_USER", "admin")
_KC_ADMIN_PASSWORD = os.environ.get("KRONOS_ADMIN_ROUTES_KC_ADMIN_PASSWORD", "admin")
# Real value from docker-compose.dev.yml's KEYCLOAK_CLIENT_SECRET default --
# this is what admin.py's own _get_service_account_token() authenticates
# with in dev, so using anything else would not be testing the real path.
_KC_BACKEND_CLIENT_SECRET = os.environ.get(
    "KRONOS_ADMIN_ROUTES_KC_BACKEND_SECRET", "kronos-backend-secret"
)

_ORG_A_ALIAS = "kronos-v5-test-a"
_ORG_B_ALIAS = "kronos-v5-test-b"


def _kc_reachable() -> bool:
    try:
        resp = httpx.get(
            f"{_KC_BASE}/realms/{_KC_REALM}/.well-known/openid-configuration", timeout=5.0
        )
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


if not _kc_reachable():
    pytest.skip(
        f"Real Keycloak not reachable at {_KC_BASE} (realm={_KC_REALM}) -- "
        "V5 real-Keycloak admin-routes tests only run against the shared "
        "dev-stack Keycloak (docker/docker-compose.dev.yml); see "
        "poc/admin_routes_real_keycloak/README.md",
        allow_module_level=True,
    )


# ---------------------------------------------------------------------------
# Minimal, direct Admin REST API client -- deliberately NOT reusing
# src/external/routes/admin.py's own private helpers, so the verification
# reads are independent of the code under test (a bug shared by both would
# otherwise go undetected).
# ---------------------------------------------------------------------------


class _RealAdminApi:
    def __init__(self, base: str, realm: str, token: str) -> None:
        self._base = base
        self._realm = realm
        self._client = httpx.Client(
            base_url=f"{base}/admin/realms/{realm}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15.0,
        )

    def get(self, path: str) -> httpx.Response:
        return self._client.get(path)

    def post(self, path: str, json: object = None) -> httpx.Response:
        return self._client.post(path, json=json)

    def delete(self, path: str) -> httpx.Response:
        return self._client.delete(path)

    def close(self) -> None:
        self._client.close()


def _master_admin_token() -> str:
    resp = httpx.post(
        f"{_KC_BASE}/realms/master/protocol/openid-connect/token",
        data={
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": _KC_ADMIN_USER,
            "password": _KC_ADMIN_PASSWORD,
        },
        timeout=15.0,
    )
    resp.raise_for_status()
    return str(resp.json()["access_token"])


def _find_org_id_by_alias(api: _RealAdminApi, alias: str) -> str | None:
    resp = api.get("/organizations?first=0&max=1000")
    resp.raise_for_status()
    for org in resp.json():
        if org["alias"] == alias:
            return str(org["id"])
    return None


def _create_org(api: _RealAdminApi, alias: str, name: str, domain: str) -> str:
    existing = _find_org_id_by_alias(api, alias)
    if existing is not None:
        return existing
    # Real finding: this realm's Keycloak rejects org creation with
    # domains=[] ("You must provide at least one domain") -- confirmed via a
    # real 400 on the first run of this fixture. scripts/provision_keycloak_org.sh
    # tolerates an empty ORG_DOMAIN (defaults domains to []), but every real
    # invocation of it in this repo (dev's ORG_DOMAIN=kronos.dev, V3's PoC
    # org-b.kronos-ci.test) always sets one -- so this had never been
    # exercised. Not a bug in admin.py itself (which never creates orgs),
    # just this test's own fixture needing a real domain like every other
    # real org-provisioning caller in the repo.
    resp = api.post(
        "/organizations",
        json={
            "name": name,
            "alias": alias,
            "enabled": True,
            "description": "V5 PoC throwaway",
            "domains": [{"name": domain, "verified": True}],
        },
    )
    assert resp.status_code == 201, f"create org {alias} -> {resp.status_code} {resp.text}"
    org_id = _find_org_id_by_alias(api, alias)
    assert org_id is not None, f"created org {alias} not found by alias afterward"
    return org_id


def _create_realm_user(api: _RealAdminApi, username: str, email: str) -> str:
    """Create a bare realm user directly via Admin API (NOT via invite_user --
    this is test-setup scaffolding for a user that pre-exists in a
    DIFFERENT org than the one under test, standing in for the "real user,
    real other org" cross-tenant fixture)."""
    resp = api.post(
        "/users",
        json={
            "username": username,
            "email": email,
            "firstName": "V5",
            "lastName": "Fixture",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": "V5FixtureUser#2026", "temporary": True}],
        },
    )
    assert resp.status_code == 201, f"create user {username} -> {resp.status_code} {resp.text}"
    location = resp.headers["location"]
    return location.rstrip("/").rsplit("/", 1)[-1]


def _add_member(api: _RealAdminApi, org_id: str, user_id: str) -> None:
    resp = api.post(f"/organizations/{org_id}/members", json=user_id)
    assert resp.status_code in (
        201,
        204,
        409,
    ), f"add member {user_id} to org {org_id} -> {resp.status_code} {resp.text}"


def _is_member(api: _RealAdminApi, org_id: str, user_id: str) -> bool:
    return api.get(f"/organizations/{org_id}/members/{user_id}").status_code == 200


def _realm_roles(api: _RealAdminApi, user_id: str) -> set[str]:
    resp = api.get(f"/users/{user_id}/role-mappings/realm")
    resp.raise_for_status()
    return {r["name"] for r in resp.json()}


def _user_exists(api: _RealAdminApi, user_id: str) -> bool:
    return api.get(f"/users/{user_id}").status_code == 200


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Populate every required src.config.Settings field.

    admin.py's routes only ever read the keycloak_* fields (set to REAL
    values matching the running dev-stack Keycloak); every other required
    field (database_url, minio_*, opensearch_*, vault_*, celery_*) is
    inert for these three routes but Settings() is a single BaseSettings
    class with no defaults for secrets, so it must still construct.
    """
    monkeypatch.setenv("KEYCLOAK_URL", _KC_BASE)
    monkeypatch.setenv("KEYCLOAK_REALM", _KC_REALM)
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "kronos-backend")
    monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", _KC_BACKEND_CLIENT_SECRET)
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://unused:unused@localhost/unused")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("MINIO_ENDPOINT", "localhost:9000")
    monkeypatch.setenv("MINIO_ACCESS_KEY", "unused")
    monkeypatch.setenv("MINIO_SECRET_KEY", "unused")
    monkeypatch.setenv("OPENSEARCH_URL", "https://localhost:9200")
    monkeypatch.setenv("OPENSEARCH_USERNAME", "unused")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "unused")
    monkeypatch.setenv("VAULT_URL", "https://localhost:8200")
    monkeypatch.setenv("VAULT_TOKEN", "unused")
    monkeypatch.setenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
    monkeypatch.setenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")


@pytest.fixture(scope="module")
def admin_api() -> Iterator[_RealAdminApi]:
    api = _RealAdminApi(_KC_BASE, _KC_REALM, _master_admin_token())
    yield api
    api.close()


@pytest.fixture(scope="module")
def throwaway_orgs(admin_api: _RealAdminApi) -> Iterator[tuple[str, str]]:
    """Create two real, disposable orgs; delete both (and any users this
    module created) on teardown so the shared dev-stack realm is left clean."""
    org_a_id = _create_org(admin_api, _ORG_A_ALIAS, "KronOS V5 Test Org A", "org-a.kronos-v5.test")
    org_b_id = _create_org(admin_api, _ORG_B_ALIAS, "KronOS V5 Test Org B", "org-b.kronos-v5.test")
    created_user_ids: list[str] = []
    _CREATED_USER_IDS.append(created_user_ids)
    yield org_a_id, org_b_id
    for user_id in created_user_ids:
        admin_api.delete(f"/users/{user_id}")
    admin_api.delete(f"/organizations/{org_a_id}")
    admin_api.delete(f"/organizations/{org_b_id}")


# Module-level list-of-lists so test functions (which only receive
# throwaway_orgs/admin_api, not a dedicated "track this for cleanup"
# fixture) can register users they create for the shared teardown above.
_CREATED_USER_IDS: list[list[str]] = []


def _track(user_id: str) -> str:
    _CREATED_USER_IDS[-1].append(user_id)
    return user_id


@pytest.fixture(scope="module")
def org_b_member(admin_api: _RealAdminApi, throwaway_orgs: tuple[str, str]) -> str:
    """A real user who is a genuine member of org B ONLY -- the fixture for
    every cross-tenant negative case (an admin of org A must never be able
    to invite/modify/remove this user via org A's TenantContext)."""
    _, org_b_id = throwaway_orgs
    user_id = _track(
        _create_realm_user(admin_api, "v5-org-b-member", "v5-org-b-member@kronos-v5.test")
    )
    _add_member(admin_api, org_b_id, user_id)
    assert _is_member(admin_api, org_b_id, user_id)
    return user_id


def _tenant_for(org_id: str, *, username: str) -> TenantContext:
    return TenantContext(
        org_id=uuid.UUID(org_id),
        org_alias=username,
        user_id=uuid.uuid4(),
        username=username,
        roles=frozenset({Role.ORG_ADMIN}),
        correlation_id=str(uuid.uuid4()),
        acr="aal2",  # invite/role-change/remove all require step-up (_assert_aal2)
    )


@pytest.fixture(scope="module")
def tenant_a(throwaway_orgs: tuple[str, str]) -> TenantContext:
    org_a_id, _ = throwaway_orgs
    return _tenant_for(org_a_id, username="v5-admin-a")


@pytest.fixture(scope="module")
def tenant_b(throwaway_orgs: tuple[str, str]) -> TenantContext:
    _, org_b_id = throwaway_orgs
    return _tenant_for(org_b_id, username="v5-admin-b")


@pytest.fixture
async def audit_svc(postgres_engine: object) -> AsyncIterator[AuditLogService]:
    """Real AuditLogService over a real (testcontainers) Postgres -- reuses
    tests/integration/conftest.py's session-scoped postgres_engine fixture
    (already used by test_evidence_intake.py), so audit rows this suite
    writes land in a real, queryable Postgres database, not a mock."""
    repo = PostgresAuditLogRepository(postgres_engine)  # type: ignore[arg-type]
    yield AuditLogService(repo)


async def _audit_events_for_org(org_id: uuid.UUID, postgres_engine: object) -> list[object]:
    """Read the audit trail back from a FRESH repository instance (a new
    connection, not the object the route mutated through) -- this
    initiative's own established "never trust the writer's own view"
    verification pattern."""
    fresh_repo = PostgresAuditLogRepository(postgres_engine)  # type: ignore[arg-type]
    return [event async for event in fresh_repo.stream_by_org(org_id)]


# ---------------------------------------------------------------------------
# 1. invite_user
# ---------------------------------------------------------------------------


async def test_invite_user_creates_real_user_linked_only_to_caller_org(
    admin_api: _RealAdminApi,
    throwaway_orgs: tuple[str, str],
    tenant_a: TenantContext,
    audit_svc: AuditLogService,
    postgres_engine: object,
) -> None:
    org_a_id, org_b_id = throwaway_orgs
    email = f"v5-invitee-{uuid.uuid4().hex[:8]}@kronos-v5.test"
    body = InviteUserIn(
        email=email,
        firstName="V5",
        lastName="Invitee",
        password="V5InviteeStrongPw!42",
        role="analyst",
    )

    result = await invite_user(body, tenant_a, audit_svc)

    assert result["created"] is True
    user_id = str(result["userId"])
    _track(user_id)

    # Independently re-verify via a SEPARATE, direct Admin API call -- never
    # trust the route's own return value.
    assert _is_member(admin_api, org_a_id, user_id) is True, (
        "invite_user reported success but the real Keycloak org-membership "
        "endpoint does not show the user as a member of org A"
    )
    assert (
        _is_member(admin_api, org_b_id, user_id) is False
    ), "invited user must NOT be linked to any org other than the caller's"
    assert "analyst" in _realm_roles(admin_api, user_id)

    events = await _audit_events_for_org(tenant_a.org_id, postgres_engine)
    invited = [e for e in events if e.event_type == AuditEventType.ORG_USER_INVITED]  # type: ignore[attr-defined]
    assert any(e.details.get("user_id") == user_id for e in invited), (  # type: ignore[attr-defined]
        "ORG_USER_INVITED audit event not found when read back from a fresh " "Postgres connection"
    )


async def test_invite_user_rejects_reusing_an_email_that_belongs_to_another_org(
    admin_api: _RealAdminApi,
    throwaway_orgs: tuple[str, str],
    tenant_a: TenantContext,
    org_b_member: str,
    audit_svc: AuditLogService,
) -> None:
    """AUTH-003/AUTH-011 cross-tenant negative case: org A's admin tries to
    "invite" (i.e. reuse) an email that is a real, existing member of org B."""
    org_a_id, org_b_id = throwaway_orgs
    body = InviteUserIn(
        email="v5-org-b-member@kronos-v5.test",
        firstName="Should",
        lastName="NotMatter",
        password="ShouldNotMatterPw!42",
        role="org-admin",
    )

    with pytest.raises(HTTPException) as exc_info:
        await invite_user(body, tenant_a, audit_svc)
    assert exc_info.value.status_code == 409, (
        f"expected a real 409 conflict, got {exc_info.value.status_code}: "
        f"{exc_info.value.detail}"
    )
    # AUTH-011: the error must not confirm which org the email belongs to.
    assert (
        "org" not in exc_info.value.detail.lower()
        or "different account" in exc_info.value.detail.lower()
    )

    # Real, independent confirmation the org-B user was NOT touched: still
    # only a member of org B, never granted org-admin, never added to org A.
    assert _is_member(admin_api, org_b_id, org_b_member) is True
    assert _is_member(admin_api, org_a_id, org_b_member) is False
    assert "org-admin" not in _realm_roles(admin_api, org_b_member)


# ---------------------------------------------------------------------------
# 2. update_user_role
# ---------------------------------------------------------------------------


async def test_update_user_role_persists_in_real_keycloak(
    admin_api: _RealAdminApi,
    throwaway_orgs: tuple[str, str],
    tenant_a: TenantContext,
    audit_svc: AuditLogService,
    postgres_engine: object,
) -> None:
    org_a_id, _ = throwaway_orgs
    user_id = _track(
        _create_realm_user(
            admin_api,
            f"v5-role-target-{uuid.uuid4().hex[:8]}",
            f"v5-role-target-{uuid.uuid4().hex[:8]}@kronos-v5.test",
        )
    )
    _add_member(admin_api, org_a_id, user_id)

    await update_user_role(user_id, UpdateRoleIn(role="case-lead"), tenant_a, audit_svc)

    # Read back via a fresh, independent Admin API call.
    roles_after = _realm_roles(admin_api, user_id)
    assert "case-lead" in roles_after
    assert "analyst" not in roles_after  # _set_realm_role removes stale managed roles

    events = await _audit_events_for_org(tenant_a.org_id, postgres_engine)
    changed = [e for e in events if e.event_type == AuditEventType.ORG_USER_ROLE_CHANGED]  # type: ignore[attr-defined]
    assert any(
        e.details.get("target_user_id") == user_id and e.details.get("new_role") == "case-lead"  # type: ignore[attr-defined]
        for e in changed
    ), "ORG_USER_ROLE_CHANGED audit event not found when read back fresh"


async def test_update_user_role_rejects_cross_org_target(
    admin_api: _RealAdminApi,
    tenant_a: TenantContext,
    org_b_member: str,
    audit_svc: AuditLogService,
    postgres_engine: object,
) -> None:
    roles_before = _realm_roles(admin_api, org_b_member)

    with pytest.raises(HTTPException) as exc_info:
        await update_user_role(org_b_member, UpdateRoleIn(role="org-admin"), tenant_a, audit_svc)
    assert exc_info.value.status_code == 403

    # Real proof the rejection actually prevented the mutation.
    assert _realm_roles(admin_api, org_b_member) == roles_before
    assert "org-admin" not in roles_before

    events = await _audit_events_for_org(tenant_a.org_id, postgres_engine)
    changed = [e for e in events if e.event_type == AuditEventType.ORG_USER_ROLE_CHANGED]  # type: ignore[attr-defined]
    assert not any(e.details.get("target_user_id") == org_b_member for e in changed)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# 3. remove_user
# ---------------------------------------------------------------------------


async def test_remove_user_removes_real_org_membership(
    admin_api: _RealAdminApi,
    throwaway_orgs: tuple[str, str],
    tenant_a: TenantContext,
    audit_svc: AuditLogService,
    postgres_engine: object,
) -> None:
    org_a_id, _ = throwaway_orgs
    uniq = uuid.uuid4().hex[:8]
    user_id = _track(
        _create_realm_user(
            admin_api, f"v5-remove-target-{uniq}", f"v5-remove-target-{uniq}@kronos-v5.test"
        )
    )
    _add_member(admin_api, org_a_id, user_id)
    assert _is_member(admin_api, org_a_id, user_id) is True

    await remove_user(user_id, tenant_a, audit_svc)

    # Real, independent confirmation the org-membership link is gone.
    assert _is_member(admin_api, org_a_id, user_id) is False

    # Document (not assume) what remove_user actually does to the realm-level
    # account: it DELETEs only the org-membership link
    # (/organizations/{org}/members/{user}), never /users/{user} -- so the
    # realm account is expected to still exist afterward. Confirmed here
    # against the real Admin API rather than inferred from a source read.
    assert _user_exists(admin_api, user_id) is True, (
        "remove_user's real behavior changed: the realm-level account no "
        "longer exists after a call that only ever DELETEs the "
        "organizations/{org}/members/{user} endpoint -- update this "
        "assertion (and the docstring below) if that is now intentional"
    )

    events = await _audit_events_for_org(tenant_a.org_id, postgres_engine)
    removed = [e for e in events if e.event_type == AuditEventType.ORG_USER_REMOVED]  # type: ignore[attr-defined]
    assert any(e.details.get("removed_user_id") == user_id for e in removed)  # type: ignore[attr-defined]


async def test_remove_user_cannot_remove_a_cross_org_member(
    admin_api: _RealAdminApi,
    throwaway_orgs: tuple[str, str],
    tenant_a: TenantContext,
    org_b_member: str,
    audit_svc: AuditLogService,
) -> None:
    """remove_user's DELETE target is
    /organizations/{tenant.org_id}/members/{user_id} -- already org-A-scoped
    by construction (no separate _assert_user_in_org call, unlike
    update_user_role). This test proves that scoping is real: Keycloak
    itself must reject a delete of a member id that doesn't belong to org A,
    not something assumed from reading the route's source."""
    _, org_b_id = throwaway_orgs

    with pytest.raises(HTTPException) as exc_info:
        await remove_user(org_b_member, tenant_a, audit_svc)
    # Real observed status -- captured for real in
    # poc/admin_routes_real_keycloak/output.txt's standalone probe -- is a
    # genuine Keycloak 404 (the DELETE target doesn't exist under org A).
    # Previously fell through to a misleading 503 (Gap Audit V5's own
    # finding, closed by Milestone Z's _to_http_error() fix); now asserted
    # precisely rather than the old, looser ">= 400".
    assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND

    assert _is_member(admin_api, org_b_id, org_b_member) is True, (
        "cross-org remove_user call must never actually remove the target " "from its real org"
    )
