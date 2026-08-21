#!/usr/bin/env python3
"""Verification-first PoC: POST /api/detections/{id}/contain/revoke-session
(roadmap M7/H2/EE1 -- Gap Audit EE1, closes H2's own explicitly-flagged
"no HTTP route wiring this pass" gap for RevokeKeycloakSessionAction).

H2 (poc/containment_approval_gate/) already proved RevokeKeycloakSessionAction/
ApprovalGate/HttpxKeycloakAdminClient work end to end against real Keycloak
26.2.5 + Postgres 16 -- but only by calling PlaybookExecutionService.execute()
directly in Python. This PoC proves the NEW real HTTP route (this pass's
own deliverable) reaches the exact same real, unmodified src/ classes,
including the NEW DI wiring in src/external/dependencies.py
(get_keycloak_admin_client, get_containment_approval_gate,
get_revoke_keycloak_session_action, get_playbook_action_registry's new
revoke_keycloak_session registration) -- not just that the underlying
classes still pass their own unit tests.

Two layers of "real" are exercised here, in order:
  1. DI WIRING: configure_keycloak_admin_client_from_settings() (patched
     Settings, real values) -> get_keycloak_admin_client() -> the REAL,
     unmodified get_playbook_action_registry() (which internally calls the
     new get_revoke_keycloak_session_action()/get_containment_approval_gate())
     -> confirms the registry produced by the real DI functions actually
     contains a real, working RevokeKeycloakSessionAction.
  2. HTTP ROUTE: that real registry (plus a real Postgres-backed
     AuditLogService and the real, unmodified create_app()) is exercised
     via httpx.ASGITransport (the established in-process pattern this
     initiative uses throughout -- see poc/evidence_download/run_poc.py) --
     never TestClient (its threaded portal is incompatible with an async
     SQLAlchemy engine created in this coroutine's own loop, the same W3/
     W8/W11/W14 finding poc/evidence_download/run_poc.py already
     documents).

Real, live Keycloak 26.2.5 sessions are created via the real scripted
Authorization Code + PKCE login (poc/auth_flow/auth_helpers.py's own
real_browser_login()) -- no password grant, no hand-minted tokens, no
fabricated session ids -- exactly H2's own established approach.

Scenarios (all four required by this item's own brief):
  (a) A real session revoked successfully with a real, valid step-up
      ticket obtained via the real POST /api/step-up/ticket route FIRST.
  (b) The same call with NO ticket is correctly denied -- independently
      re-confirmed via a fresh Admin API call that the session survives.
  (c) A cross-tenant attempt (a second real org's real user/session) is
      correctly rejected even with an otherwise-valid ticket --
      independently confirmed the session survives.
  (d) Role-gating is actually enforced: an ANALYST-only tenant gets a
      real 403, not silently allowed through.

Run: ~/venv/bin/python3 poc/revoke_session_route/run_poc.py
Requires: docker-keycloak-1 (26.2.5), docker-postgres-1 (16) already
running, and a fresh nginx/step-ca leaf cert (see docs/NEXTGEN_SOC_ROADMAP.md
SS5's documented daily friction -- `docker compose -f
docker/docker-compose.dev.yml up -d tls-init && docker restart
docker-nginx-1` if kronos.local's cert has expired).
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "poc" / "auth_flow"))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

import auth_helpers as ah  # noqa: E402
from src.adapter.repository.detection import InMemoryDetectionRepository  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_triage import DetectionTriageService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external import dependencies as deps  # noqa: E402
from src.external.fastapi_app import create_app  # noqa: E402
from src.external.middleware.step_up_store import InMemoryTicketStore  # noqa: E402
from src.external.middleware.tenant_context import get_tenant_context  # noqa: E402

KEYCLOAK_INTERNAL_URL = "http://localhost:8080"  # host-published port, real docker-keycloak-1
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

ADMIN_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")  # realm role: org-admin
ANALYST_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000002")  # realm role: analyst
KRONOS_DEV_ORG_ALIAS = "kronos-dev"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


# ---------------------------------------------------------------------------
# Real Admin API helpers (raw httpx -- deliberately NOT the src/ adapter
# under test, so verification is independent of the code being verified).
# Mirrors poc/containment_approval_gate/run_poc.py's own established helpers.
# ---------------------------------------------------------------------------


async def get_raw_admin_token(client: httpx.AsyncClient) -> str:
    resp = await client.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
            "client_secret": KEYCLOAK_ADMIN_CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


async def raw_get_org_id(client: httpx.AsyncClient, token: str, alias: str) -> str:
    resp = await client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations?first=0&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    for org in resp.json():
        if org["alias"] == alias:
            return org["id"]
    raise RuntimeError(f"org alias {alias} not found")


async def raw_list_sessions(client: httpx.AsyncClient, token: str, user_id: uuid.UUID) -> list[dict]:
    """Independent, fresh re-check -- a SEPARATE Admin API round trip from
    whatever the real HTTP route itself did, per this item's own proof bar."""
    resp = await client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()


async def raw_create_org(client: httpx.AsyncClient, token: str, alias: str, name: str) -> str:
    # Real Keycloak 26.2.5 finding (rediscovered here, first found by H2's
    # own PoC): organization creation rejects an empty domains list with a
    # real 400 ("You must provide at least one domain").
    resp = await client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": name,
            "alias": alias,
            "enabled": True,
            "domains": [{"name": f"{alias}.invalid", "verified": True}],
        },
    )
    resp.raise_for_status()
    return await raw_get_org_id(client, token, alias)


async def raw_create_user(
    client: httpx.AsyncClient, token: str, username: str, password: str
) -> uuid.UUID:
    # Real Keycloak 26.2.5 finding (H2's own PoC): this realm's Declarative
    # User Profile requires firstName/lastName for a real login to
    # complete without redirecting to VERIFY_PROFILE.
    resp = await client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "username": username,
            "email": f"{username}@example.invalid",
            "firstName": "PoC",
            "lastName": "EE1User",
            "enabled": True,
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    resp.raise_for_status()
    location = resp.headers["Location"]
    return uuid.UUID(location.rsplit("/", 1)[-1])


async def raw_add_org_member(
    client: httpx.AsyncClient, token: str, org_id: str, user_id: uuid.UUID
) -> None:
    resp = await client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org_id}/members",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=f'"{user_id}"',
    )
    resp.raise_for_status()


async def raw_delete_org(client: httpx.AsyncClient, token: str, org_id: str) -> None:
    await client.delete(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org_id}",
        headers={"Authorization": f"Bearer {token}"},
    )


async def raw_delete_user(client: httpx.AsyncClient, token: str, user_id: uuid.UUID) -> None:
    await client.delete(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
    )


def real_login_get_session(username: str, password: str, state: str) -> tuple[str, str]:
    """Real scripted browser login (Authorization Code + PKCE) against the
    real dev-stack Keycloak via kronos.local -- returns (access_token, sid)."""
    ah.trust_dev_stack_step_ca("docker-tls-init-1")
    ah.KC = "https://kronos.local:8443"
    ah.REDIRECT_URI = "https://kronos.local/poc-ee1-callback"
    tokens, _new_secret, _mfa_path = ah.real_browser_login(
        username, password, totp_secret=None, state=state
    )
    claims = ah.decode_jwt_payload(tokens["access_token"])
    return tokens["access_token"], claims["sid"]


def make_tenant(
    org_id: uuid.UUID, org_alias: str, user_id: uuid.UUID, username: str, *roles: Role
) -> TenantContext:
    return TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=user_id,
        username=username,
        roles=frozenset(roles),
        correlation_id=str(uuid.uuid4()),
        acr="aal2",
    )


def _fake_keycloak_settings() -> SimpleNamespace:
    """Minimal real-shaped Settings double for
    configure_keycloak_admin_client_from_settings() -- same style as
    tests/unit/external/test_playbook_action_registry_wiring.py's own
    _fake_splunk_settings(), pointed at the REAL docker-keycloak-1
    kronos-backend service-account credentials (not fabricated values)."""
    secret = MagicMock()
    secret.get_secret_value.return_value = KEYCLOAK_ADMIN_CLIENT_SECRET
    return SimpleNamespace(
        keycloak_url=KEYCLOAK_INTERNAL_URL,
        keycloak_realm=KEYCLOAK_REALM,
        keycloak_client_id=KEYCLOAK_ADMIN_CLIENT_ID,
        keycloak_client_secret=secret,
    )


async def main() -> None:
    deps.reset_dependencies()

    async with httpx.AsyncClient(timeout=15) as raw:
        admin_token = await get_raw_admin_token(raw)
        kronos_dev_org_id = uuid.UUID(await raw_get_org_id(raw, admin_token, KRONOS_DEV_ORG_ALIAS))
        log(f"real kronos-dev org id resolved via Admin API: {kronos_dev_org_id}")

        # -------------------------------------------------------------
        # Layer 1: DI WIRING -- prove the real, new dependencies.py
        # provider functions (not a hand-built registry) produce a real,
        # working RevokeKeycloakSessionAction.
        # -------------------------------------------------------------
        log("=== DI wiring: configure_keycloak_admin_client_from_settings() -> real client ===")
        with patch("src.config.Settings", return_value=_fake_keycloak_settings()):
            deps.configure_keycloak_admin_client_from_settings()
        admin_client = deps.get_keycloak_admin_client()
        check(
            "get_keycloak_admin_client() returns a real HttpxKeycloakAdminClient "
            "after configure_keycloak_admin_client_from_settings()",
            admin_client is not None,
        )

        engine = create_async_engine(POSTGRES_DSN)
        await PostgresAuditLogRepository.create_tables(engine)
        audit_repo = PostgresAuditLogRepository(engine)
        audit_log = AuditLogService(audit_repo)

        ticket_store = InMemoryTicketStore()
        deps.configure_step_up_auth(ticket_store)

        detection_repo = InMemoryDetectionRepository()
        triage_service = DetectionTriageService(detection_repo, audit_log)
        registry = deps.get_playbook_action_registry(detection_repo, triage_service, audit_log)
        revoke_action = registry.get_action("revoke_keycloak_session")
        check(
            "the REAL get_playbook_action_registry() (unmodified DI function) registers "
            "a real RevokeKeycloakSessionAction once a real KeycloakAdminClient is configured",
            revoke_action is not None,
        )
        execution_service = deps.get_playbook_execution_service(registry, audit_log)

        # -------------------------------------------------------------
        # Layer 2: the real HTTP route, via httpx.ASGITransport against
        # the real, unmodified create_app() -- the same in-process
        # pattern poc/evidence_download/run_poc.py already established.
        # -------------------------------------------------------------
        app = create_app(step_up_ticket_store=ticket_store)
        app.dependency_overrides[deps.get_playbook_action_registry] = lambda: registry
        app.dependency_overrides[deps.get_playbook_execution_service] = lambda: execution_service

        current_tenant: TenantContext = make_tenant(
            kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ADMIN_USER_ID, "admin", Role.ORG_ADMIN
        )
        app.dependency_overrides[get_tenant_context] = lambda: current_tenant

        detection_id = uuid.uuid4()  # audit-context only; RevokeKeycloakSessionAction
        # never looks the Detection up itself (see the route's own docstring).

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://poc-ee1"
        ) as client:
            # ---------------------------------------------------------
            # Scenario (a): real ticket via the real step-up route, then
            # a real revoke via the real new containment route.
            # ---------------------------------------------------------
            log("=== Scenario (a): real ticket (POST /api/step-up/ticket) then real revoke ===")
            _tok_a, session_a = real_login_get_session(
                "analyst", "DevAnalyst#2026", state="poc-ee1-scenario-a"
            )
            log(f"real analyst login (a) succeeded, sid={session_a}")
            sessions_before_a = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
            check(
                "(a) real session appears in a fresh, independent Admin API sessions list "
                "before any route call",
                any(s["id"] == session_a for s in sessions_before_a),
            )

            ticket_resp = await client.post(
                "/api/step-up/ticket",
                json={"operation": "revoke_keycloak_session", "resource_id": session_a},
            )
            check(
                "(a) real POST /api/step-up/ticket returns 201 with a real ticketId",
                ticket_resp.status_code == 201 and "ticketId" in ticket_resp.json(),
            )
            ticket_id_a = ticket_resp.json()["ticketId"]

            revoke_resp_a = await client.post(
                f"/api/detections/{detection_id}/contain/revoke-session",
                json={
                    "userId": str(ANALYST_USER_ID),
                    "sessionId": session_a,
                    "approvalTicketId": ticket_id_a,
                },
            )
            check("(a) real revoke route returns 200", revoke_resp_a.status_code == 200)
            body_a = revoke_resp_a.json()
            check("(a) real revoke succeeded=true", body_a["succeeded"] is True)
            check(
                "(a) real revoke output confirms revocation",
                body_a["stepResults"][0]["output"]
                == {"user_id": str(ANALYST_USER_ID), "session_id": session_a, "revoked": True},
            )

            sessions_after_a = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
            check(
                "(a) real session is GONE after the real revoke "
                "(independent fresh Admin API re-check)",
                not any(s["id"] == session_a for s in sessions_after_a),
            )

            # ---------------------------------------------------------
            # Scenario (b): the same call with NO ticket -- denied,
            # session confirmed still alive.
            # ---------------------------------------------------------
            log("=== Scenario (b): NO ticket -- denied, session confirmed still alive ===")
            _tok_b, session_b = real_login_get_session(
                "analyst", "DevAnalyst#2026", state="poc-ee1-scenario-b"
            )
            log(f"real analyst login (b) succeeded, sid={session_b}")

            revoke_resp_b = await client.post(
                f"/api/detections/{detection_id}/contain/revoke-session",
                json={"userId": str(ANALYST_USER_ID), "sessionId": session_b},  # no ticket
            )
            check("(b) real route returns 200 (audited denial, not a raised HTTP error)", revoke_resp_b.status_code == 200)
            body_b = revoke_resp_b.json()
            check("(b) real revoke succeeded=false", body_b["succeeded"] is False)
            check(
                "(b) real error names the denial",
                "denied" in (body_b["stepResults"][0]["error"] or "").lower(),
            )

            sessions_after_b = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
            check(
                "(b) real session STILL ALIVE after the denied attempt "
                "(independent fresh Admin API re-check)",
                any(s["id"] == session_b for s in sessions_after_b),
            )

            events_b = [e async for e in audit_repo.stream_by_org(kronos_dev_org_id)]
            types_b = [
                e.event_type for e in events_b if e.details.get("params", {}).get("session_id") == session_b
            ]
            check(
                "(b) real CONTAINMENT_ACTION_ATTEMPTED + _DENIED rows exist; no _EXECUTED row",
                AuditEventType.CONTAINMENT_ACTION_ATTEMPTED in types_b
                and AuditEventType.CONTAINMENT_ACTION_DENIED in types_b
                and AuditEventType.CONTAINMENT_ACTION_EXECUTED not in types_b,
            )

            # ---------------------------------------------------------
            # Scenario (c): cross-tenant -- a second real org's real
            # user/session, rejected even with a valid ticket.
            # ---------------------------------------------------------
            log("=== Scenario (c): cross-tenant -- rejected even WITH a valid ticket ===")
            run_suffix = uuid.uuid4().hex[:8]
            other_org_alias = f"kronos-poc-ee1-org-{run_suffix}"
            other_org_id = await raw_create_org(
                raw, admin_token, other_org_alias, f"PoC EE1 Org 2 {run_suffix}"
            )
            other_user_id = await raw_create_user(
                raw, admin_token, f"poc-ee1-user-{run_suffix}", "PocEe1User#2026"
            )
            await raw_add_org_member(raw, admin_token, other_org_id, other_user_id)
            log(f"real second org created: alias={other_org_alias} id={other_org_id} user={other_user_id}")

            _tok_c, session_c = real_login_get_session(
                f"poc-ee1-user-{run_suffix}", "PocEe1User#2026", state="poc-ee1-scenario-c"
            )
            log(f"real login for the second org's user succeeded, sid={session_c}")

            ticket_resp_c = await client.post(
                "/api/step-up/ticket",
                json={"operation": "revoke_keycloak_session", "resource_id": session_c},
            )
            check(
                "(c) real step-up ticket minted for the cross-org attempt (a VALID ticket)",
                ticket_resp_c.status_code == 201,
            )
            ticket_id_c = ticket_resp_c.json()["ticketId"]

            # tenant is STILL the original kronos-dev org-admin -- the
            # request names a user from a DIFFERENT org, with an
            # otherwise-valid ticket.
            revoke_resp_c = await client.post(
                f"/api/detections/{detection_id}/contain/revoke-session",
                json={
                    "userId": str(other_user_id),
                    "sessionId": session_c,
                    "approvalTicketId": ticket_id_c,
                },
            )
            check("(c) real route returns 200", revoke_resp_c.status_code == 200)
            body_c = revoke_resp_c.json()
            check("(c) real revoke succeeded=false despite a VALID ticket", body_c["succeeded"] is False)
            check(
                "(c) real error names the org-membership rejection",
                "organization" in (body_c["stepResults"][0]["error"] or "").lower(),
            )

            other_sessions_after = await raw_list_sessions(raw, admin_token, other_user_id)
            check(
                "(c) the second org's real session is STILL ALIVE "
                "(independent fresh Admin API re-check)",
                any(s["id"] == session_c for s in other_sessions_after),
            )

            events_c = [e async for e in audit_repo.stream_by_org(kronos_dev_org_id)]
            types_c = [
                e.event_type for e in events_c if e.details.get("params", {}).get("session_id") == session_c
            ]
            check(
                "(c) real CONTAINMENT_ACTION_FAILED row exists for the cross-org attempt "
                "(never _EXECUTED)",
                AuditEventType.CONTAINMENT_ACTION_FAILED in types_c
                and AuditEventType.CONTAINMENT_ACTION_EXECUTED not in types_c,
            )

            log("=== Cleanup: removing the temporary second org/user ===")
            await raw_delete_org(raw, admin_token, other_org_id)
            await raw_delete_user(raw, admin_token, other_user_id)
            log("cleanup complete")

            # ---------------------------------------------------------
            # Scenario (d): role-gating -- an ANALYST-only tenant gets a
            # real 403, not silently allowed through.
            # ---------------------------------------------------------
            log("=== Scenario (d): role-gating -- ANALYST-only tenant gets a real 403 ===")
            current_tenant = make_tenant(
                kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ANALYST_USER_ID, "analyst", Role.ANALYST
            )
            forbidden_resp = await client.post(
                f"/api/detections/{detection_id}/contain/revoke-session",
                json={"userId": str(ANALYST_USER_ID), "sessionId": "irrelevant-for-403"},
            )
            check(
                "(d) an ANALYST-only tenant gets a real 403 (never silently allowed through)",
                forbidden_resp.status_code == 403,
            )

            # Restore an authorized tenant and confirm a READ_ONLY tenant is
            # also rejected (defense in depth beyond the single ANALYST case).
            current_tenant = make_tenant(
                kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ANALYST_USER_ID, "analyst", Role.READ_ONLY
            )
            forbidden_resp_ro = await client.post(
                f"/api/detections/{detection_id}/contain/revoke-session",
                json={"userId": str(ANALYST_USER_ID), "sessionId": "irrelevant-for-403"},
            )
            check(
                "(d) a READ_ONLY tenant also gets a real 403",
                forbidden_resp_ro.status_code == 403,
            )

        await engine.dispose()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against the real HTTP route, real Keycloak 26.2.5, and real Postgres 16."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
