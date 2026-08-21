#!/usr/bin/env python3
"""Verification-first PoC: does a step-up ticket minted for resource A
actually authorize a destructive action against resource B?

Adversarial red-team review (scoped to milestones landed since the last
full assessment), checking the exact question the review brief poses about
``StepUpApprovalGate``: "can a ticket minted for one action/resource be
replayed against a different one?"

**Gap Audit Milestone JJ update**: this PoC originally proved the attack
SUCCEEDED (a ticket minted "for" session X, via a caller-supplied
``approvalResourceId`` field, authorized revoking a completely different
session Y). That gap is now fixed: ``ApprovalGate.authorize()`` takes an
explicit, server-computed ``resource_id`` argument
(``RevokeKeycloakSessionAction._resource_id()`` derives it from the REAL
``session_id`` being acted on); the caller-supplied ``approvalResourceId``
field has been removed from ``RevokeKeycloakSessionIn`` entirely. This run
re-executes the exact same attack request shape against the FIXED code and
asserts it is now denied -- session Y must survive, session X's ticket must
remain unconsumed for a legitimate follow-up.

Mirrors poc/revoke_session_route/run_poc.py's own established pattern
exactly (same real dependencies, same in-process ASGITransport idiom, same
real Keycloak 26.2.5 / Postgres 16 dev stack) -- only the scenario differs.

Run: ~/venv/bin/python3 poc/stepup_ticket_resource_mismatch/run_poc.py
Requires: docker-keycloak-1 (26.2.5), docker-postgres-1 (16) already
running (confirmed via `docker ps` immediately before this run).
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

KEYCLOAK_INTERNAL_URL = "http://localhost:8080"
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

ANALYST_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000002")  # realm role: analyst
KRONOS_DEV_ORG_ALIAS = "kronos-dev"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


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
    resp = await client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()


def real_login_get_session(username: str, password: str, state: str) -> tuple[str, str]:
    ah.trust_dev_stack_step_ca("docker-tls-init-1")
    ah.KC = "https://kronos.local:8443"
    ah.REDIRECT_URI = "https://kronos.local/poc-mismatch-callback"
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

        with patch("src.config.Settings", return_value=_fake_keycloak_settings()):
            deps.configure_keycloak_admin_client_from_settings()
        admin_client = deps.get_keycloak_admin_client()
        check("get_keycloak_admin_client() returns a real client", admin_client is not None)

        engine = create_async_engine(POSTGRES_DSN)
        await PostgresAuditLogRepository.create_tables(engine)
        audit_repo = PostgresAuditLogRepository(engine)
        audit_log = AuditLogService(audit_repo)

        ticket_store = InMemoryTicketStore()
        deps.configure_step_up_auth(ticket_store)

        detection_repo = InMemoryDetectionRepository()
        triage_service = DetectionTriageService(detection_repo, audit_log)
        registry = deps.get_playbook_action_registry(detection_repo, triage_service, audit_log)
        execution_service = deps.get_playbook_execution_service(registry, audit_log)

        app = create_app(step_up_ticket_store=ticket_store)
        app.dependency_overrides[deps.get_playbook_action_registry] = lambda: registry
        app.dependency_overrides[deps.get_playbook_execution_service] = lambda: execution_service

        current_tenant: TenantContext = make_tenant(
            kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ANALYST_USER_ID, "admin", Role.ORG_ADMIN
        )
        app.dependency_overrides[get_tenant_context] = lambda: current_tenant

        detection_id = uuid.uuid4()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://poc-mismatch"
        ) as client:
            log("=== Setup: two real, independent, live sessions for the same user ===")
            _tok_x, session_x = real_login_get_session(
                "analyst", "DevAnalyst#2026", state="poc-mismatch-session-x"
            )
            log(f"real login #1 (session X, the one a ticket will be minted 'for') sid={session_x}")
            _tok_y, session_y = real_login_get_session(
                "analyst", "DevAnalyst#2026", state="poc-mismatch-session-y"
            )
            log(f"real login #2 (session Y, the ACTUAL target of the attack) sid={session_y}")

            sessions_before = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
            check(
                "both real sessions X and Y are alive before any route call",
                any(s["id"] == session_x for s in sessions_before)
                and any(s["id"] == session_y for s in sessions_before),
            )

            log("=== Step 1: mint a real step-up ticket nominally 'for' session X ===")
            ticket_resp = await client.post(
                "/api/step-up/ticket",
                json={"operation": "revoke_keycloak_session", "resource_id": session_x},
            )
            check(
                "real POST /api/step-up/ticket returns 201 (ticket minted for session X)",
                ticket_resp.status_code == 201,
            )
            ticket_id = ticket_resp.json()["ticketId"]

            log(
                "=== Step 2: THE (NOW-FIXED) ATTACK -- attempt to use the ticket minted "
                "for session X to revoke session Y instead, by sending sessionId=session_y "
                "(the real target) with the ticket that was only ever minted for session_x. "
                "The vulnerable 'approvalResourceId' field no longer exists on the request "
                "model at all -- resource_id is now derived server-side from sessionId ==="
            )
            attack_resp = await client.post(
                f"/api/detections/{detection_id}/contain/revoke-session",
                json={
                    "userId": str(ANALYST_USER_ID),
                    "sessionId": session_y,  # the REAL target, different from the ticket's resource
                    "approvalTicketId": ticket_id,
                },
            )
            check("attack route call returns 200 (an audited denial, not an HTTP error)", attack_resp.status_code == 200)
            attack_body = attack_resp.json()
            check(
                "*** FIX VERIFIED *** the ticket minted 'for' session X is now REJECTED "
                "when the real target is session Y -- succeeded=false",
                attack_body["succeeded"] is False,
            )
            check(
                "*** FIX VERIFIED *** the denial names the approval gate, not a backend error",
                "denied" in (attack_body["stepResults"][0]["error"] or "").lower(),
            )

            sessions_after = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
            check(
                "*** FIX VERIFIED *** independent Admin API re-check: session Y is STILL "
                "ALIVE -- the mismatched ticket did not revoke it",
                any(s["id"] == session_y for s in sessions_after),
            )
            check(
                "session X (the ticket's real, matching resource) was also never revoked "
                "by this denied attempt -- still alive",
                any(s["id"] == session_x for s in sessions_after),
            )

            events = [e async for e in audit_repo.stream_by_org(kronos_dev_org_id)]
            matching_executed = [
                e
                for e in events
                if e.details.get("params", {}).get("session_id") == session_y
                and e.event_type == AuditEventType.CONTAINMENT_ACTION_EXECUTED
            ]
            check(
                "no CONTAINMENT_ACTION_EXECUTED audit row exists for session_y -- the "
                "mismatched attempt never reached the real Keycloak revoke call",
                len(matching_executed) == 0,
            )
            matching_denied = [
                e
                for e in events
                if e.details.get("params", {}).get("session_id") == session_y
                and e.event_type == AuditEventType.CONTAINMENT_ACTION_DENIED
            ]
            check(
                "a real CONTAINMENT_ACTION_DENIED audit row exists for session_y, proving "
                "the mismatch was recorded as a denial, not silently dropped",
                len(matching_denied) == 1,
            )

            log(
                "=== Step 3: the ticket must remain unconsumed by the denied mismatch -- "
                "a legitimate follow-up request against its REAL resource (session X) "
                "must still succeed ==="
            )
            legit_resp = await client.post(
                f"/api/detections/{detection_id}/contain/revoke-session",
                json={
                    "userId": str(ANALYST_USER_ID),
                    "sessionId": session_x,
                    "approvalTicketId": ticket_id,
                },
            )
            check("legitimate follow-up route call returns 200", legit_resp.status_code == 200)
            legit_body = legit_resp.json()
            check(
                "*** FIX VERIFIED *** the same ticket, used against its REAL resource "
                "(session X), still succeeds -- the fix denies mismatches without "
                "breaking the legitimate same-resource flow",
                legit_body["succeeded"] is True,
            )

            sessions_final = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
            check(
                "independent Admin API re-check: session X is now GONE (legitimately "
                "revoked), session Y is still alive",
                not any(s["id"] == session_x for s in sessions_final)
                and any(s["id"] == session_y for s in sessions_final),
            )

            log("=== Cleanup: session Y is still alive; nothing else to clean up ===")

        await engine.dispose()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} (in the sense that all assertions "
        f"about the FINDING held) -- {passed}/{total} checks passed against the real HTTP "
        f"route, real Keycloak 26.2.5, and real Postgres 16."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
