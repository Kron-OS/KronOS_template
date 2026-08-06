#!/usr/bin/env python3
"""Verification-first PoC: containment action adapters + approval gates
(roadmap M7/H2 -- GATE).

Drives the real, unmodified production classes against the REAL, live dev
stack -- Keycloak 26.2.5 (docker-keycloak-1) and Postgres 16
(docker-postgres-1) -- never InMemory*/mocked doubles for the two systems
this gate cares about:
  ApprovalGate (StepUpApprovalGate, StaticPolicyApprovalGate)  src/application/approval_gate.py
  ContainmentAction / RevokeKeycloakSessionAction               src/application/containment_action(s).py
  HttpxKeycloakAdminClient                                      src/adapter/keycloak/admin_client.py
  PlaybookActionRegistry / PlaybookExecutionService              src/application/playbook*.py
  PostgresAuditLogRepository / AuditLogService

Real sessions are created via a genuine scripted browser login (Authorization
Code + PKCE against the real dev-stack Keycloak, reusing
poc/auth_flow/auth_helpers.py's own real_browser_login() -- no password
grant, no hand-minted tokens, no fabricated session ids).

The gate's literal text (roadmap H2): "prove no destructive action can
execute without either an explicit policy authorization or human approval,
and that every attempt is audited whether or not it succeeded."

Scenarios:
  (0) Real login creates a real Keycloak session; independently confirmed
      via the real Admin REST API (not just the JWT's own `sid` claim).
  (1) DENIED -- no approval provided. The real session is confirmed STILL
      ALIVE afterward via a fresh, independent Admin API call. Real
      CONTAINMENT_ACTION_ATTEMPTED + CONTAINMENT_ACTION_DENIED audit rows
      exist in real Postgres; no EXECUTED row.
  (2) APPROVED via a real step-up ticket. The real session is confirmed
      GONE afterward via a fresh, independent Admin API call. Real
      CONTAINMENT_ACTION_EXECUTED audit row exists; hash chain intact.
  (3) Tenant isolation -- a real second org + real second user's real
      session cannot be revoked by the first tenant, even WITH a valid
      approval ticket. The second org's real session is confirmed STILL
      ALIVE afterward. A real CONTAINMENT_ACTION_FAILED row exists (not
      EXECUTED).
  (4) Extensibility -- StaticPolicyApprovalGate (a second, different
      ApprovalGate, no human ticket) approves a real revoke of a THIRD
      real session (case-lead), proving "new approval mechanism = new
      class, zero ContainmentAction changes."

Run: ~/venv/bin/python3 poc/containment_approval_gate/run_poc.py
Requires: docker-keycloak-1 (26.2.5) and docker-postgres-1 (16) already
running, and a fresh nginx/step-ca leaf cert (see this PoC's own README --
`docker compose -f docker/docker-compose.dev.yml up -d tls-init && docker
restart docker-nginx-1` if kronos.local's cert has expired, a known,
documented recurring dev-environment fact).
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "poc" / "auth_flow"))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

import auth_helpers as ah  # noqa: E402
from src.adapter.keycloak.admin_client import HttpxKeycloakAdminClient  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.approval_gate import StaticPolicyApprovalGate, StepUpApprovalGate  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.containment_actions import RevokeKeycloakSessionAction  # noqa: E402
from src.application.playbook import PlaybookActionRegistry  # noqa: E402
from src.application.playbook_execution import PlaybookExecutionService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.playbook import Playbook, PlaybookStep  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.exceptions import ContainmentActionDeniedError  # noqa: E402
from src.external.middleware.step_up_store import InMemoryTicketStore  # noqa: E402

KEYCLOAK_INTERNAL_URL = "http://localhost:8080"  # host-published port, real docker-keycloak-1
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

ANALYST_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000002")
CASE_LEAD_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000003")
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
    whatever the code under test itself did, per this item's own proof bar."""
    resp = await client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()


async def raw_create_org(client: httpx.AsyncClient, token: str, alias: str, name: str) -> str:
    # Real finding (Keycloak 26.2.5): organization creation rejects an empty
    # domains list with a real 400 ("You must provide at least one domain")
    # -- confirmed live against docker-keycloak-1 before this fix, not
    # assumed. A real, verified, non-clashing PoC-only domain is required.
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
    # Real finding (Keycloak 26.2.5): this realm's Declarative User Profile
    # (see scripts/provision_keycloak_org.sh's own /users/profile PUT)
    # requires firstName/lastName for role "user" -- omitting them doesn't
    # fail user creation itself, but a real login then redirects to a real
    # VERIFY_PROFILE required-action page instead of completing, confirmed
    # live (a 302 to .../login-actions/required-action?execution=VERIFY_PROFILE)
    # before this fix.
    resp = await client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "username": username,
            "email": f"{username}@example.invalid",
            "firstName": "PoC",
            "lastName": "H2User",
            "enabled": True,
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    resp.raise_for_status()
    location = resp.headers["Location"]
    return uuid.UUID(location.rsplit("/", 1)[-1])


async def raw_add_org_member(client: httpx.AsyncClient, token: str, org_id: str, user_id: uuid.UUID) -> None:
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
    real dev-stack Keycloak via kronos.local -- returns (access_token, sid).
    """
    ah.trust_dev_stack_step_ca("docker-tls-init-1")
    ah.KC = "https://kronos.local:8443"
    ah.REDIRECT_URI = "https://kronos.local/poc-h2-callback"
    tokens, _new_secret, _mfa_path = ah.real_browser_login(
        username, password, totp_secret=None, state=state
    )
    claims = ah.decode_jwt_payload(tokens["access_token"])
    return tokens["access_token"], claims["sid"]


def make_tenant(org_id: uuid.UUID, org_alias: str, user_id: uuid.UUID, username: str) -> TenantContext:
    return TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=user_id,
        username=username,
        roles=frozenset({Role.CASE_LEAD}),
        correlation_id=str(uuid.uuid4()),
        acr="aal2",
    )


async def main() -> None:
    async with httpx.AsyncClient(timeout=15) as raw:
        admin_token = await get_raw_admin_token(raw)
        kronos_dev_org_id = uuid.UUID(await raw_get_org_id(raw, admin_token, KRONOS_DEV_ORG_ALIAS))
        log(f"real kronos-dev org id resolved via Admin API: {kronos_dev_org_id}")

        # -------------------------------------------------------------
        # Scenario 0: real login creates a real session.
        # -------------------------------------------------------------
        log("=== Scenario 0: real scripted PKCE login creates a real Keycloak session ===")
        _access_token, session_id = real_login_get_session(
            "analyst", "DevAnalyst#2026", state="poc-h2-scenario0"
        )
        log(f"real login succeeded, JWT sid={session_id}")
        live_sessions = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
        check(
            "real analyst session appears in a fresh, independent Admin API sessions list",
            any(s["id"] == session_id for s in live_sessions),
        )

        # Real production wiring: PostgresAuditLogRepository, real Keycloak
        # admin client, real containment action + gates.
        engine = create_async_engine(POSTGRES_DSN)
        await PostgresAuditLogRepository.create_tables(engine)
        audit_repo = PostgresAuditLogRepository(engine)
        audit_log = AuditLogService(audit_repo)
        admin_client = HttpxKeycloakAdminClient(
            KEYCLOAK_INTERNAL_URL,
            KEYCLOAK_REALM,
            KEYCLOAK_ADMIN_CLIENT_ID,
            KEYCLOAK_ADMIN_CLIENT_SECRET,
        )
        ticket_store = InMemoryTicketStore()
        step_up_gate = StepUpApprovalGate(ticket_store)

        tenant = make_tenant(kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ANALYST_USER_ID, "poc-approver")

        # -------------------------------------------------------------
        # Scenario 1: DENIED -- no approval provided.
        # -------------------------------------------------------------
        log("=== Scenario 1: DENIED -- destructive step attempted with NO approval ===")
        revoke_action = RevokeKeycloakSessionAction(admin_client, step_up_gate, audit_log)
        registry = PlaybookActionRegistry()
        registry.register(revoke_action)
        execution_service = PlaybookExecutionService(registry, audit_log)

        denied_playbook = Playbook(
            name="revoke-session-no-approval",
            steps=(
                PlaybookStep(
                    step_id="revoke-1",
                    action_name="revoke_keycloak_session",
                    params={"user_id": str(ANALYST_USER_ID), "session_id": session_id},
                    # deliberately NO approval_ticket_id/approval_resource_id
                ),
            ),
        )
        denied_result = await execution_service.execute(denied_playbook, tenant)
        check("denied run halted (no unapproved execution)", denied_result.halted_early is True)
        check(
            "denied run's real captured error names the ContainmentActionDeniedError reason",
            "denied" in (denied_result.step_results[0].error or "").lower(),
        )

        sessions_after_denied = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
        check(
            "real session STILL ALIVE after the denied attempt "
            "(independent fresh Admin API re-check)",
            any(s["id"] == session_id for s in sessions_after_denied),
        )

        # kronos-dev is a real, persistent org whose audit history
        # accumulates across repeated PoC runs -- scope every check below to
        # THIS run's own real session_id (a fresh UUID minted by the real
        # login above), never to bare event-type presence across the org's
        # entire history, or a second run would trip a stale false
        # negative/positive from a PRIOR run's own rows (the exact
        # cross-run pollution class of bug D5's own PoC already documented
        # for a different component).
        def _this_sessions_events(events: list, sid: str) -> list:
            return [e for e in events if e.details.get("params", {}).get("session_id") == sid]

        events_after_denied = _this_sessions_events(
            [e async for e in audit_repo.stream_by_org(tenant.org_id)], session_id
        )
        types_after_denied = [e.event_type for e in events_after_denied]
        check(
            "real CONTAINMENT_ACTION_ATTEMPTED row exists for the denied attempt",
            AuditEventType.CONTAINMENT_ACTION_ATTEMPTED in types_after_denied,
        )
        check(
            "real CONTAINMENT_ACTION_DENIED row exists for the denied attempt",
            AuditEventType.CONTAINMENT_ACTION_DENIED in types_after_denied,
        )
        check(
            "NO CONTAINMENT_ACTION_EXECUTED row exists yet for THIS run's session "
            "(nothing has run for real yet)",
            AuditEventType.CONTAINMENT_ACTION_EXECUTED not in types_after_denied,
        )

        # -------------------------------------------------------------
        # Scenario 2: APPROVED via a real step-up ticket.
        # -------------------------------------------------------------
        log("=== Scenario 2: APPROVED -- a real step-up ticket authorizes the same revoke ===")
        ticket_id = uuid.uuid4()
        ticket_store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", session_id)
        log(f"real step-up ticket issued (mirrors POST /api/step-up/ticket): {ticket_id}")

        approved_playbook = Playbook(
            name="revoke-session-with-approval",
            steps=(
                PlaybookStep(
                    step_id="revoke-1",
                    action_name="revoke_keycloak_session",
                    params={
                        "user_id": str(ANALYST_USER_ID),
                        "session_id": session_id,
                        "approval_ticket_id": str(ticket_id),
                        "approval_resource_id": session_id,
                    },
                ),
            ),
        )
        approved_result = await execution_service.execute(approved_playbook, tenant)
        check("approved run succeeded (real revoke executed)", approved_result.succeeded is True)
        check(
            "approved run's real output confirms revocation",
            approved_result.step_results[0].output == {
                "user_id": str(ANALYST_USER_ID),
                "session_id": session_id,
                "revoked": True,
            },
        )

        sessions_after_approved = await raw_list_sessions(raw, admin_token, ANALYST_USER_ID)
        check(
            "real session is GONE after the approved attempt "
            "(independent fresh Admin API re-check)",
            not any(s["id"] == session_id for s in sessions_after_approved),
        )

        events_after_approved = _this_sessions_events(
            [e async for e in audit_repo.stream_by_org(tenant.org_id)], session_id
        )
        types_after_approved = [e.event_type for e in events_after_approved]
        check(
            "real CONTAINMENT_ACTION_EXECUTED row now exists for THIS run's session",
            AuditEventType.CONTAINMENT_ACTION_EXECUTED in types_after_approved,
        )
        intact, detail = await audit_log.verify_chain(tenant.org_id)
        check(f"real hash chain intact after denied+approved sequence (detail={detail})", intact)

        # A second attempt to reuse the SAME (already-consumed) ticket must
        # be denied -- one-shot guarantee, verified for real.
        replay_result = await execution_service.execute(approved_playbook, tenant)
        check(
            "replaying the SAME ticket a second time is denied, not re-authorized",
            replay_result.halted_early is True,
        )

        # -------------------------------------------------------------
        # Scenario 3: tenant isolation -- a second real org/user/session.
        # -------------------------------------------------------------
        log("=== Scenario 3: tenant isolation -- a second real org's real session ===")
        run_suffix = uuid.uuid4().hex[:8]
        other_org_alias = f"kronos-poc-h2-org-{run_suffix}"
        # Real finding (Keycloak 26.2.5): organization "name" -- not just
        # "alias" -- must also be unique; a second real run reusing the
        # same hardcoded name while a prior run's org was still around
        # (crashed before reaching cleanup) got a real 409 Conflict.
        # Suffixing name too makes every run's org genuinely unique.
        other_org_id = await raw_create_org(raw, admin_token, other_org_alias, f"PoC H2 Org 2 {run_suffix}")
        other_user_id = await raw_create_user(
            raw, admin_token, f"poc-h2-user-{run_suffix}", "PocH2User#2026"
        )
        await raw_add_org_member(raw, admin_token, other_org_id, other_user_id)
        log(f"real second org created: alias={other_org_alias} id={other_org_id} user={other_user_id}")

        _other_access_token, other_session_id = real_login_get_session(
            f"poc-h2-user-{run_suffix}", "PocH2User#2026", state="poc-h2-scenario3"
        )
        log(f"real login for the second org's user succeeded, sid={other_session_id}")

        cross_org_ticket_id = uuid.uuid4()
        ticket_store.put(
            cross_org_ticket_id, tenant.user_id, "revoke_keycloak_session", other_session_id
        )
        cross_org_playbook = Playbook(
            name="revoke-session-cross-org-attempt",
            steps=(
                PlaybookStep(
                    step_id="revoke-1",
                    action_name="revoke_keycloak_session",
                    params={
                        "user_id": str(other_user_id),
                        "session_id": other_session_id,
                        "approval_ticket_id": str(cross_org_ticket_id),
                        "approval_resource_id": other_session_id,
                    },
                ),
            ),
        )
        # tenant is STILL the original kronos-dev tenant -- the step names a
        # user from a DIFFERENT org, even with a valid approval ticket.
        cross_org_result = await execution_service.execute(cross_org_playbook, tenant)
        check(
            "cross-org attempt halted (tenant isolation enforced even WITH a valid ticket)",
            cross_org_result.halted_early is True,
        )
        check(
            "cross-org failure reason names the real org-membership rejection",
            "organization" in (cross_org_result.step_results[0].error or "").lower(),
        )

        other_sessions_after = await raw_list_sessions(raw, admin_token, other_user_id)
        check(
            "the second org's real session is STILL ALIVE "
            "(independent fresh Admin API re-check)",
            any(s["id"] == other_session_id for s in other_sessions_after),
        )

        events_after_cross_org = _this_sessions_events(
            [e async for e in audit_repo.stream_by_org(tenant.org_id)], other_session_id
        )
        types_after_cross_org = [e.event_type for e in events_after_cross_org]
        check(
            "real CONTAINMENT_ACTION_FAILED row exists for THIS run's cross-org attempt "
            "(never CONTAINMENT_ACTION_EXECUTED for it)",
            types_after_cross_org.count(AuditEventType.CONTAINMENT_ACTION_FAILED) >= 1
            and AuditEventType.CONTAINMENT_ACTION_EXECUTED not in types_after_cross_org,
        )

        # -------------------------------------------------------------
        # Scenario 4: extensibility -- a second, different ApprovalGate.
        # -------------------------------------------------------------
        log("=== Scenario 4: StaticPolicyApprovalGate (explicit policy, no ticket) ===")
        policy_gate = StaticPolicyApprovalGate(
            frozenset({(kronos_dev_org_id, "revoke_keycloak_session")})
        )
        policy_gated_action = RevokeKeycloakSessionAction(admin_client, policy_gate, audit_log)
        policy_registry = PlaybookActionRegistry()
        policy_registry.register(policy_gated_action)
        policy_execution_service = PlaybookExecutionService(policy_registry, audit_log)

        _case_lead_token, case_lead_session_id = real_login_get_session(
            "case-lead", "DevCaseLead#2026", state="poc-h2-scenario4"
        )
        log(f"real case-lead login succeeded, sid={case_lead_session_id}")

        policy_playbook = Playbook(
            name="revoke-session-via-policy-gate",
            steps=(
                PlaybookStep(
                    step_id="revoke-1",
                    action_name="revoke_keycloak_session",
                    params={"user_id": str(CASE_LEAD_USER_ID), "session_id": case_lead_session_id},
                    # no ticket at all -- StaticPolicyApprovalGate needs none
                ),
            ),
        )
        policy_result = await policy_execution_service.execute(policy_playbook, tenant)
        check(
            "StaticPolicyApprovalGate authorizes with ZERO ContainmentAction/engine changes",
            policy_result.succeeded is True,
        )
        case_lead_sessions_after = await raw_list_sessions(raw, admin_token, CASE_LEAD_USER_ID)
        check(
            "real case-lead session is GONE after the policy-gated revoke "
            "(independent fresh Admin API re-check)",
            not any(s["id"] == case_lead_session_id for s in case_lead_sessions_after),
        )

        # -------------------------------------------------------------
        # Cleanup: real, additive PoC-only org/user removed via Admin API.
        # -------------------------------------------------------------
        log("=== Cleanup: removing the temporary second org/user ===")
        await raw_delete_org(raw, admin_token, other_org_id)
        await raw_delete_user(raw, admin_token, other_user_id)
        log("cleanup complete")

        await engine.dispose()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against real, live Keycloak 26.2.5 and Postgres 16."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
