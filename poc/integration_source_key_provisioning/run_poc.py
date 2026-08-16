#!/usr/bin/env python3
"""Verification-first PoC: real Alembic migration -> real admin provision
route -> real inbound push using the returned key -> real revoke -> real
rejection (Milestone W8, Gap Audit P1-7, docs/ASSESSMENT_SYNTHESIS_2026-08.md).

Proves the whole point of this milestone: an operator can provision a real,
per-(org, source) API key for POST /api/integrations/push/{source_type}
through a real admin route, and that key works on the real push route
immediately -- no backend restart -- because both routes now read from the
same live, Postgres-backed IntegrationSourceKeyRepository instead of a
boot-time-only static dict.

Pinned versions (read from this repo, not assumed):
  - Postgres: real running docker-postgres-1 (postgres:16-alpine, per
    docker/docker-compose.dev.yml).
  - alembic==1.19.1, sqlalchemy==2.0.51, asyncpg==0.31.0 (installed in
    /home/reca/venv, matching pyproject.toml's >=1.13/>=2.0/>=0.29 pins).

Exercises the real, unmodified classes:
  migrations/versions/..._add_integration_source_keys_table.py (real Alembic
    revision, applied via a real `alembic upgrade head` subprocess call)
  src/adapter/repository/postgres_integration_source_key.py
    -- PostgresIntegrationSourceKeyRepository
  src/external/routes/admin_integration_sources.py -- provision/list/revoke
  src/external/middleware/integration_source_auth.py
    -- StaticApiKeyInboundAuthenticator (repository-backed)
  src/external/routes/integration_source_push.py -- push_webhook (untouched
    beyond the authenticator constructor signature change)

Uses httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) throughout
(not TestClient) -- TestClient's own threaded portal runs the ASGI app on a
separate anyio worker-thread event loop, incompatible with the async
SQLAlchemy engine created on THIS coroutine's own loop (same real,
previously-confirmed "Future attached to a different loop" failure the
Milestone W3 PoC (poc/kronos_attest_export/run_poc.py) documented; this
script follows that exact working pattern).
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

PASS = "\033[32m[PASS]\033[0m"
FAIL = "\033[31m[FAIL]\033[0m"
failures = 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global failures
    if cond:
        print(f"{PASS} {label} {detail}")
    else:
        print(f"{FAIL} {label} {detail}")
        failures += 1


def run_alembic(*args: str) -> subprocess.CompletedProcess[str]:
    import os

    env = dict(os.environ)
    env["DATABASE_URL"] = DATABASE_URL
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
    )


async def main_async() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
    from src.adapter.repository.postgres_integration_source_key import (
        PostgresIntegrationSourceKeyRepository,
    )
    from src.application.audit_log import AuditLogService
    from src.domain.audit import AuditEventType
    from src.domain.user import Role, TenantContext
    from src.external.dependencies import (
        get_audit_log_service,
        get_inbound_source_authenticator,
        get_integration_source_key_repository,
        get_step_up_auth,
        get_tenant_context,
    )
    from src.external.fastapi_app import create_app
    from src.external.middleware.integration_source_auth import StaticApiKeyInboundAuthenticator
    from src.external.middleware.step_up_auth import StepUpAuth

    print("=" * 78)
    print("1. Real Alembic migration against the real dev-stack Postgres")
    print("=" * 78)

    result = run_alembic("current")
    print(f"`alembic current` (before) -> exit={result.returncode}\n{result.stdout}{result.stderr}")

    result = run_alembic("upgrade", "head")
    print(f"`alembic upgrade head` -> exit={result.returncode}\n{result.stdout}{result.stderr}")
    check("real `alembic upgrade head` exits 0 against docker-postgres-1", result.returncode == 0)

    result = run_alembic("current")
    print(f"`alembic current` (after) -> exit={result.returncode}\n{result.stdout}{result.stderr}")
    check(
        "database is now stamped at the integration_source_keys revision",
        "913567ca653a" in result.stdout or "913567ca653a" in result.stderr,
        result.stdout.strip() + result.stderr.strip(),
    )

    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    try:
        print("\n" + "=" * 78)
        print("2. Real PostgresIntegrationSourceKeyRepository + PostgresAuditLogRepository")
        print("=" * 78)

        await PostgresIntegrationSourceKeyRepository.create_tables(engine)
        key_repo = PostgresIntegrationSourceKeyRepository(engine)
        await PostgresAuditLogRepository.create_tables(engine)
        audit_repo = PostgresAuditLogRepository(engine)
        audit_svc = AuditLogService(audit_repo)
        check("repository + audit-log wiring constructed against real engine", True)

        org_id = uuid.uuid4()
        user_id = uuid.uuid4()
        source_id = "poc-wazuh-1"
        source_type = "generic-webhook"  # real, registered stand-in PUSH source (roadmap Q1)

        def _admin_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="poc-w8-org",
                user_id=user_id,
                username="poc-admin",
                roles=frozenset({Role.ORG_ADMIN}),
                correlation_id=str(uuid.uuid4()),
                acr="aal2",
            )

        step_up = StepUpAuth()

        app = create_app()
        app.dependency_overrides[get_tenant_context] = _admin_tenant
        app.dependency_overrides[get_integration_source_key_repository] = lambda: key_repo
        app.dependency_overrides[get_audit_log_service] = lambda: audit_svc
        app.dependency_overrides[get_step_up_auth] = lambda: step_up
        # The push route's authenticator must wrap the SAME real repository
        # instance the admin route just provisioned into -- proving both
        # routes share one live, per-request-queried store (not a
        # boot-time snapshot each route captured independently).
        app.dependency_overrides[get_inbound_source_authenticator] = (
            lambda: StaticApiKeyInboundAuthenticator(key_repo)
        )

        import httpx

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://poc"
        ) as client:
            print("\n" + "=" * 78)
            print("3. Real HTTP: POST /api/admin/integration-sources/{source_type}/provision")
            print("=" * 78)

            ticket_id = step_up.issue_ticket(
                user_id=user_id,
                operation="integration_source_key.provision",
                resource_id=f"{source_type}:{source_id}",
            )
            provision_resp = await client.post(
                f"/api/admin/integration-sources/{source_type}/provision",
                json={"sourceId": source_id},
                headers={"X-Step-Up-Ticket": str(ticket_id)},
            )
            print(f"provision -> status={provision_resp.status_code}\n{provision_resp.text}")
            check("provision route returns 201", provision_resp.status_code == 201)

            provision_body = provision_resp.json()
            real_api_key = provision_body["apiKey"]
            check("response includes a real, non-empty plaintext apiKey", bool(real_api_key))
            check("sourceId echoed correctly", provision_body["sourceId"] == source_id)
            check("sourceType echoed correctly", provision_body["sourceType"] == source_type)

            print("\n" + "=" * 78)
            print("4. Real HTTP: GET /api/admin/integration-sources (list, no plaintext)")
            print("=" * 78)
            list_resp = await client.get("/api/admin/integration-sources")
            print(f"list -> status={list_resp.status_code}\n{list_resp.text}")
            check("list route returns 200", list_resp.status_code == 200)
            list_body = list_resp.json()
            check("list contains exactly the 1 real provisioned key", list_body["total"] == 1)
            check(
                "list item never contains the plaintext key",
                "apiKey" not in list_body["items"][0],
            )

            print("\n" + "=" * 78)
            print("5. Real HTTP: POST /api/integrations/push/{source_type} using the REAL key")
            print("=" * 78)
            push_resp = await client.post(
                f"/api/integrations/push/{source_type}",
                content=b'{"message": "real poc event from W8"}',
                headers={
                    "Content-Type": "application/json",
                    "X-KronOS-Source-Key": real_api_key,
                },
            )
            print(f"push (with real key) -> status={push_resp.status_code}\n{push_resp.text}")
            check(
                "push accepted (202) using the real key returned by provision",
                push_resp.status_code == 202,
            )
            if push_resp.status_code == 202:
                outcome = push_resp.json()["results"][0]
                check("push outcome accepted=True", outcome["accepted"] is True)

            print("\n" + "=" * 78)
            print("6. Real HTTP: DELETE /api/admin/integration-sources/{source_type}/{source_id}")
            print("=" * 78)
            revoke_ticket_id = step_up.issue_ticket(
                user_id=user_id,
                operation="integration_source_key.revoke",
                resource_id=f"{source_type}:{source_id}",
            )
            revoke_resp = await client.delete(
                f"/api/admin/integration-sources/{source_type}/{source_id}",
                headers={"X-Step-Up-Ticket": str(revoke_ticket_id)},
            )
            print(f"revoke -> status={revoke_resp.status_code}")
            check("revoke route returns 204", revoke_resp.status_code == 204)

            print("\n" + "=" * 78)
            print("7. Real HTTP: same push, same real key, AFTER revocation -- must be rejected")
            print("=" * 78)
            rejected_resp = await client.post(
                f"/api/integrations/push/{source_type}",
                content=b'{"message": "should be rejected"}',
                headers={
                    "Content-Type": "application/json",
                    "X-KronOS-Source-Key": real_api_key,
                },
            )
            print(f"push (revoked key) -> status={rejected_resp.status_code}\n{rejected_resp.text}")
            check(
                "push REJECTED (401) using the same key after revocation",
                rejected_resp.status_code == 401,
            )

            print("\n" + "=" * 78)
            print("8. Real audit events (INTEGRATION_SOURCE_KEY_PROVISIONED / _REVOKED)")
            print("=" * 78)
            provisioned_events = [
                e
                async for e in audit_repo.stream_by_org(org_id)
                if e.event_type == AuditEventType.INTEGRATION_SOURCE_KEY_PROVISIONED
            ]
            revoked_events = [
                e
                async for e in audit_repo.stream_by_org(org_id)
                if e.event_type == AuditEventType.INTEGRATION_SOURCE_KEY_REVOKED
            ]
            check("exactly 1 real KEY_PROVISIONED audit event persisted", len(provisioned_events) == 1)
            check("exactly 1 real KEY_REVOKED audit event persisted", len(revoked_events) == 1)
            if provisioned_events:
                details_str = str(provisioned_events[0].details)
                check(
                    "provisioned audit event never contains the plaintext key",
                    real_api_key not in details_str,
                )

        print("\n" + "=" * 78)
        print(f"{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
        print("=" * 78)
    finally:
        await engine.dispose()

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main_async())
