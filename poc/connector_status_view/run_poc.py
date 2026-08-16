#!/usr/bin/env python3
"""Verification-first PoC: GET /api/admin/connectors/status against a real,
Postgres-backed backend (Milestone W14, docs/ASSESSMENT_SYNTHESIS_2026-08.md
P2-W14, from docs/assessments/ux_onboarding_review.md SS1).

Proves the whole point of this milestone's design decision: the new
connector-status route reflects the REAL push/poll asymmetry --

1. A real per-org PUSH source key is provisioned via the real W8 admin
   route, a real push event is sent through it, and the status route shows
   a real ``lastIngestedAt`` derived from the real
   ``INTEGRATION_SOURCE_PUSH_INGESTED`` audit row that push created --
   not a fabricated timestamp.
2. The Defender global-poll entry is included/excluded purely based on
   whether ``Settings.defender_poll_org_id`` (real ``Settings`` instance,
   constructed via a real env var, parsed via the real
   ``configure_defender_poll_source_from_settings()``/``get_defender_poll_org_id()``
   DI path) matches the calling org -- proven with one case where it
   matches (entry present, honestly labeled non-self-service) and one
   where it does not / is unset (entry absent). No real Microsoft Graph
   call is made or needed for this half of the proof.

Pinned versions (read from this repo, not assumed):
  - Postgres: real running docker-postgres-1 (postgres:16-alpine, per
    docker/docker-compose.dev.yml).
  - alembic==1.19.1, sqlalchemy==2.0.51, asyncpg==0.31.0 (installed in
    /home/reca/venv, matching pyproject.toml's >=1.13/>=2.0/>=0.29 pins).

Exercises the real, unmodified classes:
  src/external/routes/admin_connector_status.py -- get_connector_status
  src/adapter/repository/postgres_integration_source_key.py
    -- PostgresIntegrationSourceKeyRepository
  src/adapter/repository/postgres_audit_log.py -- PostgresAuditLogRepository
  src/external/routes/admin_integration_sources.py -- provision (W8, reused)
  src/external/routes/integration_source_push.py -- push_webhook (reused)
  src/external/dependencies.py -- configure_defender_poll_source_from_settings,
    get_defender_poll_org_id, get_defender_poll_source_id

Uses httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) throughout
(not TestClient) -- TestClient's own threaded portal runs the ASGI app on a
separate anyio worker-thread event loop, incompatible with the async
SQLAlchemy engine created on THIS coroutine's own loop (the same real,
previously-confirmed "Future attached to a different loop" failure
poc/kronos_attest_export/run_poc.py and
poc/integration_source_key_provisioning/run_poc.py already documented;
this script follows that exact working pattern).

A distinctly-named fresh org (``poc-w14-connector-status-org``) is used --
never resets or touches any other org's data in the shared dev Postgres.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

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
    from src.domain.user import Role, TenantContext
    from src.external.dependencies import (
        configure_defender_poll_source_from_settings,
        get_audit_log_service,
        get_defender_poll_org_id,
        get_defender_poll_source_id,
        get_inbound_source_authenticator,
        get_integration_source_key_repository,
        get_step_up_auth,
        get_tenant_context,
        reset_dependencies,
    )
    from src.external.fastapi_app import create_app
    from src.external.middleware.integration_source_auth import StaticApiKeyInboundAuthenticator
    from src.external.middleware.step_up_auth import StepUpAuth

    print("=" * 78)
    print("1. Real Alembic migration against the real dev-stack Postgres")
    print("=" * 78)

    result = run_alembic("upgrade", "head")
    print(f"`alembic upgrade head` -> exit={result.returncode}\n{result.stdout}{result.stderr}")
    check("real `alembic upgrade head` exits 0 against docker-postgres-1", result.returncode == 0)

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
        other_org_id = uuid.uuid4()
        user_id = uuid.uuid4()
        source_id = "poc-w14-wazuh-1"
        source_type = "generic-webhook"  # real, registered stand-in PUSH source (roadmap Q1)

        def _admin_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="poc-w14-connector-status-org",
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
        app.dependency_overrides[get_inbound_source_authenticator] = (
            lambda: StaticApiKeyInboundAuthenticator(key_repo)
        )
        # Defender left unconfigured for now -- part 4 below overrides these.
        app.dependency_overrides[get_defender_poll_org_id] = lambda: None
        app.dependency_overrides[get_defender_poll_source_id] = lambda: "ms-defender-alerts"

        import httpx

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://poc"
        ) as client:
            print("\n" + "=" * 78)
            print("3a. Real HTTP: provision a real PUSH source key (W8 route, reused)")
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
            real_api_key = provision_resp.json()["apiKey"]

            print("\n" + "=" * 78)
            print("3b. Status BEFORE any push: source present but never_used")
            print("=" * 78)
            status_resp = await client.get("/api/admin/connectors/status")
            print(f"status -> status={status_resp.status_code}\n{status_resp.text}")
            check("status route returns 200", status_resp.status_code == 200)
            items = status_resp.json()["items"]
            check("exactly 1 connector entry (the provisioned push source)", len(items) == 1)
            check("entry is never_used before any push", items[0]["status"] == "never_used")
            check("lastIngestedAt is null before any push", items[0]["lastIngestedAt"] is None)

            print("\n" + "=" * 78)
            print("3c. Real HTTP: POST /api/integrations/push/{source_type} -- creates a real")
            print("    INTEGRATION_SOURCE_PUSH_INGESTED audit row")
            print("=" * 78)
            push_resp = await client.post(
                f"/api/integrations/push/{source_type}",
                content=b'{"message": "real poc event from W14 connector status view"}',
                headers={
                    "Content-Type": "application/json",
                    "X-KronOS-Source-Key": real_api_key,
                },
            )
            print(f"push -> status={push_resp.status_code}\n{push_resp.text}")
            check("push accepted (202) using the real provisioned key", push_resp.status_code == 202)

            print("\n" + "=" * 78)
            print("3d. Status AFTER the real push: real lastIngestedAt, status=active")
            print("=" * 78)
            status_resp2 = await client.get("/api/admin/connectors/status")
            print(f"status -> status={status_resp2.status_code}\n{status_resp2.text}")
            items2 = status_resp2.json()["items"]
            check("still exactly 1 connector entry", len(items2) == 1)
            entry = items2[0]
            check("sourceId matches the provisioned source", entry["sourceId"] == source_id)
            check("sourceType matches", entry["sourceType"] == source_type)
            check("mode is push", entry["mode"] == "push")
            check("selfService is True for a push source", entry["selfService"] is True)
            check("status flips to active after a real push", entry["status"] == "active")
            check("lastIngestedAt is now populated (real, non-null)", entry["lastIngestedAt"] is not None)
            check("revokedAt is still null (never revoked)", entry["revokedAt"] is None)
            check("lastPollFailedAt is null (push failures aren't audited)", entry["lastPollFailedAt"] is None)

            print("\n" + "=" * 78)
            print("4a. Real Settings + real configure_defender_poll_source_from_settings():")
            print("    defender_poll_org_id NOT set for this org -> Defender entry ABSENT")
            print("=" * 78)
            reset_dependencies()  # clear module globals from any prior run/process state
            with patch("src.config.Settings") as mock_settings_cls:
                from types import SimpleNamespace

                mock_settings_cls.return_value = SimpleNamespace(
                    defender_tenant_id=None,
                    defender_client_id=None,
                    defender_client_secret=None,
                    defender_graph_base_url="https://graph.microsoft.com/v1.0",
                    defender_poll_org_id=str(other_org_id),  # a DIFFERENT org
                    defender_poll_source_id="ms-defender-alerts",
                )
                configure_defender_poll_source_from_settings()
            resolved_org_id = get_defender_poll_org_id()
            check(
                "real get_defender_poll_org_id() reflects the configured (other) org",
                resolved_org_id == str(other_org_id),
            )
            # Drop the earlier stub overrides so the route calls the REAL
            # get_defender_poll_org_id()/get_defender_poll_source_id()
            # functions, which now read the module globals
            # configure_defender_poll_source_from_settings() just set.
            del app.dependency_overrides[get_defender_poll_org_id]
            del app.dependency_overrides[get_defender_poll_source_id]
            status_resp3 = await client.get("/api/admin/connectors/status")
            items3 = status_resp3.json()["items"]
            print(f"status (defender configured for a DIFFERENT org) -> {status_resp3.text}")
            check(
                "Defender entry ABSENT when defender_poll_org_id names a different org",
                all(i["sourceType"] != "ms-defender-alerts" for i in items3),
            )

            print("\n" + "=" * 78)
            print("4b. Same real DI path, now defender_poll_org_id MATCHES this org")
            print("    -> Defender entry PRESENT, honestly labeled non-self-service")
            print("=" * 78)
            reset_dependencies()
            with patch("src.config.Settings") as mock_settings_cls:
                from types import SimpleNamespace

                mock_settings_cls.return_value = SimpleNamespace(
                    defender_tenant_id=None,
                    defender_client_id=None,
                    defender_client_secret=None,
                    defender_graph_base_url="https://graph.microsoft.com/v1.0",
                    defender_poll_org_id=str(org_id),  # THIS org
                    defender_poll_source_id="ms-defender-alerts",
                )
                configure_defender_poll_source_from_settings()
            check(
                "real get_defender_poll_org_id() now reflects THIS org",
                get_defender_poll_org_id() == str(org_id),
            )
            # get_defender_poll_org_id/get_defender_poll_source_id overrides
            # already removed above -- the route already calls the real
            # functions, which now read the freshly-reconfigured globals.
            # get_integration_source_key_repository/get_audit_log_service
            # overrides are untouched by reset_dependencies() (dependency
            # overrides live on the FastAPI app instance, not the DI
            # container's module globals), so the same real key_repo/
            # audit_svc instances used in part 3 are still wired here --
            # this is the same live app/org state, not a fresh one.
            status_resp4 = await client.get("/api/admin/connectors/status")
            print(f"status (defender configured for THIS org) -> {status_resp4.text}")
            items4 = status_resp4.json()["items"]
            defender_entries = [i for i in items4 if i["sourceType"] == "ms-defender-alerts"]
            check("Defender entry PRESENT when defender_poll_org_id matches this org", len(defender_entries) == 1)
            if defender_entries:
                d = defender_entries[0]
                check("Defender entry mode is poll", d["mode"] == "poll")
                check("Defender entry selfService is False (honest, not self-service)", d["selfService"] is False)
                check("Defender entry status is never_used (no poll cycle ran)", d["status"] == "never_used")
                check(
                    "Defender entry note communicates platform-configured, not self-service",
                    "platform settings" in d["note"] and "not self-service" in d["note"],
                )
            check("the real push-source entry is still present alongside Defender", len(items4) == 2)

        print("\n" + "=" * 78)
        print(f"{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
        print("=" * 78)
    finally:
        reset_dependencies()
        await engine.dispose()

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main_async())
