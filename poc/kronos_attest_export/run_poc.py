#!/usr/bin/env python3
"""Verification-first PoC: GET /api/audit/export -> real kronos-attest CLI.

Proves the new export route (src/external/routes/audit.py::export_org_audit_log)
produces a JSON export the real, installed kronos-attest CLI can genuinely
consume -- not just a mock-repository unit test.

Pinned versions:
  - Postgres: real running docker-postgres-1 (postgres:16-alpine).
    sqlalchemy 2.0.51, asyncpg (per pyproject.toml).

Exercises the real, unmodified classes:
  src/adapter/repository/postgres_audit_log.py -- PostgresAuditLogRepository
  src/application/audit_log.py                 -- AuditLogService
  src/external/routes/audit.py                 -- export_org_audit_log (NEW)
  kronos_attest/cli.py                         -- real subprocess, real CLI

Scenario: seed one org with TWO cases (proving the "full org export, not
case-scoped" design decision matters -- if the route wrongly filtered
server-side, this is exactly the setup that would expose it), seed a second
org (tenant isolation), call the real route via TestClient, save the real
response body, then run the REAL kronos-attest CLI (subprocess, not
imported) against it: verify, day-report, case-report (once per case).
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.dependencies import get_audit_log_service, get_tenant_context  # noqa: E402
from src.external.fastapi_app import create_app  # noqa: E402

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


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "kronos_attest.cli", *args],
        capture_output=True,
        text=True,
    )


async def main_async() -> None:
    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    try:
        await PostgresAuditLogRepository.create_tables(engine)
        repo = PostgresAuditLogRepository(engine)
        svc = AuditLogService(repo)

        org_id = uuid.uuid4()
        other_org_id = uuid.uuid4()
        case_a = uuid.uuid4()
        case_b = uuid.uuid4()
        today = datetime.now(UTC).date()

        print("=" * 78)
        print(f"1. Real Postgres-backed audit events -- org={org_id} (2 cases), other_org={other_org_id}")
        print("=" * 78)

        # Case A: 3 events. Case B: 2 events. Interleaved (not case-grouped)
        # to genuinely exercise the "full chain, client-side filter" path --
        # a server-side case-filter bug would still coincidentally "work" if
        # a case's events all happened to be contiguous in sequence_number.
        await svc.log(AuditEventType.CASE_CREATED, org_id=org_id, case_id=case_a, actor_username="alice", details={"n": 1})
        await svc.log(AuditEventType.CASE_CREATED, org_id=org_id, case_id=case_b, actor_username="bob", details={"n": 2})
        await svc.log(AuditEventType.EVIDENCE_UPLOAD_FINALIZED, org_id=org_id, case_id=case_a, evidence_id=uuid.uuid4(), details={"n": 3})
        await svc.log(AuditEventType.EVIDENCE_UPLOAD_FINALIZED, org_id=org_id, case_id=case_b, evidence_id=uuid.uuid4(), details={"n": 4})
        await svc.log(AuditEventType.INGEST_COMPLETED, org_id=org_id, case_id=case_a, details={"n": 5})
        # Other org's own event -- must NEVER appear in the export below.
        await svc.log(AuditEventType.CASE_CREATED, org_id=other_org_id, details={"n": 99})

        ok, detail = await svc.verify_chain(org_id)
        check("real chain verifies intact before export (server-side AuditLogService.verify_chain)", ok, detail or "")

        print("\n" + "=" * 78)
        print("2. Real HTTP call to the new route -- GET /api/audit/export")
        print("=" * 78)

        import httpx  # noqa: PLC0415

        def _tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="pocorg",
                user_id=uuid.uuid4(),
                username="poc-admin",
                roles=frozenset({Role.ORG_ADMIN}),
                correlation_id=str(uuid.uuid4()),
            )

        app = create_app()
        app.dependency_overrides[get_tenant_context] = _tenant
        app.dependency_overrides[get_audit_log_service] = lambda: svc

        # httpx.ASGITransport (not TestClient) -- TestClient runs the ASGI
        # app on a separate anyio worker-thread event loop via a blocking
        # portal, which is incompatible with an async SQLAlchemy engine
        # created on THIS coroutine's own loop (confirmed live: raised
        # "Future attached to a different loop" from asyncpg). Running the
        # app in-process against this same loop avoids that entirely -- a
        # real PoC-script bug, not a bug in the route itself.
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://poc"
        ) as client:
            resp = await client.get("/api/audit/export")

        check("real route returns 200", resp.status_code == 200, f"status={resp.status_code}")
        check(
            "Content-Disposition present with expected filename prefix",
            "kronos-audit-export-pocorg-" in resp.headers.get("content-disposition", ""),
            resp.headers.get("content-disposition", ""),
        )

        events = resp.json()
        check("export contains exactly the 5 real org events (not the other org's)", len(events) == 5, f"count={len(events)}")
        check(
            "no other-org event leaked into the export",
            all(e["org_id"] == str(org_id) for e in events),
        )

        export_path = Path(__file__).parent / "export.json"
        export_path.write_text(json.dumps(events, indent=2))
        print(f"\nReal route response saved to {export_path} ({len(events)} events)")

        print("\n" + "=" * 78)
        print("3. Real kronos-attest CLI (subprocess) against the route's real output")
        print("=" * 78)

        result = run_cli("merkle-root", "--audit-log", str(export_path))
        print(f"\n`kronos-attest merkle-root` -> exit={result.returncode}\nSTDOUT: {result.stdout.strip()}\nSTDERR: {result.stderr.strip()}")
        check("merkle-root ran successfully against the route's real output", result.returncode == 0 and bool(result.stdout.strip()))

        target_event_id = events[0]["event_id"]
        result = run_cli("verify", "--audit-log", str(export_path), "--event-id", target_event_id)
        print(f"\n`kronos-attest verify` -> exit={result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
        check("verify: chain intact + event found (real CLI, real exit code 0)", result.returncode == 0)

        result = run_cli("day-report", "--audit-log", str(export_path), "--day", today.isoformat())
        print(f"\n`kronos-attest day-report` -> exit={result.returncode}\n{result.stdout}")
        day_report = json.loads(result.stdout) if result.returncode == 0 else {}
        check("day-report exit 0", result.returncode == 0)
        check("day-report event_count == 5 (all 5 real events occurred today)", day_report.get("event_count") == 5, str(day_report.get("event_count")))
        check("day-report chain_valid is True -- THE key proof: full-org export, client-filtered by day, still chains correctly", day_report.get("chain_valid") is True)

        result = run_cli("case-report", "--audit-log", str(export_path), "--case-id", str(case_a))
        print(f"\n`kronos-attest case-report` (case_a, 3 events) -> exit={result.returncode}\n{result.stdout}")
        case_a_report = json.loads(result.stdout) if result.returncode == 0 else {}
        check("case-report (case_a) exit 0", result.returncode == 0)
        check("case-report (case_a) event_count == 3", case_a_report.get("event_count") == 3, str(case_a_report.get("event_count")))
        check(
            "case-report (case_a) chain_valid is True -- THE key proof this PoC exists for: "
            "a case-filtered subset of a FULL org export still verifies, because the export "
            "was never server-side case-filtered in the first place",
            case_a_report.get("chain_valid") is True,
        )

        result = run_cli("case-report", "--audit-log", str(export_path), "--case-id", str(case_b))
        print(f"\n`kronos-attest case-report` (case_b, 2 events) -> exit={result.returncode}\n{result.stdout}")
        case_b_report = json.loads(result.stdout) if result.returncode == 0 else {}
        check("case-report (case_b) event_count == 2", case_b_report.get("event_count") == 2, str(case_b_report.get("event_count")))
        check("case-report (case_b) chain_valid is True", case_b_report.get("chain_valid") is True)

        print("\n" + "=" * 78)
        print(f"{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
        print("=" * 78)
    finally:
        await engine.dispose()

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main_async())
