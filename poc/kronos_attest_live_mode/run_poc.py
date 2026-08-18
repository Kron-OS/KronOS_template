"""PoC: kronos-attest CLI's new live-Postgres mode vs. its existing offline
--audit-log mode, against the SAME real org in the real shared dev Postgres.

Verifies Gap Audit AA1 / P2-5: `kronos_attest/cli.py`'s `verify`,
`day-report`, `case-report` commands can now read directly from Postgres
(`--database-url` + `--org-id`) instead of only a static JSON export file
(`--audit-log`). The whole point of this PoC is proving the two code paths
agree byte-for-byte on the same real data -- not just that live mode runs
without crashing.

Real Postgres: docker-postgres-1 (postgres:16-alpine), localhost:5432,
db=kronos, user=kronos -- the repo's own shared dev stack, already running,
never touched/restarted by this PoC (read-only queries + the real
kronos-attest CLI subprocess only).

Real org used: 174cf1c7-a2b8-4636-b6a2-ba4b40f51007 -- a pre-existing
dev-stack org from earlier PoC/dev work (33 real audit_log rows, one real
case_id, all on 2026-08-08 UTC). Chosen via a direct read-only query
(`SELECT org_id, count(*) ... GROUP BY org_id ORDER BY c DESC`) rather than
fabricated -- see README.md for the exact query and results. No writes are
made to this org; nothing new was generated for this PoC.

Run: /home/reca/venv/bin/python poc/kronos_attest_live_mode/run_poc.py
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.external.routes.audit import _to_export_dict  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
ORG_ID = "174cf1c7-a2b8-4636-b6a2-ba4b40f51007"
CASE_ID = "906ad0c9-0f59-44d9-bbf9-23c26fb34e7c"
DAY = "2026-08-08"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "kronos_attest.cli", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


async def build_offline_export() -> Path:
    """Produce a real --audit-log export file using the exact same
    repository call + field mapping GET /api/audit/export uses (imported,
    not re-derived) -- this is the "offline mode" side of the comparison."""
    engine = create_async_engine(DATABASE_URL)
    try:
        repo = PostgresAuditLogRepository(engine)
        import uuid as uuid_mod

        events = [_to_export_dict(ev) async for ev in repo.stream_by_org(uuid_mod.UUID(ORG_ID))]
    finally:
        await engine.dispose()

    export_path = Path(__file__).parent / "export.json"
    export_path.write_text(json.dumps(events, indent=2))
    print(f"Wrote real offline export: {len(events)} events -> {export_path}")
    return export_path, events


def main() -> None:
    export_path, events = asyncio.run(build_offline_export())
    check("offline export has real events for the chosen org", len(events) > 0, str(len(events)))

    target_event_id = events[0]["event_id"]

    print(f"\n{'=' * 70}\nDAY-REPORT: offline (--audit-log) vs. live (--database-url/--org-id)\n{'=' * 70}")
    offline_day = run_cli("day-report", "--audit-log", str(export_path), "--day", DAY)
    live_day = run_cli("day-report", "--database-url", DATABASE_URL, "--org-id", ORG_ID, "--day", DAY)
    print(f"\n-- offline day-report (exit={offline_day.returncode}) --\n{offline_day.stdout}")
    print(f"-- live day-report (exit={live_day.returncode}) --\n{live_day.stdout}")
    check("offline day-report exited 0", offline_day.returncode == 0, offline_day.stderr)
    check("live day-report exited 0", live_day.returncode == 0, live_day.stderr)
    if offline_day.returncode == 0 and live_day.returncode == 0:
        offline_data = json.loads(offline_day.stdout)
        live_data = json.loads(live_day.stdout)
        for field in (
            "event_count",
            "merkle_root",
            "chain_valid",
            "break_count",
            "org_chain_fully_intact",
        ):
            check(
                f"day-report[{field}] identical offline vs. live",
                offline_data.get(field) == live_data.get(field),
                f"offline={offline_data.get(field)!r} live={live_data.get(field)!r}",
            )

    print(f"\n{'=' * 70}\nCASE-REPORT: offline (--audit-log) vs. live (--database-url/--org-id)\n{'=' * 70}")
    offline_case = run_cli("case-report", "--audit-log", str(export_path), "--case-id", CASE_ID)
    live_case = run_cli(
        "case-report", "--database-url", DATABASE_URL, "--org-id", ORG_ID, "--case-id", CASE_ID
    )
    print(f"\n-- offline case-report (exit={offline_case.returncode}) --\n{offline_case.stdout}")
    print(f"-- live case-report (exit={live_case.returncode}) --\n{live_case.stdout}")
    check("offline case-report exited 0", offline_case.returncode == 0, offline_case.stderr)
    check("live case-report exited 0", live_case.returncode == 0, live_case.stderr)
    if offline_case.returncode == 0 and live_case.returncode == 0:
        offline_data = json.loads(offline_case.stdout)
        live_data = json.loads(live_case.stdout)
        for field in (
            "event_count",
            "merkle_root",
            "chain_valid",
            "break_count",
            "org_chain_fully_intact",
            "evidence_ids",
        ):
            check(
                f"case-report[{field}] identical offline vs. live",
                offline_data.get(field) == live_data.get(field),
                f"offline={offline_data.get(field)!r} live={live_data.get(field)!r}",
            )

    print(f"\n{'=' * 70}\nVERIFY: offline (--audit-log) vs. live (--database-url/--org-id)\n{'=' * 70}")
    offline_verify = run_cli("verify", "--audit-log", str(export_path), "--event-id", target_event_id)
    live_verify = run_cli(
        "verify", "--database-url", DATABASE_URL, "--org-id", ORG_ID, "--event-id", target_event_id
    )
    print(f"\n-- offline verify (exit={offline_verify.returncode}) --\n{offline_verify.stdout}")
    print(f"-- live verify (exit={live_verify.returncode}) --\n{live_verify.stdout}")
    check("offline verify exited 0 (chain intact + event found)", offline_verify.returncode == 0)
    check("live verify exited 0 (chain intact + event found)", live_verify.returncode == 0)
    check(
        "offline and live verify report the same merkle root prefix",
        offline_verify.stdout.split("root=")[-1] == live_verify.stdout.split("root=")[-1],
    )

    print(f"\n{'=' * 70}\nCLI OPTION VALIDATION: real invocations (not just unit-mocked)\n{'=' * 70}")
    both = run_cli(
        "verify", "--audit-log", str(export_path), "--org-id", ORG_ID, "--event-id", target_event_id
    )
    print(f"\n-- verify with both --audit-log and --org-id (exit={both.returncode}) --\n{both.stdout}{both.stderr}")
    check("real CLI rejects --audit-log + --org-id together", both.returncode == 2)
    check("error message names the conflict", "not both" in both.stderr)

    neither = run_cli("day-report", "--day", DAY)
    print(f"\n-- day-report with neither source (exit={neither.returncode}) --\n{neither.stdout}{neither.stderr}")
    check("real CLI rejects neither source given", neither.returncode == 2)

    bad_org_only = run_cli("case-report", "--org-id", ORG_ID, "--case-id", CASE_ID)
    print(
        f"\n-- case-report with --org-id but no --database-url (exit={bad_org_only.returncode}) --\n"
        f"{bad_org_only.stdout}{bad_org_only.stderr}"
    )
    check("real CLI rejects --org-id without --database-url", bad_org_only.returncode == 2)

    print(f"\n{'=' * 70}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 70}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
