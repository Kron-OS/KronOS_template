"""PoC: Postgres -> Merkle root -> real RFC3161 TSA anchor -> real
kronos-attest CLI, using the real, unmodified classes throughout.

Reuses poc/rfc3161/'s real openssl-ts-backed TSA responder (the repo's own
dev-compose `tsa` stub is not a real RFC 3161 responder -- see that PoC's
README) so AuditLogService.anchor_day() gets a genuine RFC 3161 token, not
a fake one.

Run: source ~/venv/bin/activate && DATABASE_URL=... python poc/chain_of_custody/run_poc.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "poc" / "rfc3161"))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from run_poc import TSA_HOST, TSA_PORT, build_throwaway_tsa, make_handler  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.timestamping import RFC3161TimestampService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402

DATABASE_URL = os.environ["DATABASE_URL"]

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


async def main() -> None:
    engine = create_async_engine(DATABASE_URL)
    await PostgresAuditLogRepository.create_tables(engine)
    repo = PostgresAuditLogRepository(engine)
    svc = AuditLogService(repo)

    org_id = uuid.uuid4()
    case_id = uuid.uuid4()
    today = datetime.now(UTC).date()

    print(f"org_id={org_id} case_id={case_id} anchor day (UTC)={today}")

    # --- 1. Real events across a case ---
    event_types = [
        AuditEventType.CASE_CREATED,
        AuditEventType.EVIDENCE_UPLOAD_REQUESTED,
        AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
        AuditEventType.INGEST_STARTED,
        AuditEventType.INGEST_COMPLETED,
    ]
    logged = []
    for et in event_types:
        ev = await svc.log(et, org_id=org_id, case_id=case_id, details={"note": et.value})
        logged.append(ev)
    check("5 real events logged to real Postgres", len(logged) == 5)

    # --- 2. Real openssl-ts-backed TSA responder ---
    workdir = Path("/tmp/kronos_poc_coc_tsa")
    workdir.mkdir(exist_ok=True)
    tsa_cnf = build_throwaway_tsa(workdir)
    handler = make_handler(tsa_cnf, workdir)
    import socketserver

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), handler)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"\nreal openssl-ts TSA responder listening on http://{TSA_HOST}:{TSA_PORT}")

    timestamp_service = RFC3161TimestampService(tsa_url=f"http://{TSA_HOST}:{TSA_PORT}/")

    # --- 3. Real anchor_day() -- real Merkle root + real TSA call ---
    root_hash = await svc.anchor_day(today, org_id, timestamp_service)
    print(f"\nAuditLogService.anchor_day() returned root_hash={root_hash[:16]}...")
    check("anchor_day() returned a non-empty root hash", bool(root_hash) and root_hash != "")

    anchor = await repo.get_anchor(today, org_id=org_id)
    check("real anchor row persisted in Postgres", anchor is not None)
    if anchor:
        stored_root, tsa_token = anchor
        check("stored anchor root matches anchor_day()'s return value", stored_root == root_hash)
        check("real TSA token was actually stored (not None)", tsa_token is not None, f"{len(tsa_token) if tsa_token else 0} bytes")

    ok, detail = await svc.verify_chain(org_id)
    check("full chain verifies intact after anchoring", ok, detail or "")

    # --- 4. Export events to JSON, exactly as kronos-attest expects ---
    all_events = [e async for e in repo.stream_by_org(org_id)]

    def _to_json(ev):
        return {
            "event_id": str(ev.event_id),
            "event_type": ev.event_type.value,
            "actor_user_id": str(ev.actor_user_id) if ev.actor_user_id else None,
            "actor_username": ev.actor_username,
            "org_id": str(ev.org_id) if ev.org_id else None,
            "case_id": str(ev.case_id) if ev.case_id else None,
            "evidence_id": str(ev.evidence_id) if ev.evidence_id else None,
            "details": ev.details,
            "occurred_at": ev.occurred_at.isoformat(),
            "sequence_number": ev.sequence_number,
            "prev_row_hash": ev.prev_row_hash,
            "row_hash": ev.row_hash,
        }

    export_path = Path(__file__).parent / "export.json"
    export_path.write_text(json.dumps([_to_json(e) for e in all_events], indent=2))
    print(f"\nExported {len(all_events)} events (including the AUDIT_MERKLE_ANCHORED bookkeeping event) to {export_path}")

    ca_pem = workdir / "ca.pem"

    # --- 5. Real kronos-attest CLI: merkle-root ---
    result = run_cli("merkle-root", "--audit-log", str(export_path))
    cli_root = result.stdout.strip()
    print(f"\n`kronos-attest merkle-root` -> {cli_root[:16]}... (exit {result.returncode})")
    # NOTE: the CLI's merkle-root spans ALL exported events (including the
    # anchor event itself), while anchor_day()'s root deliberately excludes
    # it -- these are legitimately different roots computed over different
    # leaf sets, not a bug. Documented in the README.
    check("kronos-attest merkle-root ran successfully", result.returncode == 0 and bool(cli_root))

    # --- 6. Real kronos-attest CLI: verify (chain + TSA anchors) ---
    target_event = logged[0]
    result = run_cli(
        "verify", "--audit-log", str(export_path),
        "--event-id", str(target_event.event_id),
        "--tsa-cert", str(ca_pem),
    )
    print(f"\n`kronos-attest verify --tsa-cert` ->\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}\nexit={result.returncode}")
    check("kronos-attest verify: chain intact + event found + TSA anchor genuinely verified", result.returncode == 0)
    check("verify output reports the TSA anchor as valid", "valid" in result.stdout and "INVALID" not in result.stdout)

    # --- 7. Real kronos-attest CLI: merkle-proof ---
    result = run_cli("merkle-proof", "--audit-log", str(export_path), "--event-id", str(target_event.event_id))
    print(f"\n`kronos-attest merkle-proof` -> exit={result.returncode}\n{result.stdout[:400]}")
    proof_json = json.loads(result.stdout) if result.returncode == 0 else {}
    check("merkle-proof succeeded and returned a proof list", result.returncode == 0 and isinstance(proof_json.get("proof"), list))

    # --- 8. Real kronos-attest CLI: day-report (the suspected buggy path) ---
    result = run_cli("day-report", "--audit-log", str(export_path), "--day", today.isoformat(), "--tsa-cert", str(ca_pem))
    print(f"\n`kronos-attest day-report --tsa-cert` -> exit={result.returncode}\n{result.stdout}")
    day_report = json.loads(result.stdout) if result.returncode == 0 else {}
    check(
        "day-report's tsa_anchored is True for a day that WAS genuinely TSA-anchored",
        day_report.get("tsa_anchored") is True,
        f"got {day_report.get('tsa_anchored')!r} -- see README for root cause if False",
    )

    # --- 9. Real kronos-attest CLI: case-report ---
    result = run_cli("case-report", "--audit-log", str(export_path), "--case-id", str(case_id))
    print(f"\n`kronos-attest case-report` -> exit={result.returncode}\n{result.stdout}")
    case_report = json.loads(result.stdout) if result.returncode == 0 else {}
    check("case-report found all 5 real case events", case_report.get("event_count") == 5, str(case_report.get("event_count")))
    check("case-report's chain_valid is True", case_report.get("chain_valid") is True)

    # --- 10. Tamper test: mutate one row_hash in the export, confirm detection ---
    tampered_events = json.loads(export_path.read_text())
    tampered_events[1]["row_hash"] = "f" * 64
    tampered_path = Path(__file__).parent / "export_tampered.json"
    tampered_path.write_text(json.dumps(tampered_events, indent=2))

    result = run_cli("verify", "--audit-log", str(tampered_path), "--event-id", str(target_event.event_id))
    print(f"\n`kronos-attest verify` on TAMPERED export -> exit={result.returncode}\n{result.stdout}")
    check("kronos-attest verify DETECTS the tamper and exits nonzero", result.returncode != 0)
    check("verify output reports a chain break (on stderr, where the CLI writes it)", "BROKEN" in result.stderr)

    server.shutdown()
    await engine.dispose()

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


if __name__ == "__main__":
    asyncio.run(main())
