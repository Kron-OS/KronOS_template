"""PoC: real Celery beat task BODIES against real seeded-stale Postgres rows.

Tasks under test (src/external/celery_app.py), all scheduled hourly/daily
via crontab and never previously run against real data old enough to
trigger their actual timeout logic:
  - abort_orphan_uploads  -- UPLOADING evidence stuck >2h -> ERROR
  - abort_orphan_parses   -- PARSING evidence stuck >3h -> ERROR
  - auto_dispatch_received -- RECEIVED evidence stuck >5min -> re-enqueued
  - anchor_audit_log      -- yesterday's (UTC) audit events -> real Merkle
    root + real RFC3161 TSA anchor, once per org that had activity

Uses the REAL wire_dependencies_sync() (the exact function Celery's
worker_init signal calls in production -- src/external/celery_app.py's
_on_worker_init) so the DI container/timestamp service are wired exactly as
they would be on a real worker, then calls the real task functions
directly (bypassing the broker for execution, since eager in-process
invocation is the correct way to exercise task BODY logic against seeded
data, not dispatch semantics -- poc/celery_redis already covered real
dispatch through Redis).

Run via run_poc.sh (starts real Postgres + Redis, exports the full env
Settings() requires, then runs this).
"""
from __future__ import annotations

import asyncio
import socketserver
import sys
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "poc" / "rfc3161"))

import redis  # noqa: E402
from run_poc import TSA_HOST, TSA_PORT, build_throwaway_tsa, make_handler  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.config import Settings  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState  # noqa: E402
from src.external.startup import wire_dependencies_sync  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def make_evidence(state: EvidenceState, created_at: datetime, updated_at: datetime, *, org_id: uuid.UUID) -> Evidence:
    return Evidence(
        metadata=EvidenceMetadata(
            original_filename="seed.evtx",
            content_type="application/octet-stream",
            size_bytes=1024,
            uploader_user_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=org_id,
            org_alias="celerybeatpoc",
        ),
        state=state,
        created_at=created_at,
        updated_at=updated_at,
    )


async def seed(settings: Settings) -> dict:
    evidence_repo = PostgresEvidenceRepository(create_async_engine(settings.database_url.get_secret_value()))
    now = datetime.now(UTC)
    org_stale = uuid.uuid4()

    # --- Seed evidence rows: one genuinely stale + one fresh control per state ---
    seeds = {
        "stale_uploading": make_evidence(EvidenceState.UPLOADING, now - timedelta(hours=3), now - timedelta(hours=3), org_id=org_stale),
        "fresh_uploading": make_evidence(EvidenceState.UPLOADING, now - timedelta(minutes=10), now - timedelta(minutes=10), org_id=org_stale),
        "stale_parsing": make_evidence(EvidenceState.PARSING, now - timedelta(hours=5), now - timedelta(hours=4), org_id=org_stale),
        "fresh_parsing": make_evidence(EvidenceState.PARSING, now - timedelta(hours=1), now - timedelta(minutes=10), org_id=org_stale),
        "stale_received": make_evidence(EvidenceState.RECEIVED, now - timedelta(hours=1), now - timedelta(minutes=10), org_id=org_stale),
        "fresh_received": make_evidence(EvidenceState.RECEIVED, now - timedelta(minutes=1), now - timedelta(minutes=1), org_id=org_stale),
    }
    for label, ev in seeds.items():
        await evidence_repo.save(ev)
        print(f"seeded {label}: evidence_id={ev.evidence_id} created_at={ev.created_at} updated_at={ev.updated_at}")

    # --- Seed audit events: 2 orgs with real "yesterday" (UTC) activity, 1 org today-only (control) ---
    audit_repo = PostgresAuditLogRepository(create_async_engine(settings.database_url.get_secret_value()))
    audit_service = AuditLogService(audit_repo)
    org_a, org_b, org_today_only = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    yesterday_utc = (datetime.now(UTC) - timedelta(days=1)).replace(hour=12, minute=0, second=0, microsecond=0)
    for org in (org_a, org_b):
        await audit_service.log(AuditEventType.CASE_CREATED, org_id=org, occurred_at=yesterday_utc, details={"seed": "yesterday"})
    await audit_service.log(AuditEventType.CASE_CREATED, org_id=org_today_only, occurred_at=datetime.now(UTC), details={"seed": "today"})
    print(f"seeded audit events: org_a={org_a} org_b={org_b} (yesterday), org_today_only={org_today_only} (today)")

    await evidence_repo._engine.dispose()  # type: ignore[attr-defined]
    await audit_repo._engine.dispose()  # type: ignore[attr-defined]

    return {
        "seeds": seeds, "org_stale": org_stale,
        "org_a": org_a, "org_b": org_b, "org_today_only": org_today_only,
        "yesterday_utc": yesterday_utc,
    }


async def verify(settings: Settings, ctx: dict, results: dict) -> None:
    evidence_repo = PostgresEvidenceRepository(create_async_engine(settings.database_url.get_secret_value()))
    audit_repo = PostgresAuditLogRepository(create_async_engine(settings.database_url.get_secret_value()))
    audit_service = AuditLogService(audit_repo)

    seeds, org_stale = ctx["seeds"], ctx["org_stale"]
    org_a, org_b, org_today_only = ctx["org_a"], ctx["org_b"], ctx["org_today_only"]
    n_uploads, n_parses, n_dispatched, roots = (
        results["n_uploads"], results["n_parses"], results["n_dispatched"], results["roots"],
    )

    print("\n" + "=" * 10, "Verification", "=" * 10)
    check("abort_orphan_uploads reported exactly 1 aborted (the stale row only)", n_uploads == 1, str(n_uploads))
    check("abort_orphan_parses reported exactly 1 aborted (the stale row only)", n_parses == 1, str(n_parses))
    check("auto_dispatch_received reported exactly 1 dispatched (the stale row only)", n_dispatched == 1, str(n_dispatched))

    stale_upload_after = await evidence_repo.get_by_id(seeds["stale_uploading"].evidence_id, org_stale)
    fresh_upload_after = await evidence_repo.get_by_id(seeds["fresh_uploading"].evidence_id, org_stale)
    check("real stale UPLOADING row is now ERROR in real Postgres", stale_upload_after.state == EvidenceState.ERROR)
    check("real stale UPLOADING row's error_reason is 'upload_timeout'", stale_upload_after.error_reason == "upload_timeout")
    check("real fresh UPLOADING control row was NOT touched (still UPLOADING)", fresh_upload_after.state == EvidenceState.UPLOADING)

    stale_parse_after = await evidence_repo.get_by_id(seeds["stale_parsing"].evidence_id, org_stale)
    fresh_parse_after = await evidence_repo.get_by_id(seeds["fresh_parsing"].evidence_id, org_stale)
    check("real stale PARSING row is now ERROR in real Postgres", stale_parse_after.state == EvidenceState.ERROR)
    check("real stale PARSING row's error_reason is 'parse_timeout'", stale_parse_after.error_reason == "parse_timeout")
    check("real fresh PARSING control row was NOT touched (still PARSING)", fresh_parse_after.state == EvidenceState.PARSING)

    # --- Verify the real Redis broker actually received a dispatch_parse message ---
    r = redis.Redis.from_url(settings.celery_broker_url.get_secret_value())
    qlen = r.llen("q.index")
    print(f"real Redis LLEN q.index = {qlen}")
    check("auto_dispatch_received's re-enqueue produced a REAL message on the real Redis broker (q.index)", qlen >= 1, str(qlen))

    # --- Verify anchor_audit_log's real results ---
    check("anchor_audit_log anchored exactly the 2 orgs with real 'yesterday' activity", set(roots.keys()) == {str(org_a), str(org_b)}, str(set(roots.keys())))
    check("today-only control org was correctly EXCLUDED from yesterday's anchor", str(org_today_only) not in roots)

    yesterday_date = ctx["yesterday_utc"].date()
    anchor_a = await audit_repo.get_anchor(yesterday_date, org_id=org_a)
    check("real anchor row persisted in Postgres for org A", anchor_a is not None)
    if anchor_a:
        root_hash_a, tsa_token_a = anchor_a
        check("org A's persisted root hash matches anchor_audit_log()'s return value", root_hash_a == roots[str(org_a)])
        check("org A's anchor has a REAL TSA token stored (not None)", tsa_token_a is not None, f"{len(tsa_token_a) if tsa_token_a else 0} bytes")

    ok_a, detail_a = await audit_service.verify_chain(org_a)
    check("org A's hash chain verifies intact after anchoring", ok_a, detail_a or "")

    await evidence_repo._engine.dispose()  # type: ignore[attr-defined]
    await audit_repo._engine.dispose()  # type: ignore[attr-defined]


def main() -> None:
    settings = Settings()

    # Wire dependencies EXACTLY as a real Celery worker does on startup.
    # Must be plain sync top-level code, NOT inside an asyncio.run() of our
    # own -- wire_dependencies_sync() does its own internal asyncio.run() to
    # create tables, and nesting asyncio.run() calls raises "cannot be
    # called from a running event loop". Real finding: this rules out
    # wrapping this whole PoC in one big async function, the same "one
    # asyncio.run() per unit of work, never nested" constraint
    # run_evidence_coro() already follows for the tasks themselves.
    wire_dependencies_sync()
    print("wire_dependencies_sync() completed (real DI container wired, tables created)")

    ctx = asyncio.run(seed(settings))

    # --- Real local openssl-ts TSA responder (same technique as poc/rfc3161) ---
    workdir = Path("/tmp/kronos_poc_celery_beat_tsa")
    workdir.mkdir(exist_ok=True)
    tsa_cnf = build_throwaway_tsa(workdir)
    handler = make_handler(tsa_cnf, workdir)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer((TSA_HOST, TSA_PORT), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"real openssl-ts TSA responder listening on http://{TSA_HOST}:{TSA_PORT}")

    # --- Run the REAL task functions directly (eager, in-process; each one
    # does its own internal asyncio.run() via run_evidence_coro()) ---
    from src.external.celery_app import (  # noqa: PLC0415
        abort_orphan_parses,
        abort_orphan_uploads,
        anchor_audit_log,
        auto_dispatch_received,
    )

    print("\n" + "=" * 10, "abort_orphan_uploads()", "=" * 10)
    n_uploads = abort_orphan_uploads()
    print(f"-> aborted {n_uploads}")

    print("\n" + "=" * 10, "abort_orphan_parses()", "=" * 10)
    n_parses = abort_orphan_parses()
    print(f"-> aborted {n_parses}")

    print("\n" + "=" * 10, "auto_dispatch_received()", "=" * 10)
    n_dispatched = auto_dispatch_received()
    print(f"-> dispatched {n_dispatched}")

    print("\n" + "=" * 10, "anchor_audit_log()", "=" * 10)
    roots = anchor_audit_log()
    print(f"-> {roots}")

    results = {"n_uploads": n_uploads, "n_parses": n_parses, "n_dispatched": n_dispatched, "roots": roots}
    asyncio.run(verify(settings, ctx, results))

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
