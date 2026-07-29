"""PoC: real Postgres audit hash-chain concurrency/integrity + evidence/case
repo CRUD, using the REAL PostgresAuditLogRepository/AuditLogService/
PostgresEvidenceRepository/PostgresCaseRepository classes -- no reimplementation.

Focus: the audit hash chain's core compliance guarantee (CLAUDE.md A.2) is
cryptographic tamper-evidence AND correctness under real concurrent writers.
Both are testable and neither was ever verified against a real Postgres
before this pass (existing unit tests use an in-memory fake repo — see
tests/conftest.py's InMemoryAuditLogRepository).

Run: source ~/venv/bin/activate && DATABASE_URL=... python poc/postgres/run_poc.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_case import PostgresCaseRepository  # noqa: E402
from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.evidence import EvidenceState  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from fixtures.factories import make_case, make_evidence  # noqa: E402

DATABASE_URL = os.environ["DATABASE_URL"]

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


async def main() -> None:
    engine = create_async_engine(DATABASE_URL, pool_size=60, max_overflow=60)
    await PostgresAuditLogRepository.create_tables(engine)
    await PostgresEvidenceRepository.create_tables(engine)
    await PostgresCaseRepository.create_tables(engine)

    audit_repo = PostgresAuditLogRepository(engine)
    audit_svc = AuditLogService(audit_repo)
    evidence_repo = PostgresEvidenceRepository(engine)
    case_repo = PostgresCaseRepository(engine)

    org_a = uuid.uuid4()
    org_b = uuid.uuid4()

    # --- Test A: sequential chain correctness ---
    print("\n=== Test A: sequential hash chain ===")
    for i in range(5):
        await audit_svc.log(AuditEventType.CASE_CREATED, org_id=org_a, details={"i": i})
    ok, detail = await audit_svc.verify_chain(org_a)
    check("sequential chain of 5 events verifies intact", ok, detail or "")
    seq = await audit_repo.get_latest_sequence(org_a)
    check("sequence number reached 5", seq == 5, f"got {seq}")

    # --- Test B: real concurrent writers, SAME org ---
    print("\n=== Test B: 30 concurrent appends to the SAME org ===")

    async def _append(i: int) -> None:
        await audit_svc.log(AuditEventType.EVIDENCE_UPLOAD_REQUESTED, org_id=org_a, details={"n": i})

    await asyncio.gather(*[_append(i) for i in range(30)])
    seq_after = await audit_repo.get_latest_sequence(org_a)
    check("sequence advanced by exactly 30 (5 + 30 = 35), no lost/duplicate writes", seq_after == 35, f"got {seq_after}")
    ok, detail = await audit_svc.verify_chain(org_a)
    check("chain still verifies intact after concurrent writes", ok, detail or "")

    # Confirm no duplicate sequence_numbers landed (would violate the unique
    # constraint anyway, but check directly against real Postgres).
    async with engine.connect() as conn:
        dup = await conn.execute(
            text(
                "SELECT sequence_number, COUNT(*) FROM audit_log WHERE org_id = :org "
                "GROUP BY sequence_number HAVING COUNT(*) > 1"
            ),
            {"org": str(org_a)},
        )
        dup_rows = dup.fetchall()
    check("no duplicate sequence_number rows in real Postgres", len(dup_rows) == 0, str(dup_rows))

    # --- Test C: concurrent writers, DIFFERENT orgs, should NOT serialize against each other ---
    # Fair comparison: SAME total work (40 writes) either way, so any speedup
    # is attributable to lock scoping, not just "less total work".
    print("\n=== Test C: concurrent writers on two DIFFERENT orgs (lock scoping) ===")
    import time

    org_one = uuid.uuid4()
    start = time.monotonic()
    await asyncio.gather(*[_append_org(audit_svc, org_one, i) for i in range(40)])
    t_one_org_40 = time.monotonic() - start

    org_x, org_y = uuid.uuid4(), uuid.uuid4()
    start = time.monotonic()
    await asyncio.gather(
        *[_append_org(audit_svc, org_x, i) for i in range(20)],
        *[_append_org(audit_svc, org_y, i) for i in range(20)],
    )
    t_two_org_40 = time.monotonic() - start

    print(
        f"40 concurrent writes, ONE org (fully serialized): {t_one_org_40:.3f}s -- "
        f"40 concurrent writes, TWO orgs 20 each: {t_two_org_40:.3f}s"
    )
    check(
        "two different orgs' writers do NOT serialize against each other "
        "(same total work split across 2 orgs is meaningfully faster than 1 org)",
        t_two_org_40 < t_one_org_40 * 0.6,
        f"one_org={t_one_org_40:.3f}s two_org={t_two_org_40:.3f}s ratio={t_one_org_40 / t_two_org_40:.2f}",
    )
    for org in (org_x, org_y):
        ok, detail = await audit_svc.verify_chain(org)
        check(f"org {org} chain intact after concurrent cross-org writes", ok, detail or "")

    # --- Test D: tamper detection ---
    print("\n=== Test D: tamper detection (direct raw SQL UPDATE, bypassing the app) ===")
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE audit_log SET details = '{\"tampered\": true}' WHERE org_id = :org AND sequence_number = 3"),
            {"org": str(org_a)},
        )
    ok, detail = await audit_svc.verify_chain(org_a)
    check("verify_chain() DETECTS a raw-SQL tamper of event content", not ok, detail or "(no detail -- BUG: not detected)")

    # --- Test E: evidence repo real CRUD ---
    print("\n=== Test E: PostgresEvidenceRepository real CRUD ===")
    ev = make_evidence(state=EvidenceState.UPLOADING, org_id=org_a)
    saved = await evidence_repo.save(ev)
    check("evidence saved", saved.evidence_id == ev.evidence_id)
    fetched = await evidence_repo.get_by_id(ev.evidence_id, org_a)
    check("evidence fetched back with same id", fetched is not None and fetched.evidence_id == ev.evidence_id)
    updated = fetched.with_state(EvidenceState.SCANNING)
    await evidence_repo.update(updated)
    refetched = await evidence_repo.get_by_id(ev.evidence_id, org_a)
    check("evidence state transition persisted for real", refetched.state == EvidenceState.SCANNING, str(refetched.state))
    cross_org_fetch = await evidence_repo.get_by_id(ev.evidence_id, org_b)
    check("evidence NOT visible to a different org_id", cross_org_fetch is None)
    deleted = await evidence_repo.delete_by_id(ev.evidence_id, org_a)
    check("evidence delete_by_id returns True", deleted is True)
    gone = await evidence_repo.get_by_id(ev.evidence_id, org_a)
    check("evidence really gone after delete", gone is None)

    # --- Test F: case repo pagination + update ---
    print("\n=== Test F: PostgresCaseRepository pagination + update ===")
    for i in range(7):
        c = make_case(org_id=org_b)
        c = c.model_copy(update={"metadata": c.metadata.model_copy(update={"title": f"Case {i}"})})
        await case_repo.save(c)
    page1, total = await case_repo.list_by_org(org_b, page=1, page_size=5)
    page2, _ = await case_repo.list_by_org(org_b, page=2, page_size=5)
    check("pagination: total is 7", total == 7, f"got {total}")
    check("pagination: page1 has 5, page2 has 2", len(page1) == 5 and len(page2) == 2, f"{len(page1)}/{len(page2)}")
    ids_p1 = {c.case_id for c in page1}
    ids_p2 = {c.case_id for c in page2}
    check("pagination: no overlap between pages", ids_p1.isdisjoint(ids_p2))

    await engine.dispose()

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


async def _append_org(svc: AuditLogService, org_id: uuid.UUID, i: int) -> None:
    await svc.log(AuditEventType.EVIDENCE_UPLOAD_REQUESTED, org_id=org_id, details={"n": i})


if __name__ == "__main__":
    asyncio.run(main())
