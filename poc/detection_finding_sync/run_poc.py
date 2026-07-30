"""PoC: exercise the real Detection entity + triage FSM + audited finding
sync (roadmap M2/C4) against the real, already-running dev stack --
OpenSearch 2.11.1 Security Analytics (localhost:9200) and real PostgreSQL
(localhost:5432). Imports and calls the exact classes KronOS ships
(src/domain/detection.py, src/application/detection_sync.py,
src/application/detection_triage.py, src/adapter/opensearch/
findings_client.py, src/adapter/repository/postgres_detection.py) -- not a
reimplementation.

Prerequisite this script assumes already happened (not scripted here,
because it is real, hands-on cluster setup a throwaway PoC bootstraps once,
not something DetectionSyncService itself ever does -- the sync is
strictly READ-ONLY with respect to OpenSearch):

  A real detector "kronos-kronos-dev-network-detector" was created directly
  against the live cluster, scoped to ONE already-populated real case index
  (kronos-kronos-dev-case-1a49dcd0-b6a6-4410-83aa-def7ffc9f9fa-202309)
  rather than the org wildcard -- sidestepping C2's documented cross-index
  alias-consistency bug (poc/detector_provisioning/README.md), per the
  redispatch brief's own prior-progress guidance. 10 of that index's real
  Suricata EVE documents were re-indexed with a fresh @timestamp so the
  detector's 1-minute scheduled monitor run had new documents to evaluate
  (SA detectors only evaluate documents that arrive after the monitor's own
  last-run cursor, not pre-existing ones -- confirmed the hard way: zero
  findings appeared until this re-indexing). This produced 10 real findings
  in `.opensearch-sap-network-findings-*` before this script ever runs, with
  the real rule t1021.001 (remote-services lateral movement) firing on all
  of them -- see README.md for the full account, including a real finding
  this session's own "zero findings" verification actually used the wrong
  index pattern (`.opensearch-sap-findings-*` does not exist; real indices
  are per-log-type `.opensearch-sap-{log_type}-findings-*`).

This script itself only ever READS from OpenSearch and does real
create/read/update against real Postgres via the actual DetectionRepository/
AuditLogService implementations KronOS ships. At the end it deletes the
bootstrap detector (throwaway infra, not part of any committed src/ path)
but deliberately leaves the real Detection + audit_log rows it created in
Postgres as inspectable proof of the run.

Run: source ~/venv/bin/activate && python poc/detection_finding_sync/run_poc.py
Requires the real dev stack up (docker compose -f docker/docker-compose.dev.yml up -d).
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.opensearch.findings_client import SecurityAnalyticsFindingsClient  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sync import DetectionSyncService  # noqa: E402
from src.application.detection_triage import DetectionTriageService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.detection import DetectionTriageState  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.exceptions import DetectionStateError  # noqa: E402

OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")
DB_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

# Real values confirmed directly against the live stack before this script
# was written (see README.md "Real values used" section) -- never guessed.
ORG_ALIAS = "kronos-dev"
ORG_ID = uuid.UUID("482072f5-8086-4815-be03-879cc2eaecb5")
USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000003")  # a real evidence uploader_user_id for this org
BOOTSTRAP_DETECTOR_NAME = "kronos-kronos-dev-network-detector"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def make_tenant() -> TenantContext:
    return TenantContext(
        org_id=ORG_ID,
        org_alias=ORG_ALIAS,
        user_id=USER_ID,
        username="case-lead",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def part0_confirm_real_findings_exist_before_touching_sync_code() -> None:
    print("\n=== Part 0: confirm real findings exist (per F.2 step 4 -- captured before any sync code runs) ===")
    resp = httpx.post(
        f"{OS_URL}/.opensearch-sap-network-findings-*/_search",
        auth=OS_ADMIN,
        verify=False,
        timeout=15,
        json={"size": 5, "query": {"term": {"monitor_name": BOOTSTRAP_DETECTOR_NAME}}},
    )
    resp.raise_for_status()
    body = resp.json()
    total = body["hits"]["total"]["value"]
    check(
        f"real findings exist for {BOOTSTRAP_DETECTOR_NAME} in the correct "
        f".opensearch-sap-network-findings-* index (NOT the nonexistent "
        f".opensearch-sap-findings-* this session's own earlier check used)",
        total > 0,
        f"total={total}",
    )
    if total > 0:
        sample = body["hits"]["hits"][0]
        print(f"  sample real finding _id={sample['_id']}")
        print(f"  sample real finding _source keys: {sorted(sample['_source'].keys())}")
        print(f"  sample real finding queries[0]: {sample['_source']['queries'][0]}")


async def part1_real_sync(
    detection_repo: PostgresDetectionRepository, audit_log: AuditLogService
) -> tuple[int, list]:
    print("\n=== Part 1: run the real DetectionSyncService against real OpenSearch + real Postgres ===")
    findings_client = SecurityAnalyticsFindingsClient(OS_URL, "admin", "admin")
    sync_service = DetectionSyncService(findings_client, detection_repo, audit_log)
    tenant = make_tenant()

    created = await sync_service.sync_org_findings(tenant)
    check("first real sync run created at least one real Detection row", created > 0, f"created={created}")

    stored = [d async for d in detection_repo.stream_by_org(tenant.org_id)]
    check(
        "every stored Detection has org_id == the syncing tenant's real org_id "
        "(roadmap invariant #3 -- never from the finding)",
        all(d.org_id == ORG_ID for d in stored),
        f"org_ids={ {str(d.org_id) for d in stored} }",
    )
    check(
        "every newly-synced Detection starts in triage_state NEW",
        all(d.triage_state == DetectionTriageState.NEW for d in stored),
        str({d.triage_state.value for d in stored}),
    )
    check(
        "every stored Detection carries at least one real rule_id (replayability)",
        all(len(d.rule_matches) > 0 for d in stored),
        str([d.rule_matches for d in stored][:1]),
    )
    matched_rule_ids = {m.rule_id for d in stored for m in d.rule_matches}
    check(
        "the real t1021.001 rule id is among the stored rule_matches",
        "1fc0809e-06bf-4de3-ad52-25e5263b7623" in matched_rule_ids,
        str(matched_rule_ids),
    )
    check(
        "case_id correctly extracted from the finding's real source index name",
        all(d.case_id == uuid.UUID("1a49dcd0-b6a6-4410-83aa-def7ffc9f9fa") for d in stored),
        str({d.case_id for d in stored}),
    )

    print(f"  {len(stored)} real Detection rows now in Postgres for org {ORG_ALIAS}")
    return created, stored


async def part2_idempotent_rerun(
    detection_repo: PostgresDetectionRepository, audit_log: AuditLogService, first_run_count: int
) -> None:
    print("\n=== Part 2: re-run sync -- must be idempotent, zero duplicates ===")
    findings_client = SecurityAnalyticsFindingsClient(OS_URL, "admin", "admin")
    sync_service = DetectionSyncService(findings_client, detection_repo, audit_log)
    tenant = make_tenant()

    before = [d async for d in detection_repo.stream_by_org(tenant.org_id)]
    created_second_run = await sync_service.sync_org_findings(tenant)
    after = [d async for d in detection_repo.stream_by_org(tenant.org_id)]

    check("re-run creates zero new Detection rows", created_second_run == 0, f"created={created_second_run}")
    check(
        "row count unchanged after re-run (rigorous: same finding_ids, same count)",
        len(before) == len(after) and {d.finding_id for d in before} == {d.finding_id for d in after},
        f"before={len(before)} after={len(after)}",
    )


async def part3_real_triage_transitions(
    detection_repo: PostgresDetectionRepository, audit_log: AuditLogService, stored: list
) -> None:
    print("\n=== Part 3: real valid triage FSM transition + audit hash-chain verification ===")
    triage = DetectionTriageService(detection_repo, audit_log)
    tenant = make_tenant()
    target = stored[0]

    updated = await triage.transition(target.detection_id, DetectionTriageState.INVESTIGATING, tenant)
    check(
        "real NEW -> INVESTIGATING transition applied and persisted",
        updated.triage_state == DetectionTriageState.INVESTIGATING,
        updated.triage_state.value,
    )
    persisted = await detection_repo.get_by_id(target.detection_id, tenant.org_id)
    check(
        "re-read from real Postgres confirms the persisted triage_state",
        persisted is not None and persisted.triage_state == DetectionTriageState.INVESTIGATING,
        persisted.triage_state.value if persisted else "None",
    )

    updated2 = await triage.transition(target.detection_id, DetectionTriageState.TRUE_POSITIVE, tenant)
    check(
        "real INVESTIGATING -> TRUE_POSITIVE transition applied and persisted",
        updated2.triage_state == DetectionTriageState.TRUE_POSITIVE,
        updated2.triage_state.value,
    )

    # Real hash-chain verification: pull the two real audit_log rows this
    # caused directly from Postgres and confirm the chain link, plus run
    # the real AuditLogService.verify_chain() over the org's FULL real
    # chain (this org has a long real history from earlier sessions' work).
    events = [e async for e in audit_log._repository.stream_by_org(tenant.org_id)]  # noqa: SLF001
    transitioned = sorted(
        (
            e
            for e in events
            if e.event_type == AuditEventType.DETECTION_TRIAGE_TRANSITIONED
            and e.details.get("detection_id") == str(target.detection_id)
        ),
        key=lambda e: e.sequence_number,
    )
    check(
        "exactly 2 real DETECTION_TRIAGE_TRANSITIONED audit events for this detection",
        len(transitioned) == 2,
        f"count={len(transitioned)}",
    )
    if len(transitioned) == 2:
        check(
            "second event's prev_row_hash == first event's row_hash (real hash-chain link)",
            transitioned[1].prev_row_hash == transitioned[0].row_hash,
            f"first.row_hash={transitioned[0].row_hash} second.prev_row_hash={transitioned[1].prev_row_hash}",
        )

    ok, detail = await audit_log.verify_chain(tenant.org_id)
    check(
        "AuditLogService.verify_chain() confirms the org's FULL real hash chain is intact "
        "(includes this org's entire real history, not just this run)",
        ok,
        detail or "chain intact",
    )


async def part4_illegal_transition_rejected(
    detection_repo: PostgresDetectionRepository, audit_log: AuditLogService, stored: list
) -> None:
    print("\n=== Part 4: illegal transition must be rejected (with a real audit trail) ===")
    triage = DetectionTriageService(detection_repo, audit_log)
    tenant = make_tenant()

    # A detection still in NEW (part3 only advanced stored[0]) attempting to
    # jump straight to TRUE_POSITIVE, skipping the mandatory INVESTIGATING step.
    still_new = [d for d in stored if d.triage_state == DetectionTriageState.NEW]
    check("at least one Detection remains in NEW to exercise the illegal-transition case", len(still_new) > 0)
    if not still_new:
        return
    target = still_new[0]

    rejected = False
    try:
        await triage.transition(target.detection_id, DetectionTriageState.TRUE_POSITIVE, tenant)
    except DetectionStateError as exc:
        rejected = True
        print(f"  real rejection: {exc}")
    check("illegal NEW -> TRUE_POSITIVE transition raised DetectionStateError", rejected)

    persisted = await detection_repo.get_by_id(target.detection_id, tenant.org_id)
    check(
        "rejected transition did NOT mutate the persisted triage_state",
        persisted is not None and persisted.triage_state == DetectionTriageState.NEW,
        persisted.triage_state.value if persisted else "None",
    )

    events = [e async for e in audit_log._repository.stream_by_org(tenant.org_id)]  # noqa: SLF001
    failed = [
        e
        for e in events
        if e.event_type == AuditEventType.DETECTION_TRIAGE_TRANSITION_FAILED
        and e.details.get("detection_id") == str(target.detection_id)
    ]
    check(
        "the rejected attempt itself produced a real DETECTION_TRIAGE_TRANSITION_FAILED audit event",
        len(failed) == 1,
        f"count={len(failed)}",
    )

    # Also confirm the terminal-state case from part3: TRUE_POSITIVE cannot
    # be reopened.
    terminal_target = stored[0]
    terminal_rejected = False
    try:
        await triage.transition(terminal_target.detection_id, DetectionTriageState.INVESTIGATING, tenant)
    except DetectionStateError:
        terminal_rejected = True
    check(
        "a terminal TRUE_POSITIVE Detection also rejects re-transition (no reopen loophole)",
        terminal_rejected,
    )


def cleanup_bootstrap_detector() -> None:
    print("\n=== Cleanup: remove the throwaway bootstrap detector (not part of any committed src/ path) ===")
    resp = httpx.post(
        f"{OS_URL}/_plugins/_security_analytics/detectors/_search",
        auth=OS_ADMIN,
        verify=False,
        timeout=15,
        json={
            "size": 1,
            "query": {"nested": {"path": "detector", "query": {"term": {"detector.name.keyword": BOOTSTRAP_DETECTOR_NAME}}}},
        },
    )
    hits = resp.json().get("hits", {}).get("hits", [])
    if not hits:
        print(f"  {BOOTSTRAP_DETECTOR_NAME} already absent, nothing to clean up")
        return
    detector_id = hits[0]["_id"]
    d = httpx.delete(
        f"{OS_URL}/_plugins/_security_analytics/detectors/{detector_id}",
        auth=OS_ADMIN,
        verify=False,
        timeout=15,
    )
    print(f"  deleted detector {detector_id}: status={d.status_code}")
    print(
        "  NOTE: the real findings this detector already produced remain in "
        ".opensearch-sap-network-findings-* (findings are independent, "
        "immutable records -- deleting a detector does not delete its past "
        "findings), and the real Detection + audit_log rows this PoC "
        "created remain in Postgres as inspectable proof of the run."
    )


async def main() -> None:
    part0_confirm_real_findings_exist_before_touching_sync_code()

    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    await PostgresDetectionRepository.create_tables(engine)
    await PostgresAuditLogRepository.create_tables(engine)
    detection_repo = PostgresDetectionRepository(engine)
    audit_log = AuditLogService(PostgresAuditLogRepository(engine))

    created, stored = await part1_real_sync(detection_repo, audit_log)
    await part2_idempotent_rerun(detection_repo, audit_log, created)
    # Refresh 'stored' post idempotent-rerun check (unchanged, but re-read for good measure).
    stored = [d async for d in detection_repo.stream_by_org(ORG_ID)]
    await part3_real_triage_transitions(detection_repo, audit_log, stored)
    stored = [d async for d in detection_repo.stream_by_org(ORG_ID)]
    await part4_illegal_transition_rejected(detection_repo, audit_log, stored)

    await engine.dispose()
    cleanup_bootstrap_detector()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
