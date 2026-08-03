#!/usr/bin/env python3
"""Verification-first PoC: playbook engine (roadmap M7/H1).

Drives the real, unmodified production classes against a REAL Postgres 16
instance (docker-postgres-1), not InMemory* doubles:
  PlaybookActionRegistry/PlaybookAction   (src/application/playbook.py)
  TransitionDetectionTriageAction         (src/application/playbook_actions.py)
  LogNotificationAction                   (src/application/playbook_actions.py)
  PlaybookExecutionService                (src/application/playbook_execution.py)
  PostgresDetectionRepository              (src/adapter/repository/postgres_detection.py)
  PostgresAuditLogRepository/AuditLogService

Scenarios:
  (1) Real success run: a real Detection row is created in Postgres, then a
      real two-step Playbook (transition_detection_triage, log_notification)
      is executed against it. Confirm the real Detection row's triage_state
      actually changed in Postgres, every step's real audit row exists with
      correct input/output, and the real hash chain is intact
      (AuditLogService.verify_chain()).
  (2) Real failure run: a playbook step that performs an illegal FSM
      transition halts the remainder of the playbook; confirm this is a
      real, audited PLAYBOOK_STEP_FAILED row, not a silent skip, and that
      the chain is STILL intact afterward (a failure must never corrupt
      the chain).
  (3) "New action = registration, not an edit," proved concretely: both
      TransitionDetectionTriageAction and LogNotificationAction are
      registered into the SAME PlaybookActionRegistry and run through the
      SAME PlaybookExecutionService with zero engine-code differences.

Run: ~/venv/bin/python3 poc/playbook_engine/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_triage import DetectionTriageService  # noqa: E402
from src.application.playbook import PlaybookActionRegistry  # noqa: E402
from src.application.playbook_actions import (  # noqa: E402
    LogNotificationAction,
    TransitionDetectionTriageAction,
)
from src.application.playbook_execution import PlaybookExecutionService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.detection import Detection  # noqa: E402
from src.domain.playbook import Playbook, PlaybookStep  # noqa: E402
from tests.fixtures.factories import make_tenant_context  # noqa: E402

POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


async def _seed_detection(repo: PostgresDetectionRepository, tenant) -> Detection:
    detection = Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        finding_id=f"poc-h1-finding-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-poc-h1-windows-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{uuid.uuid4()}-202608",
        finding_timestamp=datetime.now(UTC),
    )
    return await repo.save(detection)


async def main() -> None:
    engine = create_async_engine(POSTGRES_DSN)
    await PostgresDetectionRepository.create_tables(engine)
    await PostgresAuditLogRepository.create_tables(engine)

    detection_repo = PostgresDetectionRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)
    audit_log = AuditLogService(audit_repo)
    triage_service = DetectionTriageService(detection_repo, audit_log)

    registry = PlaybookActionRegistry()
    registry.register(TransitionDetectionTriageAction(triage_service))
    registry.register(LogNotificationAction())
    execution_service = PlaybookExecutionService(registry, audit_log)

    tenant = make_tenant_context()

    log("=== Scenario 1: real success run against a real Postgres Detection row ===")
    detection = await _seed_detection(detection_repo, tenant)
    log(f"real seeded Detection: detection_id={detection.detection_id} triage_state=NEW")

    playbook = Playbook(
        name="triage-and-notify",
        steps=(
            PlaybookStep(
                step_id="move-to-investigating",
                action_name="transition_detection_triage",
                params={
                    "detection_id": str(detection.detection_id),
                    "target_state": "INVESTIGATING",
                },
            ),
            PlaybookStep(
                step_id="notify",
                action_name="log_notification",
                params={"message": f"Detection {detection.detection_id} moved to INVESTIGATING"},
            ),
        ),
    )
    result = await execution_service.execute(playbook, tenant)
    check("real execution succeeded (both steps ran, no halt)", result.succeeded)
    check("real execution result has exactly 2 step results", len(result.step_results) == 2)
    log(
        f"real step 1 output: {result.step_results[0].output} "
        f"real step 2 output: {result.step_results[1].output}"
    )

    real_stored = await detection_repo.get_by_id(detection.detection_id, tenant.org_id)
    check(
        "real Detection row's triage_state actually changed in Postgres to INVESTIGATING",
        real_stored is not None and real_stored.triage_state.value == "INVESTIGATING",
    )

    events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
    started = [e for e in events if e.event_type == AuditEventType.PLAYBOOK_EXECUTION_STARTED]
    step_executed = [e for e in events if e.event_type == AuditEventType.PLAYBOOK_STEP_EXECUTED]
    completed = [e for e in events if e.event_type == AuditEventType.PLAYBOOK_EXECUTION_COMPLETED]
    check("real PLAYBOOK_EXECUTION_STARTED row exists", len(started) == 1)
    check(
        "real PLAYBOOK_STEP_EXECUTED rows: exactly 2 (one per real step)", len(step_executed) == 2
    )
    check("real PLAYBOOK_EXECUTION_COMPLETED row exists", len(completed) == 1)
    triage_step_event = next(
        e for e in step_executed if e.details["step_id"] == "move-to-investigating"
    )
    check(
        "real step-1 audit row's own recorded output matches what actually happened",
        triage_step_event.details["output"]
        == {
            "detection_id": str(detection.detection_id),
            "triage_state": "INVESTIGATING",
        },
    )
    intact, detail = await audit_log.verify_chain(tenant.org_id)
    check(f"real hash chain intact after success run (detail={detail})", intact)

    log(
        "=== Scenario 2: real failure run halts remaining steps, "
        "still audited, chain still intact ==="
    )
    detection2 = await _seed_detection(detection_repo, tenant)
    bad_playbook = Playbook(
        name="illegal-transition-then-notify",
        steps=(
            PlaybookStep(
                step_id="illegal-jump",
                action_name="transition_detection_triage",
                # NEW -> TRUE_POSITIVE directly is not a legal FSM transition.
                params={
                    "detection_id": str(detection2.detection_id),
                    "target_state": "TRUE_POSITIVE",
                },
            ),
            PlaybookStep(
                step_id="never-runs",
                action_name="log_notification",
                params={"message": "this must never execute"},
            ),
        ),
    )
    bad_result = await execution_service.execute(bad_playbook, tenant)
    check("real failure run halted early", bad_result.halted_early is True)
    check("real failure run did not succeed", bad_result.succeeded is False)
    check(
        "only the failing step ran -- the second step never executed",
        len(bad_result.step_results) == 1,
    )
    log(f"real captured step error: {bad_result.step_results[0].error}")

    still_new = await detection_repo.get_by_id(detection2.detection_id, tenant.org_id)
    check(
        "real Detection row's triage_state is UNCHANGED after the illegal transition (still NEW)",
        still_new is not None and still_new.triage_state.value == "NEW",
    )

    events2 = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
    step_failed = [e for e in events2 if e.event_type == AuditEventType.PLAYBOOK_STEP_FAILED]
    check("real PLAYBOOK_STEP_FAILED row exists for the illegal transition", len(step_failed) >= 1)
    intact2, detail2 = await audit_log.verify_chain(tenant.org_id)
    check(f"real hash chain STILL intact after a failure run (detail={detail2})", intact2)

    log("=== Scenario 3: 'new action = registration, not an edit' proved concretely ===")
    check(
        "both TransitionDetectionTriageAction and LogNotificationAction are registered "
        "in the SAME registry with zero PlaybookExecutionService code differences",
        registry.get_action("transition_detection_triage") is not None
        and registry.get_action("log_notification") is not None,
    )
    # Scenario 1's own playbook already ran BOTH actions through the exact
    # same execution_service instance -- this assertion is the concrete
    # proof, not a separate claim.
    check(
        "scenario 1's single execution already ran both real, independently-registered "
        "actions through the identical PlaybookExecutionService.execute() code path",
        {r.action_name for r in result.step_results}
        == {"transition_detection_triage", "log_notification"},
    )

    await engine.dispose()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against real, live Postgres 16."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
