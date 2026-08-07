"""L3 chain PoC (roadmap M7/H3, docs/NEXTGEN_SOC_ROADMAP.md):

    real Detection row (Postgres) -> real Playbook step
    (CollectForensicArtifactAction) -> real EvidenceIntakeService
    (request_upload -> real presigned PUT to real MinIO -> start_intake)
    -> real Celery-driven autonomous pipeline (the SAME q.intake/q.index/
    q.parse.fast queues + the SAME already-running docker-celery-worker-1
    the real dev-stack backend uses) -> a real terminal Evidence state
    -> full audit trail (Detection-side + Evidence-side), independently
    re-read from a FRESH Postgres connection, not the one that wrote it.

Honesty note (see src/application/evidence_collection_action.py's own
module docstring for the full reasoning): this platform has no live
remote host-agent/EDR anywhere in src/ (H2 already confirmed this by grep;
re-confirmed again for this item -- see README.md). "Collection" here
means a real, already-staged artifact (a small real Suricata EVE log
bundle already used by C5's own chain PoC,
tests/fixtures/samples/real/suricata/eve.json) entering the real evidence
pipeline with full custody -- NOT a live pull from a remote host, which
does not exist in this codebase and is not fabricated here.

Runs directly against the real, live dev-compose stack from the HOST
(mirrors poc/chain_detect_from_evidence/'s own precedent of driving the
real EvidenceIntakeService/Postgres/MinIO/Celery stack from outside the
containers):
  - Postgres 16       localhost:5432 (docker-postgres-1)
  - MinIO              localhost:9000 (internal ops) /
                        https://kronos.local:9444 (real presigned PUT,
                        same public endpoint a browser client uses)
  - Celery broker/backend  redis://localhost:6379/1 and /2 (the SAME
                        broker docker-celery-worker-1 already consumes --
                        a bare `Celery` client is used here instead of
                        importing src.external.celery_app, which would
                        otherwise require satisfying ~14 unrelated
                        required Settings fields (Keycloak/Vault/
                        OpenSearch secrets) never touched by this task's
                        own send path; the worker-side process_intake/
                        dispatch_parse/parse_artefact_fast tasks that
                        actually run are the REAL, unmodified
                        src/external/celery_app.py task bodies inside the
                        REAL, already-running container -- only the
                        SENDING side here is a bare client).

Run: source ~/venv/bin/activate && python poc/detection_triggered_collection/run_poc.py
Requires the real dev stack up (docker compose -f docker/docker-compose.dev.yml).
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "poc" / "auth_flow"))

import auth_helpers  # noqa: E402
from celery import Celery  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.queue.task_queue import TaskQueue  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository  # noqa: E402
from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.evidence_collection_action import CollectForensicArtifactAction  # noqa: E402
from src.application.evidence_intake import EvidenceIntakeService  # noqa: E402
from src.application.hashing import HashService  # noqa: E402
from src.application.playbook import PlaybookActionRegistry  # noqa: E402
from src.application.playbook_execution import PlaybookExecutionService  # noqa: E402
from src.application.scanning import NoOpScanner  # noqa: E402
from src.application.validation import default_validator_chain  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.detection import Detection  # noqa: E402
from src.domain.evidence import EvidenceState  # noqa: E402
from src.domain.playbook import Playbook, PlaybookStep  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402

POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_PUBLIC_ENDPOINT = "https://kronos.local:9444"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"
ARTIFACT_PATH = REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "suricata" / "eve.json"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" -- {detail}" if detail else ""))


class RealCeleryTaskQueue(TaskQueue):
    """Sends real tasks to the REAL broker docker-celery-worker-1 already
    consumes -- a bare `Celery` client (see module docstring for why this
    is used instead of importing src.external.celery_app/CeleryTaskQueue
    directly from a host-side script)."""

    def __init__(self) -> None:
        self._app = Celery(
            "kronos-poc-h3",
            broker="redis://localhost:6379/1",
            backend="redis://localhost:6379/2",
        )

    async def enqueue_intake(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        result = self._app.send_task(
            "kronos.process_intake",
            kwargs={
                "evidence_id": str(evidence_id),
                "org_id": str(tenant.org_id),
                "user_id": str(tenant.user_id),
            },
            queue="q.intake",
        )
        return result.id

    async def enqueue_dispatch(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        result = self._app.send_task(
            "kronos.dispatch_parse",
            kwargs={
                "evidence_id": str(evidence_id),
                "org_id": str(tenant.org_id),
                "user_id": str(tenant.user_id),
            },
            queue="q.index",
        )
        return result.id

    async def enqueue_parse_fast(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        raise NotImplementedError("not exercised by this PoC -- dispatch_parse picks the queue")

    async def enqueue_parse_heavy(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        raise NotImplementedError("not exercised by this PoC -- dispatch_parse picks the queue")


def make_tenant() -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias=f"h3poc{uuid.uuid4().hex[:8]}",
        user_id=uuid.uuid4(),
        username="h3-poc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


async def main() -> None:
    auth_helpers.trust_dev_stack_step_ca()
    check(
        "real artifact file exists on disk (the honest 'already staged' precondition)",
        ARTIFACT_PATH.is_file(),
        str(ARTIFACT_PATH),
    )

    setup_engine = create_async_engine(POSTGRES_DSN)
    await PostgresDetectionRepository.create_tables(setup_engine)
    await PostgresAuditLogRepository.create_tables(setup_engine)
    await PostgresEvidenceRepository.create_tables(setup_engine)

    detection_repo = PostgresDetectionRepository(setup_engine)
    audit_repo = PostgresAuditLogRepository(setup_engine)
    audit_log = AuditLogService(audit_repo)
    evidence_repo = PostgresEvidenceRepository(setup_engine)

    storage = S3EvidenceStorage(
        endpoint_url=MINIO_ENDPOINT,
        presign_endpoint_url=MINIO_PUBLIC_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        quarantine_bucket_prefix="kronos-evidence",
        evidence_bucket_prefix="kronos-evidence",
        use_tls=False,
    )
    intake = EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=storage,
        audit_log=audit_log,
        # Never invoked from this script -- process_intake (which DOES use
        # a real validator/scanner) runs inside the real celery-worker
        # container's own, separately-DI-wired EvidenceIntakeService
        # instance once this script's start_intake() enqueues the task
        # (see module docstring).
        validator=default_validator_chain(max_upload_bytes=10_000_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=10_000_000,
        task_queue=RealCeleryTaskQueue(),
    )

    tenant = make_tenant()
    case_id = uuid.uuid4()
    log(f"=== real tenant org_id={tenant.org_id} org_alias={tenant.org_alias} case_id={case_id} ===")

    print("\n=== Step 1: real Detection row seeded in Postgres, case-scoped ===")
    detection = Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=case_id,
        finding_id=f"poc-h3-finding-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-h3poc-network-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{case_id}-202608",
        finding_timestamp=datetime.now(UTC),
    )
    detection = await detection_repo.save(detection)
    check("real Detection row persisted", detection.detection_id is not None)
    log(f"detection_id={detection.detection_id} case_id={detection.case_id}")

    print("\n=== Step 2: real Playbook (collect_forensic_artifact step) via PlaybookExecutionService ===")
    registry = PlaybookActionRegistry()
    registry.register(
        CollectForensicArtifactAction(detection_repo, intake, verify=auth_helpers.CA_BUNDLE)
    )
    execution_service = PlaybookExecutionService(registry, audit_log)

    playbook = Playbook(
        name="detection-triggered-collection",
        steps=(
            PlaybookStep(
                step_id="collect-network-logs",
                action_name="collect_forensic_artifact",
                params={
                    "detection_id": str(detection.detection_id),
                    "artifact_path": str(ARTIFACT_PATH),
                    "artifact_label": "logs",
                    "content_type": "application/json",
                    # Deliberately included to prove invariant #3 for real
                    # against the live stack, not just the unit tests:
                    # these must be silently ignored, never trusted.
                    "case_id": str(uuid.uuid4()),
                    "org_id": str(uuid.uuid4()),
                },
            ),
        ),
    )
    result = await execution_service.execute(playbook, tenant)
    check("real playbook execution succeeded (no halt)", result.succeeded)
    output = result.step_results[0].output if result.step_results else None
    check("real step produced output with a new evidence_id", bool(output and output.get("evidence_id")))
    if not output:
        log("FATAL: no step output, cannot continue")
        await setup_engine.dispose()
        sys.exit(1)
    evidence_id = uuid.UUID(output["evidence_id"])
    log(f"real output: {output}")

    check(
        "output case_id is the REAL Detection's case_id, NOT the attacker-supplied one in params",
        output["case_id"] == str(case_id),
        output["case_id"],
    )

    print("\n=== Step 3: poll the REAL Celery-driven autonomous pipeline for a terminal state ===")
    deadline = time.time() + 120
    final_state = None
    while time.time() < deadline:
        ev = await evidence_repo.get_by_id(evidence_id, tenant.org_id)
        state = ev.state.value if ev else "?"
        log(f"poll: evidence_id={evidence_id} state={state}")
        if state in (EvidenceState.COMPLETE.value, EvidenceState.ERROR.value):
            final_state = state
            break
        time.sleep(3)
    check(
        "real evidence reached a real terminal state via the autonomous pipeline (no manual parse/start call)",
        final_state == EvidenceState.COMPLETE.value,
        f"final_state={final_state}",
    )

    print("\n=== Step 4: INDEPENDENT re-verification from a FRESH Postgres connection ===")
    fresh_engine = create_async_engine(POSTGRES_DSN)
    fresh_evidence_repo = PostgresEvidenceRepository(fresh_engine)
    fresh_detection_repo = PostgresDetectionRepository(fresh_engine)
    fresh_audit_repo = PostgresAuditLogRepository(fresh_engine)
    fresh_audit_log = AuditLogService(fresh_audit_repo)

    fresh_evidence = await fresh_evidence_repo.get_by_id(evidence_id, tenant.org_id)
    check("fresh read: Evidence row exists independently of the writing connection", fresh_evidence is not None)
    if fresh_evidence is not None:
        check(
            "fresh read: Evidence.case_id == real Detection.case_id (custody link intact)",
            fresh_evidence.metadata.case_id == case_id,
            str(fresh_evidence.metadata.case_id),
        )
        check(
            "fresh read: Evidence.org_id == the real tenant's org_id (invariant #3, never fabricated)",
            fresh_evidence.metadata.org_id == tenant.org_id,
            str(fresh_evidence.metadata.org_id),
        )
        check(
            "fresh read: Evidence.state is the real terminal COMPLETE",
            fresh_evidence.state == EvidenceState.COMPLETE,
            fresh_evidence.state.value,
        )
        check(
            "fresh read: Evidence.sha256 matches the real artifact's own real bytes",
            fresh_evidence.sha256 == output["sha256"],
        )

    fresh_detection = await fresh_detection_repo.get_by_id(detection.detection_id, tenant.org_id)
    check(
        "fresh read: the triggering Detection is UNCHANGED (invariant #5 -- never mutated)",
        fresh_detection is not None and fresh_detection == detection,
    )

    events = [e async for e in fresh_audit_repo.stream_by_org(tenant.org_id)]
    event_types = [e.event_type for e in events]
    check(
        "fresh read: real PLAYBOOK_EXECUTION_STARTED/STEP_EXECUTED/COMPLETED audit rows exist",
        AuditEventType.PLAYBOOK_EXECUTION_STARTED in event_types
        and AuditEventType.PLAYBOOK_STEP_EXECUTED in event_types
        and AuditEventType.PLAYBOOK_EXECUTION_COMPLETED in event_types,
    )
    check(
        "fresh read: real EVIDENCE_UPLOAD_REQUESTED audit row exists (Evidence-side custody)",
        AuditEventType.EVIDENCE_UPLOAD_REQUESTED in event_types,
    )
    step_event = next(
        (e for e in events if e.event_type == AuditEventType.PLAYBOOK_STEP_EXECUTED), None
    )
    check(
        "fresh read: the playbook step's own audit row links detection_id -> evidence_id coherently",
        step_event is not None
        and step_event.details.get("params", {}).get("detection_id") == str(detection.detection_id)
        and step_event.details.get("output", {}).get("evidence_id") == str(evidence_id),
    )
    intact, detail = await fresh_audit_log.verify_chain(tenant.org_id)
    check(f"fresh read: real audit hash chain intact end-to-end (detail={detail})", intact)

    await setup_engine.dispose()
    await fresh_engine.dispose()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against the real, live dev stack (Postgres 16 + MinIO + the real running Celery worker)."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
