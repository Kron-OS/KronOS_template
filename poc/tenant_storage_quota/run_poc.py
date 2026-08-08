"""PoC: real tenant storage usage/quota enforcement (docs/TENANT_USAGE_QUOTA.md).

Exercises the REAL, unmodified src/ classes end to end against real
Postgres + real MinIO + the real (already-running, shared) dev-stack
OpenSearch, then the REAL Celery task functions from
src/external/celery_app.py -- not reimplemented logic, not mocks of the
exact calls under test:

  - StorageQuotaGate.check_upload_allowed()  (1.5x hard ceiling)
  - StorageQuotaGate.is_ingestion_held()     (1.0x soft ceiling)
  - EvidenceIntakeService.request_upload()   (real hook 1)
  - ParsingOrchestrationService.start_parsing() (real hook 2)
  - auto_resume_quota_held / dispatch_parse / parse_artefact_fast
    (real Celery task bodies, called directly -- same eager-invocation
    idiom poc/celery_beat/run_poc.py already established: real task BODY
    logic under test, not broker dispatch semantics)

Run via run_poc.sh (starts real throwaway Postgres/Redis/MinIO containers,
exports the full env Settings() requires, then runs this).
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402
import redis  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository  # noqa: E402
from src.adapter.repository.postgres_quota import PostgresOrgQuotaRepository  # noqa: E402
from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.evidence_intake import EvidenceIntakeService  # noqa: E402
from src.application.hashing import HashService  # noqa: E402
from src.application.quota_gate import StorageQuotaGate  # noqa: E402
from src.application.scanning import NoOpScanner  # noqa: E402
from src.application.tenant_usage import TenantUsageService  # noqa: E402
from src.application.validation import default_validator_chain  # noqa: E402
from src.config import Settings  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.evidence import EvidenceState  # noqa: E402
from src.domain.quota import OrgQuota  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.exceptions import StorageQuotaExceededError  # noqa: E402
from src.external.startup import wire_dependencies_sync  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cloudtrail_json(padding_to: int) -> bytes:
    """A real CloudTrail-shaped JSON payload CloudTrailParser.supports()/parse()
    actually recognizes, padded with whitespace to an exact real byte count
    so usage-threshold arithmetic in this PoC is exact and easy to verify by
    eye."""
    base = (
        b'{"Records": [{"eventTime": "2024-01-01T00:00:00Z", "eventName": "ConsoleLogin",'
        b' "eventSource": "signin.amazonaws.com",'
        b' "userIdentity": {"userName": "poc-user", "accountId": "111111111111"}}]}'
    )
    assert len(base) <= padding_to, f"base payload ({len(base)}B) exceeds requested size {padding_to}B"
    return base + b" " * (padding_to - len(base))


async def real_upload(
    intake: EvidenceIntakeService,
    tenant: TenantContext,
    case_id: uuid.UUID,
    filename: str,
    content: bytes,
):
    """Drive the REAL EvidenceIntakeService.request_upload() -> a REAL HTTP
    PUT to real MinIO -> start_intake() pipeline. start_intake() falls back
    to running process_intake() inline (its own documented behavior when no
    task_queue is configured), so this genuinely exercises validate -> scan
    -> hash -> promote -> RECEIVED, exactly mirroring the real autonomous
    pipeline minus the FastAPI/Celery transport hops (already verified
    elsewhere, e.g. poc/full_pipeline/).
    """
    evidence, presigned = await intake.request_upload(
        filename=filename,
        content_type="application/json",
        size_bytes=len(content),
        case_id=case_id,
        tenant=tenant,
    )
    resp = httpx.put(presigned.url, content=content, timeout=15.0)
    resp.raise_for_status()
    evidence = await intake.start_intake(evidence.evidence_id, _sha256(content), tenant)
    return evidence


async def phase_1_quota_and_intake(settings: Settings, org_id: uuid.UUID, org_alias: str) -> dict:
    engine = create_async_engine(settings.database_url.get_secret_value())
    evidence_repo = PostgresEvidenceRepository(engine)
    quota_repo = PostgresOrgQuotaRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)
    await PostgresEvidenceRepository.create_tables(engine)
    await PostgresOrgQuotaRepository.create_tables(engine)
    await PostgresAuditLogRepository.create_tables(engine)
    audit_svc = AuditLogService(audit_repo)
    usage_svc = TenantUsageService(evidence_repo)
    quota_gate = StorageQuotaGate(quota_repo, usage_svc)

    storage = S3EvidenceStorage(
        endpoint_url=f"http://{settings.minio_endpoint}",
        access_key=settings.minio_access_key.get_secret_value(),
        secret_key=settings.minio_secret_key.get_secret_value(),
        quarantine_bucket_prefix=settings.minio_quarantine_bucket_prefix,
        evidence_bucket_prefix=settings.minio_evidence_bucket_prefix,
        use_tls=False,
    )

    intake = EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=storage,
        audit_log=audit_svc,
        validator=default_validator_chain(max_upload_bytes=settings.max_upload_bytes),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=settings.max_upload_bytes,
        task_queue=None,  # no queue configured -> start_intake runs process_intake() inline
        quota_gate=quota_gate,
    )

    tenant = TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=uuid.uuid4(),
        username="poc-admin",
        roles=frozenset({Role.ORG_ADMIN}),
        correlation_id=str(uuid.uuid4()),
        acr="aal2",
    )
    case_id = uuid.uuid4()

    print("\n" + "=" * 10, "Step 1: real upload #1 (1000 bytes) via the REAL full intake pipeline", "=" * 10)
    ev1 = await real_upload(intake, tenant, case_id, "seed.json", _cloudtrail_json(1000))
    print(f"real evidence #1: id={ev1.evidence_id} state={ev1.state.value} size_bytes={ev1.metadata.size_bytes}")
    check("evidence #1 reached RECEIVED via the real intake pipeline", ev1.state == EvidenceState.RECEIVED)

    usage_after_1 = await evidence_repo.get_total_size_bytes(org_id)
    print(f"real usage after upload #1 (Postgres SUM via get_total_size_bytes): {usage_after_1} bytes")
    check("usage after upload #1 == 1000 (real Postgres SUM query)", usage_after_1 == 1000, str(usage_after_1))

    print("\n" + "=" * 10, "Step 2: set real quota = 1000 bytes (hard ceiling=1500, soft ceiling=1000)", "=" * 10)
    await quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=1000))
    stored_quota = await quota_repo.get(org_id)
    print(f"real quota row read back from Postgres: storage_quota_bytes={stored_quota.storage_quota_bytes if stored_quota else None}")
    check(
        "quota persisted for real in Postgres",
        stored_quota is not None and stored_quota.storage_quota_bytes == 1000,
    )

    print(
        "\n" + "=" * 10,
        "Step 3: real upload of 600 more bytes (1000+600=1600 > 1500 hard ceiling) -> must be DENIED",
        "=" * 10,
    )
    denied = False
    denial_ctx: dict = {}
    try:
        await real_upload(intake, tenant, case_id, "toobig.json", _cloudtrail_json(600))
    except StorageQuotaExceededError as exc:
        denied = True
        denial_ctx = exc.context
        print(f"real StorageQuotaExceededError raised: {exc}  context={exc.context}")
    check("oversized upload was denied for real (StorageQuotaExceededError raised)", denied)
    check(
        "denial reports the real current_usage_bytes (1000)",
        denial_ctx.get("current_usage_bytes") == 1000,
        str(denial_ctx),
    )
    check(
        "denial reports the real configured quota_bytes (1000)",
        denial_ctx.get("quota_bytes") == 1000,
        str(denial_ctx),
    )

    print(
        "\n" + "=" * 10,
        "Step 4: real upload of 400 more bytes (1000+400=1400 <= 1500 hard ceiling) -> ALLOWED",
        "=" * 10,
    )
    ev2 = await real_upload(intake, tenant, case_id, "allowed.json", _cloudtrail_json(400))
    print(f"real evidence #2: id={ev2.evidence_id} state={ev2.state.value} size_bytes={ev2.metadata.size_bytes}")
    check("evidence #2 (under the hard ceiling) was accepted and reached RECEIVED", ev2.state == EvidenceState.RECEIVED)

    usage_after_2 = await evidence_repo.get_total_size_bytes(org_id)
    print(f"real usage after upload #2: {usage_after_2} bytes (>= quota 1000 -> soft ceiling now crossed)")
    check("usage after upload #2 == 1400 (real Postgres SUM query)", usage_after_2 == 1400, str(usage_after_2))
    is_held_now = await quota_gate.is_ingestion_held(org_id)
    check("StorageQuotaGate.is_ingestion_held() is True now that usage (1400) >= quota (1000)", is_held_now)

    await engine.dispose()
    return {"tenant": tenant, "case_id": case_id, "ev1_id": ev1.evidence_id, "ev2_id": ev2.evidence_id}


def wire_and_check_quota_hold(ctx: dict, org_id: uuid.UUID) -> None:
    """Plain sync top-level code (NOT inside our own asyncio.run()) -- mirrors
    poc/celery_beat/run_poc.py's own documented constraint: wire_dependencies_sync()
    and every Celery task function called below each do their own internal
    asyncio.run(), which cannot nest inside an already-running loop."""
    from src.external.celery_app import dispatch_parse  # noqa: PLC0415

    wire_dependencies_sync()
    print("\nwire_dependencies_sync() completed (real DI container wired exactly as a real Celery worker does)")

    tenant = ctx["tenant"]
    ev2_id = ctx["ev2_id"]

    print(
        "\n" + "=" * 10,
        "Step 5: real dispatch_parse() Celery task on evidence #2 -> must be HELD, not parsed",
        "=" * 10,
    )
    dispatch_parse(evidence_id=str(ev2_id), org_id=str(tenant.org_id), user_id=str(tenant.user_id))


async def verify_held(settings: Settings, org_id: uuid.UUID, ev2_id: uuid.UUID) -> None:
    engine = create_async_engine(settings.database_url.get_secret_value())
    evidence_repo = PostgresEvidenceRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)

    ev2_after = await evidence_repo.get_by_id(ev2_id, org_id)
    print(f"real evidence #2 after dispatch_parse(): state={ev2_after.state.value} quota_held={ev2_after.quota_held}")
    check("evidence #2 did NOT reach COMPLETE while held", ev2_after.state != EvidenceState.COMPLETE)
    check("evidence #2 stayed in RECEIVED (no FSM transition -- see with_quota_held's docstring)", ev2_after.state == EvidenceState.RECEIVED)
    check("evidence #2's real quota_held flag is True in Postgres", ev2_after.quota_held is True)

    held_events = [e async for e in audit_repo.stream_by_org(org_id) if e.event_type == AuditEventType.QUOTA_INGESTION_HELD]
    print(f"real QUOTA_INGESTION_HELD audit events for this org (fresh Postgres read): {len(held_events)}")
    check("exactly one real QUOTA_INGESTION_HELD audit event persisted", len(held_events) == 1, str(len(held_events)))
    if held_events:
        check("the held audit event references evidence #2", held_events[0].evidence_id == ev2_id)

    await engine.dispose()


async def raise_quota(settings: Settings, org_id: uuid.UUID) -> None:
    engine = create_async_engine(settings.database_url.get_secret_value())
    quota_repo = PostgresOrgQuotaRepository(engine)
    print("\n" + "=" * 10, "Step 6: real quota increase (1000 -> 1,000,000 bytes)", "=" * 10)
    await quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=1_000_000))
    stored = await quota_repo.get(org_id)
    print(f"real quota row after PATCH-equivalent update: storage_quota_bytes={stored.storage_quota_bytes}")
    check("raised quota persisted for real in Postgres", stored is not None and stored.storage_quota_bytes == 1_000_000)
    await engine.dispose()


def run_real_auto_resume_and_parse(ctx: dict, settings: Settings) -> None:
    """Plain sync top-level code -- see wire_and_check_quota_hold's docstring
    for why. Calls the REAL Celery task functions directly (eager,
    in-process execution of the real task BODY -- the same idiom
    poc/celery_beat established): auto_resume_quota_held() is the real beat
    task with NO manual state-mutation of its own (it only re-checks
    is_ingestion_held() per held evidence and re-enqueues dispatch_parse via
    a REAL CeleryTaskQueue against the real throwaway Redis broker -- this
    script never calls with_quota_held()/with_state() itself). dispatch_parse()
    and parse_artefact_fast() are the exact same task functions a real
    Celery worker consuming that re-enqueued message would run.
    """
    from src.external.celery_app import (  # noqa: PLC0415
        dispatch_parse,
        parse_artefact_fast,
    )
    from src.external.celery_app import auto_resume_quota_held  # noqa: PLC0415

    tenant = ctx["tenant"]
    ev2_id = ctx["ev2_id"]

    print(
        "\n" + "=" * 10,
        "Step 7: real auto_resume_quota_held() beat task -- NO manual trigger of our own",
        "=" * 10,
    )
    resumed_count = auto_resume_quota_held()
    print(f"auto_resume_quota_held() returned: {resumed_count} candidate(s) re-enqueued")
    check("auto_resume_quota_held() found and re-enqueued exactly evidence #2", resumed_count == 1, str(resumed_count))

    print("\n" + "=" * 10, "Step 7b: confirm the re-enqueue produced a REAL message on the real Redis broker", "=" * 10)
    r = redis.Redis.from_url(settings.celery_broker_url.get_secret_value())
    qlen = r.llen("q.index")
    print(f"real Redis LLEN q.index = {qlen}")
    check("a real dispatch_parse message is sitting on the real broker (q.index)", qlen >= 1, str(qlen))

    # This script does not run a live worker process consuming that queue
    # (see README's "what was not verified" section) -- it instead calls
    # the exact same real task functions directly, the identical body a
    # live worker would execute for that exact message.
    print(
        "\n" + "=" * 10,
        "Step 8: real dispatch_parse() re-check -- usage now under the raised quota -> must RESUME",
        "=" * 10,
    )
    dispatch_parse(evidence_id=str(ev2_id), org_id=str(tenant.org_id), user_id=str(tenant.user_id))

    print("\n" + "=" * 10, "Step 9: real parse_artefact_fast() -- the real CloudTrailParser, real execute_parse()", "=" * 10)
    result = parse_artefact_fast(evidence_id=str(ev2_id), org_id=str(tenant.org_id), user_id=str(tenant.user_id))
    print(f"parse_artefact_fast() returned: {result}")


async def verify_resumed(settings: Settings, org_id: uuid.UUID, ev2_id: uuid.UUID) -> None:
    engine = create_async_engine(settings.database_url.get_secret_value())
    evidence_repo = PostgresEvidenceRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)

    ev2_final = await evidence_repo.get_by_id(ev2_id, org_id)
    print(f"\nreal evidence #2 FINAL state (fresh Postgres read): state={ev2_final.state.value} quota_held={ev2_final.quota_held}")
    check("evidence #2 reached real COMPLETE with NO manual state mutation by this script", ev2_final.state == EvidenceState.COMPLETE)
    check("evidence #2's quota_held flag was cleared on resume", ev2_final.quota_held is False)

    resumed_events = [
        e async for e in audit_repo.stream_by_org(org_id) if e.event_type == AuditEventType.QUOTA_INGESTION_RESUMED
    ]
    print(f"real QUOTA_INGESTION_RESUMED audit events (fresh Postgres read): {len(resumed_events)}")
    check("exactly one real QUOTA_INGESTION_RESUMED audit event persisted", len(resumed_events) == 1, str(len(resumed_events)))

    completed_events = [e async for e in audit_repo.stream_by_org(org_id) if e.event_type == AuditEventType.PARSE_COMPLETED]
    check("a real PARSE_COMPLETED audit event was persisted", len(completed_events) == 1, str(len(completed_events)))

    denied_events = [e async for e in audit_repo.stream_by_org(org_id) if e.event_type == AuditEventType.QUOTA_UPLOAD_DENIED]
    check("the earlier QUOTA_UPLOAD_DENIED event is still present in the org's real audit trail", len(denied_events) == 1)

    updated_events = [e async for e in audit_repo.stream_by_org(org_id) if e.event_type == AuditEventType.QUOTA_UPDATED]
    print(f"(informational) QUOTA_UPDATED events found: {len(updated_events)} (this PoC updates quota_repo directly, not via the admin route, so 0 is expected here)")

    await engine.dispose()


def main() -> None:
    settings = Settings()  # type: ignore[call-arg]
    org_id = uuid.uuid4()
    org_alias = f"pocquota{uuid.uuid4().hex[:8]}"
    print(f"PoC org_id={org_id} org_alias={org_alias}")

    ctx = asyncio.run(phase_1_quota_and_intake(settings, org_id, org_alias))

    wire_and_check_quota_hold(ctx, org_id)
    asyncio.run(verify_held(settings, org_id, ctx["ev2_id"]))

    asyncio.run(raise_quota(settings, org_id))
    run_real_auto_resume_and_parse(ctx, settings)
    asyncio.run(verify_resumed(settings, org_id, ctx["ev2_id"]))

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
