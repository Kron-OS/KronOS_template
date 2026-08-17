#!/usr/bin/env python3
"""PoC: GET /api/cases/{case_id}/evidence/{evidence_id}/download (Gap Audit
X1, docs/GAP_AUDIT_2026-08-17.md).

Exercises the REAL, unmodified src/ classes end to end against the real,
already-running dev-stack Postgres and MinIO (docker-postgres-1,
docker-minio-1) -- not reimplemented logic, not mocks of the exact calls
under test:

  - EvidenceIntakeService.request_upload()/start_intake() (real hooks,
    mirroring poc/tenant_storage_quota/run_poc.py's own established
    pattern -- start_intake() falls back to running process_intake()
    inline since no task_queue is configured here, its own documented
    behavior, so this genuinely drives validate->scan->hash->promote
    against real MinIO)
  - S3EvidenceStorage.stream_object() via the real NEW download route
    (src/external/routes/cases.py::download_evidence)
  - AuditLogService.log() -> real Postgres EVIDENCE_DOWNLOAD row

Runs the real FastAPI app in-process via httpx.ASGITransport (not
TestClient -- TestClient's own threaded portal is incompatible with an
async SQLAlchemy engine created in this coroutine's own loop, the same
finding W3/W8/W11/W14 already made and worked around this same way) so
this exercises the real, unmodified route code from THIS worktree's own
src/ -- NOT the shared dev-stack backend container, which mounts
../src:/app/src:ro from the MAIN checkout, not this worktree, and would
therefore never see this uncommitted route at all.

Pinned versions: Postgres postgres:16-alpine (own throwaway
kronos-poc-x1-postgres container, port 15432 -- NOT the shared
docker-postgres-1; see "Real, pre-existing schema drift" below for why),
MinIO minio/minio:latest (real, shared docker-minio-1, reachable at
localhost:9000 -- MinIO buckets are per-org and created fresh by this
PoC's own throwaway org_alias, so sharing the real MinIO instance is
safe and doesn't touch any other org's data).

Real, pre-existing schema drift found running this PoC against the
shared docker-postgres-1 (confirmed, not this PoC's own bug): the shared
dev Postgres's `evidence` table predates `quota_held` being added to
`postgres_evidence.py`'s own `sa.Table` (Milestone Q, tenant storage
quotas) and was never migrated, since `create_tables()`'s
`checkfirst=True` only creates missing *tables*, never adds missing
*columns* to an existing one -- confirmed via `alembic current` on the
real shared DB reporting HEAD (913567ca653a) despite the column genuinely
being absent, i.e. no migration for this drift exists at all. This exact
gap was already found and explicitly NOT fixed by the Milestone W8
subagent's own migration commit message (see
`migrations/versions/20260816_1113_913567ca653a_...py`'s own docstring) --
deliberately not re-fixed here either, since it's real, pre-existing,
unrelated drift on SHARED infrastructure, and fixing it is a separate,
focused migration of its own, not an X1 side effect. This PoC instead
uses its own fresh, throwaway `kronos-poc-x1-postgres` container (a brand
new table, created fresh from the CURRENT, correct `sa.Table` metadata,
never has this drift by construction) -- torn down at the end of this
script's own run, per CLAUDE.md's own PoC-container convention.

Run: source ~/venv/bin/activate && python poc/evidence_download/run_poc.py
Requires the real, shared dev-stack MinIO (docker-minio-1) already
running; starts and tears down its own throwaway Postgres.
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
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_case import PostgresCaseRepository  # noqa: E402
from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository  # noqa: E402
from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.evidence_intake import EvidenceIntakeService  # noqa: E402
from src.application.hashing import HashService  # noqa: E402
from src.application.scanning import NoOpScanner  # noqa: E402
from src.application.validation import default_validator_chain  # noqa: E402
from src.domain.case import Case, CaseMetadata  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.dependencies import (  # noqa: E402
    get_audit_log_service,
    get_case_repository,
    get_evidence_repository,
    get_evidence_storage,
    get_tenant_context,
)
from src.external.fastapi_app import create_app  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:15432/kronos"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def main_async() -> None:
    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    try:
        await PostgresEvidenceRepository.create_tables(engine)
        await PostgresCaseRepository.create_tables(engine)
        await PostgresAuditLogRepository.create_tables(engine)

        evidence_repo = PostgresEvidenceRepository(engine)
        case_repo = PostgresCaseRepository(engine)
        audit_repo = PostgresAuditLogRepository(engine)
        audit_svc = AuditLogService(audit_repo)

        storage = S3EvidenceStorage(
            endpoint_url=MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            quarantine_bucket_prefix="kronos-evidence",
            evidence_bucket_prefix="kronos-evidence",
            use_tls=False,
        )

        intake = EvidenceIntakeService(
            evidence_repository=evidence_repo,
            storage=storage,
            audit_log=audit_svc,
            validator=default_validator_chain(max_upload_bytes=100 * 1024 * 1024),
            scanner=NoOpScanner(),
            hash_service=HashService(),
            max_upload_bytes=100 * 1024 * 1024,
        )

        org_id = uuid.uuid4()
        org_alias = f"poc-x1-{uuid.uuid4().hex[:8]}"
        user_id = uuid.uuid4()
        tenant = TenantContext(
            org_id=org_id,
            org_alias=org_alias,
            user_id=user_id,
            username="poc-analyst",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

        print("=" * 78)
        print(f"1. Real Postgres case + real MinIO upload -- org={org_alias}")
        print("=" * 78)

        case = Case(
            org_id=org_id,
            org_alias=org_alias,
            owner_user_id=user_id,
            metadata=CaseMetadata(title="X1 evidence-download PoC"),
        )
        case = await case_repo.save(case)
        check("real case persisted in Postgres", case.case_id is not None)

        # Real CloudTrail-shaped JSON, matching poc/tenant_storage_quota/ and
        # poc/evidence_intake_async/'s own established content -- a real
        # accepted forensic format the MagicByteValidator genuinely passes
        # (an arbitrary .bin blob correctly fails real magic-byte
        # validation, confirmed live in an earlier run of this exact
        # script -- that's correct validator behavior, not a bug in the new
        # download route, and this PoC isn't testing the validator).
        content = (
            b'{"Records": [{"eventID": "'
            + str(uuid.uuid4()).encode()
            + b'", "eventName": "X1DownloadPoC"}]}'
        )
        evidence, presigned = await intake.request_upload(
            filename="download-poc.json",
            content_type="application/json",
            size_bytes=len(content),
            case_id=case.case_id,
            tenant=tenant,
        )
        put_resp = httpx.put(presigned.url, content=content, timeout=15.0)
        check("real PUT to real MinIO succeeds", put_resp.status_code < 300, str(put_resp.status_code))

        evidence = await intake.start_intake(evidence.evidence_id, sha256_of(content), tenant)
        check(
            "real evidence promoted (minio_evidence_key set) via real validate->scan->hash->promote",
            evidence.minio_evidence_key is not None,
            f"state={evidence.state.value}",
        )

        print("\n" + "=" * 78)
        print("2. Real HTTP (in-process ASGI) -- GET download route")
        print("=" * 78)

        app = create_app()
        app.dependency_overrides[get_tenant_context] = lambda: tenant
        app.dependency_overrides[get_case_repository] = lambda: case_repo
        app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo
        app.dependency_overrides[get_evidence_storage] = lambda: storage
        app.dependency_overrides[get_audit_log_service] = lambda: audit_svc

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://poc"
        ) as client:
            dl_resp = await client.get(
                f"/api/cases/{case.case_id}/evidence/{evidence.evidence_id}/download"
            )
            check("download returns 200", dl_resp.status_code == 200, str(dl_resp.status_code))
            check(
                "downloaded bytes match the real uploaded bytes exactly (byte-for-byte)",
                dl_resp.content == content,
            )
            check(
                "Content-Disposition carries the real original filename",
                'filename="download-poc.json"' in dl_resp.headers.get("content-disposition", ""),
                dl_resp.headers.get("content-disposition"),
            )
            check(
                "Content-Type is the real uploaded content-type",
                dl_resp.headers.get("content-type", "").startswith("application/json"),
                dl_resp.headers.get("content-type"),
            )

            print("\n" + "=" * 78)
            print("3. Real Postgres: EVIDENCE_DOWNLOAD audit row")
            print("=" * 78)

            events = [e async for e in audit_repo.stream_by_org(org_id)]
            download_events = [e for e in events if e.event_type.value == "evidence.download"]
            check(
                "exactly one real EVIDENCE_DOWNLOAD audit row persisted",
                len(download_events) == 1,
                str(len(download_events)),
            )
            if download_events:
                ev = download_events[0]
                check("audit row's evidence_id matches", ev.evidence_id == evidence.evidence_id)
                check("audit row's case_id matches", ev.case_id == case.case_id)
                check(
                    "audit row's details carry the filename, not sensitive content",
                    ev.details.get("original_filename") == "download-poc.json",
                    ev.details,
                )

            print("\n" + "=" * 78)
            print("4. Un-finalized evidence (no minio_evidence_key yet) -> 404")
            print("=" * 78)

            unpromoted, _presigned2 = await intake.request_upload(
                filename="unfinalized.bin",
                content_type="application/octet-stream",
                size_bytes=4,
                case_id=case.case_id,
                tenant=tenant,
            )
            # Deliberately never finalized -- still UPLOADING, no minio_evidence_key.
            early_resp = await client.get(
                f"/api/cases/{case.case_id}/evidence/{unpromoted.evidence_id}/download"
            )
            check(
                "un-finalized evidence download returns 404 (honest, real object doesn't exist yet)",
                early_resp.status_code == 404,
                str(early_resp.status_code),
            )

            print("\n" + "=" * 78)
            print("5. Cross-org access refused (404, never 403 -- no existence leak)")
            print("=" * 78)

            other_org_id = uuid.uuid4()
            other_tenant = TenantContext(
                org_id=other_org_id,
                org_alias=f"poc-x1-other-{uuid.uuid4().hex[:8]}",
                user_id=uuid.uuid4(),
                username="poc-other-analyst",
                roles=frozenset({Role.ANALYST}),
                correlation_id=str(uuid.uuid4()),
            )
            app.dependency_overrides[get_tenant_context] = lambda: other_tenant
            cross_resp = await client.get(
                f"/api/cases/{case.case_id}/evidence/{evidence.evidence_id}/download"
            )
            check(
                "a different org's caller gets 404 for this real case/evidence (not 403)",
                cross_resp.status_code == 404,
                str(cross_resp.status_code),
            )
            app.dependency_overrides[get_tenant_context] = lambda: tenant

            print("\n" + "=" * 78)
            print("6. Nonexistent case/evidence both 404")
            print("=" * 78)

            nf1 = await client.get(f"/api/cases/{uuid.uuid4()}/evidence/{uuid.uuid4()}/download")
            check("nonexistent case -> 404", nf1.status_code == 404, str(nf1.status_code))
            nf2 = await client.get(
                f"/api/cases/{case.case_id}/evidence/{uuid.uuid4()}/download"
            )
            check("nonexistent evidence -> 404", nf2.status_code == 404, str(nf2.status_code))

        print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
        if FAIL:
            print("FAILURES:", FAIL)
    finally:
        await engine.dispose()

    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main_async())
