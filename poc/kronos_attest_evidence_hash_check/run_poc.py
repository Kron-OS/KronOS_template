#!/usr/bin/env python3
"""PoC: kronos-attest `case-report --verify-evidence-hashes` (Gap Audit BB1,
follow-on to AA1/P2-5's live-Postgres mode -- docs/GAP_AUDIT_2026-08-18_MILESTONE_AA.md).

Exercises the REAL, unmodified ``kronos_attest.cli`` end to end as a real
subprocess against the real, already-running shared dev stack
(``docker-postgres-1``, ``docker-minio-1``) -- not reimplemented logic, not
mocks of the exact calls under test:

  - Part 1 (read-only): a real existing org/case in the shared dev Postgres
    (``kronos-dev`` / case ``c6284b59-...``) already has a real mix of
    promoted evidence (sha256 + minio_evidence_key set) and un-promoted
    evidence (both still NULL, e.g. a real ClamAV-quarantined upload) --
    demonstrates both the real "verified" outcome and the real
    "not_yet_hashed" outcome from ONE real CLI invocation, without creating
    or touching any new data.
  - Part 2 (throwaway data only): drives a real upload->promote flow via
    ``EvidenceIntakeService`` (same real Postgres, same real MinIO -- no
    separate throwaway Postgres needed this time; the schema drift
    ``poc/evidence_download/`` hit against `quota_held` is confirmed absent
    from the CURRENT shared `evidence` table, checked directly via
    information_schema before writing this script) into a brand-new,
    uniquely-named throwaway org/case, then deliberately corrupts that
    evidence's own real object bytes in MinIO (a second ``PutObject`` to the
    same key -- the evidence bucket has Object Lock enabled, so this lands
    as a new object VERSION, not an overwrite; ``stream_object`` reads
    whichever version is current, so the corrupted bytes are what the real
    CLI's re-hash sees) to produce a real, detected "MISMATCH" -- then
    restores the original correct bytes as a further new version so the
    bucket's current state ends up non-corrupted again. Locked prior
    versions cannot be purged before their retention date -- that IS the
    WORM guarantee working as intended, not a PoC bug (same conclusion
    ``poc/evidence_download/`` already reached and left in its own bucket).

Pinned versions (checked directly, not assumed):
  - Postgres: `postgres:16-alpine`, the real running `docker-postgres-1`
    (`docker inspect docker-postgres-1 --format '{{.Config.Image}}'`).
  - MinIO: `minio/minio:latest`, the real running `docker-minio-1`, creds
    `kronos_minio` / `kronos_minio_dev_password` (confirmed via
    `docker inspect docker-minio-1` env, matching `docker/docker-compose.dev.yml`'s
    `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` defaults).
  - `boto3==1.42.x`/`sqlalchemy==2.0.x`/`asyncpg==0.31.x`/`click==8.4.x` --
    same as `poc/kronos_attest_live_mode/README.md`'s own pinned versions
    (unchanged `pyproject.toml` constraints).

Run: /home/reca/venv/bin/python poc/kronos_attest_evidence_hash_check/run_poc.py
Requires the real, already-running shared dev-stack Postgres+MinIO
(docker-postgres-1, docker-minio-1). Reads real data from an existing
kronos-dev org/case (read-only) and creates+cleans up its own fresh
throwaway org/case/evidence for the corruption demonstration.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

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
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"

# Real, pre-existing org/case in the shared dev Postgres -- found via a
# direct read-only query before writing this script (see the orchestrating
# agent's own transcript for the raw SELECTs): org_alias "kronos-dev",
# case c6284b59-... has 3 real evidence_ids referenced by real audit
# events -- two promoted (sha256 + minio_evidence_key set) and one that
# failed ClamAV scanning (sha256/minio_evidence_key both still NULL, a
# real "not_yet_hashed" state, not fabricated for this PoC).
EXISTING_ORG_ID = "482072f5-8086-4815-be03-879cc2eaecb5"
EXISTING_CASE_ID = "c6284b59-fe95-4b72-8a75-3a3abcc062d2"
EXISTING_EVIDENCE_VERIFIED = {
    "e2d863a9-7043-4186-b9be-1213c87b2d6d",
    "d29734a3-bbff-4d26-bc73-03396b334912",
}
EXISTING_EVIDENCE_NOT_YET_HASHED = {"b384dc58-5213-48b5-a3a8-67c1a1a0fa13"}

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_case_report(org_id: str, case_id: str) -> dict:
    """Real subprocess invocation of the real, installed kronos-attest CLI."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "kronos_attest.cli",
            "case-report",
            "--database-url",
            DATABASE_URL,
            "--org-id",
            org_id,
            "--case-id",
            case_id,
            "--verify-evidence-hashes",
            "--minio-endpoint",
            MINIO_ENDPOINT,
            "--minio-access-key",
            MINIO_ACCESS_KEY,
            "--minio-secret-key",
            MINIO_SECRET_KEY,
            "--minio-use-tls",
            "false",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    print(f"$ kronos-attest case-report ... --case-id {case_id} --verify-evidence-hashes")
    print(proc.stdout)
    if proc.returncode != 0:
        print("STDERR:", proc.stderr, file=sys.stderr)
        raise RuntimeError(f"case-report subprocess failed (exit {proc.returncode})")
    return json.loads(proc.stdout)


async def main_async() -> None:
    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    try:
        print("=" * 78)
        print("PART 1 -- real, pre-existing org/case (read-only): verified + not_yet_hashed")
        print("=" * 78)

        data = run_case_report(EXISTING_ORG_ID, EXISTING_CASE_ID)
        integrity = data.get("evidence_integrity", {})
        check(
            "case-report --verify-evidence-hashes returned evidence_integrity",
            bool(integrity),
            str(list(integrity.keys())),
        )
        for eid in EXISTING_EVIDENCE_VERIFIED:
            entry = integrity.get(eid)
            check(
                f"real pre-existing promoted evidence {eid[:8]}... verified",
                entry is not None and entry["status"] == "verified",
                str(entry),
            )
            if entry is not None and entry["status"] == "verified":
                check(
                    f"  expected_sha256 == computed_sha256 for {eid[:8]}...",
                    entry["expected_sha256"] == entry["computed_sha256"],
                    entry["expected_sha256"],
                )
        for eid in EXISTING_EVIDENCE_NOT_YET_HASHED:
            entry = integrity.get(eid)
            check(
                f"real pre-existing un-promoted evidence {eid[:8]}... -> not_yet_hashed",
                entry is not None and entry["status"] == "not_yet_hashed",
                str(entry),
            )

        print("\n" + "=" * 78)
        print("PART 2 -- fresh throwaway org/case/evidence: real MISMATCH detection")
        print("=" * 78)

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
        org_alias = f"kronos-poc-bb1-{uuid.uuid4().hex[:8]}"
        user_id = uuid.uuid4()
        tenant = TenantContext(
            org_id=org_id,
            org_alias=org_alias,
            user_id=user_id,
            username="poc-bb1-analyst",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

        case = Case(
            org_id=org_id,
            org_alias=org_alias,
            owner_user_id=user_id,
            metadata=CaseMetadata(title="BB1 evidence-hash-check PoC"),
        )
        case = await case_repo.save(case)
        check("fresh throwaway case persisted in real Postgres", case.case_id is not None)

        original_content = (
            b'{"Records": [{"eventID": "'
            + str(uuid.uuid4()).encode()
            + b'", "eventName": "BB1EvidenceHashCheckPoC"}]}'
        )
        original_sha256 = sha256_of(original_content)

        evidence, presigned = await intake.request_upload(
            filename="bb1-poc.json",
            content_type="application/json",
            size_bytes=len(original_content),
            case_id=case.case_id,
            tenant=tenant,
        )
        put_resp = httpx.put(presigned.url, content=original_content, timeout=15.0)
        check(
            "real PUT of original bytes to real MinIO succeeds",
            put_resp.status_code < 300,
            str(put_resp.status_code),
        )

        evidence = await intake.start_intake(evidence.evidence_id, original_sha256, tenant)
        check(
            "real evidence promoted (sha256 + minio_evidence_key set) via real validate->scan->hash->promote",
            evidence.sha256 == original_sha256 and evidence.minio_evidence_key is not None,
            f"state={evidence.state.value} sha256={evidence.sha256}",
        )

        print("\n--- 2a. Real CLI: verified (unmodified real MinIO bytes) ---")
        data = run_case_report(str(org_id), str(case.case_id))
        entry = data["evidence_integrity"].get(str(evidence.evidence_id))
        check(
            "fresh evidence verified BEFORE corruption",
            entry is not None and entry["status"] == "verified",
            str(entry),
        )

        print("\n--- 2b. Deliberately corrupt the real MinIO object bytes ---")
        assert evidence.minio_evidence_key is not None
        bucket = storage.bucket_for(evidence.minio_evidence_key, bucket="evidence")
        corrupted_content = original_content.replace(b"BB1EvidenceHashCheckPoC", b"TAMPERED!!!!!!!!")
        check(
            "corrupted content really differs from the original bytes",
            corrupted_content != original_content,
        )
        # A second PutObject to the SAME key -- since the evidence bucket has
        # Object Lock enabled (S3EvidenceStorage._ensure_bucket), this lands
        # as a new object VERSION, not a true in-place overwrite; a plain GET
        # (no version-id, exactly what stream_object() does) always serves
        # the newest version, so this genuinely changes what the real CLI's
        # re-hash reads.
        boto_client = storage._client  # noqa: SLF001 -- PoC-only direct access, see README
        boto_client.put_object(Bucket=bucket, Key=evidence.minio_evidence_key, Body=corrupted_content)
        print(f"real PutObject (corruption) -> bucket={bucket} key={evidence.minio_evidence_key}")

        print("\n--- 2c. Real CLI: MISMATCH detected against the real corrupted bytes ---")
        data = run_case_report(str(org_id), str(case.case_id))
        entry = data["evidence_integrity"].get(str(evidence.evidence_id))
        check(
            "MISMATCH detected on the real corrupted object",
            entry is not None and entry["status"] == "MISMATCH",
            str(entry),
        )
        if entry is not None:
            check(
                "expected_sha256 (Postgres) != computed_sha256 (real re-hashed MinIO bytes)",
                entry.get("expected_sha256") != entry.get("computed_sha256"),
                f"expected={entry.get('expected_sha256')} computed={entry.get('computed_sha256')}",
            )
            check(
                "computed_sha256 matches a real local hash of the corrupted content",
                entry.get("computed_sha256") == sha256_of(corrupted_content),
            )

        print("\n--- 2d. Restore original bytes (new version; old locked versions survive by WORM design) ---")
        boto_client.put_object(Bucket=bucket, Key=evidence.minio_evidence_key, Body=original_content)
        data = run_case_report(str(org_id), str(case.case_id))
        entry = data["evidence_integrity"].get(str(evidence.evidence_id))
        check(
            "verified again after restoring the original bytes",
            entry is not None and entry["status"] == "verified",
            str(entry),
        )

        print("\n--- 2e. Cleanup: remove throwaway Postgres rows (audit_log left intact, append-only by design) ---")
        deleted_evidence = await evidence_repo.delete_by_id(evidence.evidence_id, org_id)
        deleted_case = await case_repo.delete(case.case_id, org_id)
        check("throwaway evidence row deleted from Postgres", deleted_evidence)
        check("throwaway case row deleted from Postgres", deleted_case)
        print(
            "Note: MinIO object versions for this throwaway bucket "
            f"({bucket}) cannot be purged before their WORM retention date -- "
            "that is the Object Lock guarantee working as intended, matching "
            "poc/evidence_download/'s own prior finding. The bucket's CURRENT "
            "version is the restored, correct content."
        )

        print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
        if FAIL:
            print("FAILURES:", FAIL)
    finally:
        await engine.dispose()

    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main_async())
