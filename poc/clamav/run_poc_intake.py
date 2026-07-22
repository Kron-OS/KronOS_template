"""PoC part 2: real EvidenceIntakeService._run_scan() with a real EICAR
upload through real MinIO and a real ClamAVScanner -- the actual production
call path (finalize_upload -> _run_validation -> _run_scan -> ...), not
just the scanner class in isolation (see run_poc.py for that).

Evidence/audit repos are in-memory here deliberately (already verified
against real Postgres in poc/postgres/ and poc/multi_tenancy/) -- this PoC
is scoped to the scanning integration point, per CLAUDE.md B.5.

Run: source ~/venv/bin/activate && CLAMD_PORT=13310 python poc/clamav/run_poc_intake.py
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))

from fixtures.factories import make_tenant_context  # noqa: E402

from conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.evidence_intake import EvidenceIntakeService  # noqa: E402
from src.application.hashing import HashService  # noqa: E402
from src.application.scanning import ClamAVScanner  # noqa: E402
from src.application.validation import default_validator_chain  # noqa: E402
from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: E402
from src.domain.evidence import EvidenceState  # noqa: E402
from src.domain.user import Role  # noqa: E402
from src.exceptions import ValidationError  # noqa: E402

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CLEAN = b"just a normal forensic log line\n" * 100

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


async def _upload_and_finalize(intake: EvidenceIntakeService, tenant, filename: str, content: bytes):
    ev, presigned = await intake.request_upload(
        filename=filename, content_type="text/plain", size_bytes=len(content),
        case_id=uuid.uuid4(), tenant=tenant,
    )
    import httpx

    put = httpx.put(presigned.url, content=content, timeout=30)
    assert put.status_code == 200, put.text

    sha256 = hashlib.sha256(content).hexdigest()
    try:
        return await intake.finalize_upload(ev.evidence_id, sha256, tenant), None
    except ValidationError as exc:
        return await intake._repo.get_by_id(ev.evidence_id, tenant.org_id), exc


async def main() -> None:
    storage = S3EvidenceStorage(
        endpoint_url="http://localhost:19600",
        access_key="kronos_minio",
        secret_key="kronos_minio_dev_password",
        quarantine_bucket_prefix="kronos-evidence",
        evidence_bucket_prefix="kronos-evidence",
        use_tls=False,
    )
    scanner = ClamAVScanner(host="localhost", port=int(os.environ.get("CLAMD_PORT", "13310")))
    evidence_repo = InMemoryEvidenceRepository()
    audit_svc = AuditLogService(InMemoryAuditLogRepository())
    intake = EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=storage,
        audit_log=audit_svc,
        validator=default_validator_chain(1_073_741_824),
        scanner=scanner,
        hash_service=HashService(),
        max_upload_bytes=1_073_741_824,
    )
    tenant = make_tenant_context(roles={Role.ANALYST})

    print("=== Clean file through the real intake pipeline ===")
    ev, exc = await _upload_and_finalize(intake, tenant, "clean.txt", CLEAN)
    print(f"state={ev.state}, exc={exc}")
    check("clean file reaches RECEIVED (scan passed for real)", ev.state == EvidenceState.RECEIVED)

    print("\n=== Real EICAR through the real intake pipeline ===")
    ev, exc = await _upload_and_finalize(intake, tenant, "eicar.txt", EICAR)
    print(f"state={ev.state}, error_reason={ev.error_reason}, exc={exc}")
    check("EICAR upload is rejected with ValidationError", exc is not None and "infected" in str(exc))
    check("evidence lands in ERROR state", ev.state == EvidenceState.ERROR, str(ev.state))
    check("error_reason records the real threat name", ev.error_reason is not None and "infected" in ev.error_reason, str(ev.error_reason))

    events = [e async for e in audit_svc._repository.stream_by_evidence(ev.evidence_id)]
    event_types = [e.event_type.value for e in events]
    print(f"audit trail for the infected evidence: {event_types}")
    check("real EVIDENCE_SCAN_FAILED audit event logged", "evidence.scan_failed" in event_types)

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


if __name__ == "__main__":
    asyncio.run(main())
