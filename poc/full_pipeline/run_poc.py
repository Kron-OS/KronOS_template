"""PoC: full backend-only, end-to-end evidence lifecycle, autonomous after
finalize, exactly as docs/ingestion-pipeline.md describes:

  finalize_upload (FastAPI) -> _promote() -> enqueue dispatch_parse (Celery q.index)
    -> dispatch_parse -> start_parsing() -> PARSING
      -> parse_artefact_fast -> execute_parse() -> COMPLETE
        -> finalize_evidence -> INGEST_COMPLETED audit event

Uses the REAL FastAPI app (booted via its real production startup path),
a REAL Celery worker process (started separately, see run_poc.sh), real
Postgres/MinIO/OpenSearch/Redis. The one thing NOT re-verified here is
Keycloak JWT parsing -- already thoroughly verified in poc/keycloak/ and
poc/multi_tenancy/ -- so this PoC overrides get_tenant_context to skip
minting a real token and focus on the pipeline mechanics themselves.

Run: source ~/venv/bin/activate && source /tmp/fp_env.sh && python poc/full_pipeline/run_poc.py
(the real Celery worker from run_poc.sh must already be running)
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.dependencies import get_tenant_context  # noqa: E402
from src.external.fastapi_app import create_app  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


ORG_ID = uuid.uuid4()
USER_ID = uuid.uuid4()


def _tenant_override() -> TenantContext:
    return TenantContext(
        org_id=ORG_ID,
        org_alias="pipelineorg",
        user_id=USER_ID,
        username="pipeline-poc-user",
        roles=frozenset({Role.ANALYST, Role.CASE_LEAD}),
        correlation_id=str(uuid.uuid4()),
    )


def main() -> None:
    app = create_app(
        keycloak_issuer="http://unused.invalid/realms/kronos",
        keycloak_audience="kronos-backend",
        keycloak_jwks_url="http://unused.invalid/realms/kronos/protocol/openid-connect/certs",
    )
    app.dependency_overrides[get_tenant_context] = _tenant_override

    with TestClient(app) as client:
        # --- 0. Create a case (real Postgres, via the fixed case_repository wiring) ---
        resp = client.post("/api/cases", json={"title": "Pipeline PoC case", "description": "e2e"})
        print(f"create case -> {resp.status_code}")
        check("case created", resp.status_code == 201)
        case_id = resp.json()["id"]

        # --- 1. Request presigned upload for the real system.evtx sample ---
        sample_path = Path(__file__).resolve().parents[2] / "tests/fixtures/samples/real/system.evtx"
        sample_bytes = sample_path.read_bytes()
        sha256 = hashlib.sha256(sample_bytes).hexdigest()
        print(f"\nsample: {sample_path.name}, {len(sample_bytes)} bytes, sha256={sha256[:16]}...")

        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "system.evtx",
                "contentType": "application/octet-stream",
                "sizeBytes": len(sample_bytes),
                "caseId": case_id,
            },
        )
        print(f"upload/request -> {resp.status_code} {resp.text[:200]}")
        check("upload/request succeeded (real presigned URL from real MinIO)", resp.status_code == 201)
        upload = resp.json()
        evidence_id = upload["evidenceId"]
        presigned_url = upload["presignedUrl"]

        # --- 2. Real PUT of the real bytes to the real presigned MinIO URL ---
        put_resp = httpx.put(presigned_url, content=sample_bytes, timeout=30)
        print(f"\nreal PUT to MinIO presigned URL -> {put_resp.status_code}")
        check("real bytes landed in real MinIO quarantine bucket", put_resp.status_code == 200)

        # --- 3. Finalize (validate -> scan -> hash -> promote -> auto-dispatch) ---
        resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": sha256},
        )
        print(f"\nfinalize -> {resp.status_code} {resp.text[:300]}")
        check("finalize succeeded (validate+scan+hash+promote all passed for real)", resp.status_code == 200)
        if resp.status_code == 200:
            print(f"state after finalize: {resp.json().get('state')}")

        # --- 4. The pipeline should now be FULLY AUTONOMOUS: poll for COMPLETE ---
        # (real Celery worker consuming q.index -> q.parse.fast -> finalize_evidence)
        print("\nwaiting for autonomous pipeline to reach COMPLETE (real Celery worker)...")
        final_state = None
        for i in range(60):
            resp = client.get(f"/api/cases/{case_id}/evidence")
            items = resp.json().get("items", [])
            match = next((e for e in items if e["id"] == evidence_id), None)
            state = match["state"] if match else None
            if state != final_state:
                print(f"  t={i}s state={state}")
                final_state = state
            if state in ("COMPLETE", "ERROR"):
                break
            time.sleep(1)

        check("evidence reached COMPLETE autonomously, no client-side trigger", final_state == "COMPLETE", f"final={final_state}")

    # --- 5. Confirm real records actually landed in real OpenSearch ---
    print("\n=== Verifying real OpenSearch documents ===")
    import opensearchpy

    os_client = opensearchpy.OpenSearch(hosts=[{"host": "localhost", "port": 19500}], use_ssl=False)
    os_client.indices.refresh(index="kronos-*")
    search = os_client.search(index="kronos-*", body={"query": {"term": {"kronos.evidence_id": evidence_id}}})
    hit_count = search["hits"]["total"]["value"]
    print(f"OpenSearch documents with kronos.evidence_id={evidence_id}: {hit_count}")
    check("real EVTX records landed in real OpenSearch", hit_count > 0, f"count={hit_count}")
    if hit_count:
        first = search["hits"]["hits"][0]["_source"]
        check("indexed doc carries correct kronos.case_id", first["kronos"]["case_id"] == case_id)
        check("indexed doc carries evtx-rs as parser", first["kronos"]["parser"] == "evtx-rs", first["kronos"]["parser"])

    # --- 6. Confirm the full real audit trail in real Postgres, hash chain intact ---
    print("\n=== Verifying real Postgres audit trail ===")
    import asyncio as _asyncio

    from sqlalchemy.ext.asyncio import create_async_engine

    from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
    from src.application.audit_log import AuditLogService

    async def _check_audit() -> None:
        engine = create_async_engine("postgresql+asyncpg://kronos:kronos_dev_password@localhost:15435/kronos")
        repo = PostgresAuditLogRepository(engine)
        svc = AuditLogService(repo)
        events = [e async for e in repo.stream_by_evidence(uuid.UUID(evidence_id))]
        types = [e.event_type.value for e in events]
        print(f"audit events for this evidence, in order: {types}")
        check(
            "audit trail includes upload_requested through ingest_completed",
            "evidence.upload_requested" in types and "ingest.completed" in types,
            str(types),
        )
        ok, detail = await svc.verify_chain(ORG_ID)
        check("full org hash chain still verifies intact after real pipeline run", ok, detail or "")
        await engine.dispose()

    _asyncio.run(_check_audit())

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


if __name__ == "__main__":
    main()
