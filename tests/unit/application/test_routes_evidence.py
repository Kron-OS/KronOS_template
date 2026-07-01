"""Unit tests for the evidence HTTP routes via TestClient."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.case_repository import InMemoryCaseRepository
from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.scanning import NoOpScanner
from src.application.validation import default_validator_chain
from src.domain.case import Case, CaseMetadata
from src.domain.evidence import EvidenceState
from src.domain.user import Role, TenantContext
from src.external.dependencies import get_case_repository, get_intake_service, get_tenant_context
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository

_JSON_CONTENT = b'{"Records": []}'
_EVTX_HEADER = b"ElfFile\x00" + b"\x00" * 512


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def app_client(tmp_path: Path):  # type: ignore[no-untyped-def]
    from src.adapter.storage.local import LocalEvidenceStorage

    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    audit_svc = AuditLogService(audit_repo)
    case_repo = InMemoryCaseRepository()

    intake = EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=storage,
        audit_log=audit_svc,
        validator=default_validator_chain(10_000_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=10_000_000,
    )

    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()
    fixed_case_id = uuid.uuid4()

    # Pre-populate a case so request_upload ownership check passes.
    case = Case(
        case_id=fixed_case_id,
        org_id=fixed_org,
        org_alias="testorg",
        owner_user_id=fixed_user,
        metadata=CaseMetadata(title="Test Case"),
    )
    asyncio.run(case_repo.save(case))

    def _fixed_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="testuser",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

    app = create_app()
    app.dependency_overrides[get_intake_service] = lambda: intake
    app.dependency_overrides[get_tenant_context] = _fixed_tenant
    app.dependency_overrides[get_case_repository] = lambda: case_repo

    return TestClient(app), storage, audit_repo, fixed_org, fixed_case_id


class TestRequestUploadRoute:
    def test_returns_201_with_presigned_url(self, app_client) -> None:
        client, _, _, _, case_id = app_client
        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "test.json",
                "contentType": "application/json",
                "sizeBytes": 100,
                "caseId": str(case_id),
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert "evidenceId" in body
        assert "presignedUrl" in body

    def test_invalid_payload_returns_422(self, app_client) -> None:
        client, *_ = app_client
        resp = client.post("/api/evidence/upload/request", json={"filename": ""})
        assert resp.status_code == 422

    def test_unknown_case_returns_404(self, app_client) -> None:
        client, *_ = app_client
        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "test.json",
                "contentType": "application/json",
                "sizeBytes": 100,
                "caseId": str(uuid.uuid4()),  # not in case_repo
            },
        )
        assert resp.status_code == 404


class TestFinalizeUploadRoute:
    def test_happy_path_returns_received(self, app_client) -> None:
        client, storage, _, _, case_id = app_client
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        assert req_resp.status_code == 201
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]

        storage.write_quarantine(object_key, _JSON_CONTENT)

        fin_resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": _sha256(_JSON_CONTENT)},
        )
        assert fin_resp.status_code == 200
        body = fin_resp.json()
        assert body["state"] == EvidenceState.RECEIVED.value
        assert body["sha256"] == _sha256(_JSON_CONTENT)

    def test_hash_mismatch_returns_422(self, app_client) -> None:
        client, storage, _, _, case_id = app_client
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]
        storage.write_quarantine(object_key, _JSON_CONTENT)

        fin_resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": "a" * 64},
        )
        assert fin_resp.status_code == 422

    def test_nonexistent_evidence_returns_422(self, app_client) -> None:
        client, *_ = app_client
        fin_resp = client.post(
            f"/api/evidence/upload/finalize/{uuid.uuid4()}",
            json={"client_sha256": "a" * 64},
        )
        assert fin_resp.status_code == 422
