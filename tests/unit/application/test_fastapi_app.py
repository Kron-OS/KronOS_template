"""Unit tests for FastAPI app factory and exception handlers."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.scanning import NoOpScanner
from src.application.validation import default_validator_chain
from src.domain.user import Role, TenantContext
from src.exceptions import AuditLogError, AuthenticationError, AuthorizationError, StorageError
from src.external.dependencies import get_intake_service, get_tenant_context
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository


@pytest.fixture
def base_app(tmp_path: Path):  # type: ignore[no-untyped-def]
    from src.adapter.storage.local import LocalEvidenceStorage

    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    audit_svc = AuditLogService(audit_repo)

    intake = EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=storage,
        audit_log=audit_svc,
        validator=default_validator_chain(10_000_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=10_000_000,
    )

    def _fixed_tenant() -> TenantContext:
        return TenantContext(
            org_id=uuid.uuid4(),
            org_alias="testorg",
            user_id=uuid.uuid4(),
            username="testuser",
            roles=frozenset({Role.ANALYST}),
            correlation_id="test-corr",
        )

    app = create_app()
    app.dependency_overrides[get_intake_service] = lambda: intake
    app.dependency_overrides[get_tenant_context] = _fixed_tenant
    return app


class TestAppFactory:
    def test_app_created_with_correct_title(self, base_app) -> None:
        assert base_app.title == "KronOS"

    def test_evidence_routes_registered(self, base_app) -> None:
        # Verify the upload/request route responds correctly (route is registered).
        client = TestClient(base_app)
        # A POST with missing body returns 422, not 404 — confirms route is mounted.
        resp = client.post("/api/evidence/upload/request", json={})
        assert resp.status_code != 404

    def test_health_evidence_route_returns_404_for_missing(self, base_app) -> None:
        client = TestClient(base_app)
        resp = client.post(
            f"/api/evidence/upload/finalize/{uuid.uuid4()}",
            json={"client_sha256": "a" * 64},
        )
        assert resp.status_code == 422  # evidence not found = ValidationError → 422


class TestExceptionHandlers:
    def test_storage_error_returns_503(self, base_app) -> None:
        from src.external.routes.evidence import router

        @router.get("/test-storage-error")
        async def _err() -> None:
            raise StorageError("disk full")

        client = TestClient(base_app, raise_server_exceptions=False)
        resp = client.get("/api/evidence/test-storage-error")
        assert resp.status_code == 503

    def test_auth_error_returns_401(self, base_app) -> None:
        from src.external.routes.evidence import router

        @router.get("/test-auth-error")
        async def _err() -> None:
            raise AuthenticationError("invalid token")

        client = TestClient(base_app, raise_server_exceptions=False)
        resp = client.get("/api/evidence/test-auth-error")
        assert resp.status_code == 401

    def test_authz_error_returns_403(self, base_app) -> None:
        from src.external.routes.evidence import router

        @router.get("/test-authz-error")
        async def _err() -> None:
            raise AuthorizationError("forbidden")

        client = TestClient(base_app, raise_server_exceptions=False)
        resp = client.get("/api/evidence/test-authz-error")
        assert resp.status_code == 403

    def test_audit_error_returns_500(self, base_app) -> None:
        from src.external.routes.evidence import router

        @router.get("/test-audit-error")
        async def _err() -> None:
            raise AuditLogError("audit db down")

        client = TestClient(base_app, raise_server_exceptions=False)
        resp = client.get("/api/evidence/test-audit-error")
        assert resp.status_code == 500
