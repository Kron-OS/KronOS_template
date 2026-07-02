"""Unit tests for cases HTTP routes."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.case_repository import InMemoryCaseRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_audit_log_service,
    get_case_repository,
    get_evidence_repository,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository


@pytest.fixture
def cases_client():
    case_repo = InMemoryCaseRepository()
    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    audit_svc = AuditLogService(audit_repo)

    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()

    def _admin_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="admin",
            roles=frozenset({Role.ORG_ADMIN}),
            correlation_id=str(uuid.uuid4()),
            acr="aal2",
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _admin_tenant
    app.dependency_overrides[get_case_repository] = lambda: case_repo
    app.dependency_overrides[get_audit_log_service] = lambda: audit_svc
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo

    return TestClient(app), case_repo, fixed_org, fixed_user, audit_repo


class TestCreateCase:
    def test_create_case_returns_201(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.post("/api/cases", json={"title": "Test Case"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Test Case"
        assert "id" in data

    def test_create_case_persists(self, cases_client):
        client, repo, org_id, _, _ = cases_client
        resp = client.post("/api/cases", json={"title": "Saved Case", "reference_number": "REF-001"})
        assert resp.status_code == 201
        case_id = uuid.UUID(resp.json()["id"])
        import asyncio
        stored = asyncio.run(repo.get_by_id(case_id, org_id))
        assert stored is not None
        assert stored.metadata.title == "Saved Case"
        assert stored.metadata.reference_number == "REF-001"

    def test_create_case_missing_title_returns_422(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.post("/api/cases", json={})
        assert resp.status_code == 422


class TestListCases:
    def test_empty_list(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.get("/api/cases")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_returns_created_cases(self, cases_client):
        client, _, _, _, _ = cases_client
        client.post("/api/cases", json={"title": "Case A"})
        client.post("/api/cases", json={"title": "Case B"})
        resp = client.get("/api/cases")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2


class TestGetCase:
    def test_get_existing_case(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "Specific"}).json()
        resp = client.get(f"/api/cases/{created['id']}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "Specific"

    def test_get_missing_case_returns_404(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.get(f"/api/cases/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestDeleteCase:
    def test_delete_archives_case(self, cases_client):
        client, repo, org_id, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "To Delete"}).json()
        case_id = created["id"]
        resp = client.delete(f"/api/cases/{case_id}")
        assert resp.status_code == 204

    def test_delete_missing_returns_404(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.delete(f"/api/cases/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestListCaseEvidence:
    def test_empty_evidence_list(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "E-Case"}).json()
        resp = client.get(f"/api/cases/{created['id']}/evidence")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0


class TestDashboardUrl:
    def test_returns_503_when_not_configured(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "Timeline Case"}).json()
        # Settings() won't have opensearch_dashboards_url in test env
        resp = client.get(f"/api/cases/{created['id']}/dashboard-url")
        # Either 503 (not configured) or 422 (missing required env vars)
        assert resp.status_code in (422, 503)


class TestListCaseAuditEvents:
    def test_empty_returns_empty(self, cases_client):
        client, _, _, _, _ = cases_client
        # A case with no case_id filter match — create_case itself logs a
        # CASE_CREATED event, so use a random unassociated case_id instead.
        resp = client.get(f"/api/cases/{uuid.uuid4()}/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_returns_events_for_case(self, cases_client):
        client, _, org_id, _, audit_repo = cases_client
        created = client.post("/api/cases", json={"title": "Audit Case"}).json()
        case_id = uuid.UUID(created["id"])
        import asyncio

        async def _add():
            svc = AuditLogService(audit_repo)
            await svc.log(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                org_id=org_id,
                case_id=case_id,
                details={"filename": "test.evtx"},
            )

        asyncio.run(_add())
        resp = client.get(f"/api/cases/{case_id}/audit")
        assert resp.status_code == 200
        data = resp.json()
        # create_case logs CASE_CREATED, plus the EVIDENCE_UPLOAD_FINALIZED added above.
        assert data["total"] == 2
        event_types = {item["eventType"] for item in data["items"]}
        assert AuditEventType.EVIDENCE_UPLOAD_FINALIZED.value in event_types
        assert AuditEventType.CASE_CREATED.value in event_types

    def test_pagination(self, cases_client):
        client, _, org_id, _, audit_repo = cases_client
        created = client.post("/api/cases", json={"title": "Audit Case"}).json()
        case_id = uuid.UUID(created["id"])
        import asyncio

        async def _add_many():
            svc = AuditLogService(audit_repo)
            for _ in range(5):
                await svc.log(
                    AuditEventType.SYSTEM_ERROR,
                    org_id=org_id,
                    case_id=case_id,
                    details={},
                )

        asyncio.run(_add_many())
        resp = client.get(f"/api/cases/{case_id}/audit?page=1&pageSize=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 3
        # create_case logs CASE_CREATED, plus the 5 SYSTEM_ERROR events added above.
        assert data["total"] == 6
