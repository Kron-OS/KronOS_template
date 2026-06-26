"""Unit tests for audit log HTTP routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.user import Role, TenantContext
from src.external.dependencies import get_audit_log_service, get_tenant_context
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository


@pytest.fixture
def audit_client():
    audit_repo = InMemoryAuditLogRepository()
    audit_svc = AuditLogService(audit_repo)
    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()
    fixed_case = uuid.uuid4()

    def _fixed_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="tester",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _fixed_tenant
    app.dependency_overrides[get_audit_log_service] = lambda: audit_svc

    return TestClient(app), audit_repo, fixed_org, fixed_case


class TestListAuditEvents:
    def test_empty_returns_empty(self, audit_client):
        client, _, _, case_id = audit_client
        resp = client.get(f"/api/audit/cases/{case_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_returns_events_for_case(self, audit_client):
        client, repo, org_id, case_id = audit_client
        import asyncio

        async def _add():
            svc = AuditLogService(repo)
            await svc.log(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                org_id=org_id,
                case_id=case_id,
                details={"filename": "test.evtx"},
            )

        asyncio.run(_add())
        resp = client.get(f"/api/audit/cases/{case_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["event_type"] == AuditEventType.EVIDENCE_UPLOAD_FINALIZED.value

    def test_pagination(self, audit_client):
        client, repo, org_id, case_id = audit_client
        import asyncio

        async def _add_many():
            svc = AuditLogService(repo)
            for _ in range(5):
                await svc.log(
                    AuditEventType.SYSTEM_ERROR,
                    org_id=org_id,
                    case_id=case_id,
                    details={},
                )

        asyncio.run(_add_many())
        resp = client.get(f"/api/audit/cases/{case_id}?page=1&page_size=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 3
        assert data["total"] == 5


class TestVerifyChain:
    def test_empty_chain_is_valid(self, audit_client):
        client, _, org_id, _ = audit_client
        resp = client.get(f"/api/audit/cases/{org_id}/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True


class TestMerkleProof:
    def test_event_not_found_returns_404(self, audit_client):
        client, _, _, _ = audit_client
        missing = uuid.uuid4()
        resp = client.get(f"/api/audit/merkle-proof/{missing}")
        assert resp.status_code == 404

    def test_single_event_proof(self, audit_client):
        client, repo, org_id, case_id = audit_client
        import asyncio

        target_id = None

        async def _add():
            nonlocal target_id
            svc = AuditLogService(repo)
            ev = await svc.log(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                org_id=org_id,
                case_id=case_id,
                details={},
            )
            target_id = ev.event_id

        asyncio.run(_add())

        resp = client.get(f"/api/audit/merkle-proof/{target_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == str(target_id)
        assert "leaf_hash" in data
        assert "root_hash" in data
        assert isinstance(data["proof"], list)
