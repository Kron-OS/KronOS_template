"""Unit tests for audit log HTTP routes."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
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

    def test_unanchored_day_returns_404(self, audit_client):
        """AUDIT-05: a proof for a day that hasn't been anchored yet must 404,
        not silently return an un-validated root."""
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
        assert resp.status_code == 404
        assert "anchored" in resp.json()["detail"]

    def test_single_event_proof_after_anchoring(self, audit_client):
        client, repo, org_id, case_id = audit_client
        import asyncio
        from datetime import date

        target_id = None
        today = date.today()

        async def _add_and_anchor():
            nonlocal target_id
            svc = AuditLogService(repo)
            ev = await svc.log(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                org_id=org_id,
                case_id=case_id,
                details={},
            )
            target_id = ev.event_id
            await svc.anchor_day(today, org_id)

        asyncio.run(_add_and_anchor())

        resp = client.get(f"/api/audit/merkle-proof/{target_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == str(target_id)
        assert data["anchored"] is True
        assert "leaf_hash" in data
        assert "root_hash" in data
        assert isinstance(data["proof"], list)

    def test_tampered_root_after_anchoring_returns_409(self, audit_client):
        """A row_hash mutated after anchoring must fail proof validation."""
        client, repo, org_id, case_id = audit_client
        import asyncio
        from datetime import date

        target_id = None
        today = date.today()

        async def _add_and_anchor():
            nonlocal target_id
            svc = AuditLogService(repo)
            ev = await svc.log(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                org_id=org_id,
                case_id=case_id,
                details={},
            )
            target_id = ev.event_id
            await svc.anchor_day(today, org_id)
            # Tamper the stored row after the anchor was computed.
            tampered = repo._events[0].model_copy(update={"row_hash": "f" * 64})
            repo._events[0] = tampered

        asyncio.run(_add_and_anchor())

        resp = client.get(f"/api/audit/merkle-proof/{target_id}")
        assert resp.status_code == 409
