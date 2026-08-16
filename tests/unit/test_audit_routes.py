"""Unit tests for audit log HTTP routes."""

from __future__ import annotations

import asyncio
import json
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


def _build_client_with_roles(
    roles: frozenset[Role],
) -> tuple[TestClient, InMemoryAuditLogRepository, uuid.UUID]:
    """Like the ``audit_client`` fixture, but with a caller-chosen role set.

    Needed for the export route's role-gate tests (ORG_ADMIN-only) — the
    module fixture above is pinned to Role.ANALYST for the pre-existing
    verify/merkle-proof tests.
    """
    audit_repo = InMemoryAuditLogRepository()
    audit_svc = AuditLogService(audit_repo)
    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()

    def _fixed_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="tester",
            roles=roles,
            correlation_id=str(uuid.uuid4()),
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _fixed_tenant
    app.dependency_overrides[get_audit_log_service] = lambda: audit_svc

    return TestClient(app), audit_repo, fixed_org


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
        from datetime import UTC, datetime

        target_id = None
        # UTC date, not local date.today(): events are stamped occurred_at=
        # datetime.now(UTC) and the route scopes anchors by occurred_at.date()
        # (UTC) -- see src/external/celery_app.py's anchor_audit_log fix.
        today = datetime.now(UTC).date()

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
        from datetime import UTC, datetime

        target_id = None
        today = datetime.now(UTC).date()

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


class TestExportAuditLog:
    """GET /api/audit/export -- full-org export feeding the kronos-attest CLI."""

    _EXPECTED_KEYS = {
        "event_id",
        "event_type",
        "actor_user_id",
        "actor_username",
        "org_id",
        "case_id",
        "evidence_id",
        "details",
        "occurred_at",
        "sequence_number",
        "prev_row_hash",
        "row_hash",
    }

    def test_export_returns_callers_org_events_in_expected_shape(self):
        client, repo, org_id = _build_client_with_roles(frozenset({Role.ORG_ADMIN}))
        case_id = uuid.uuid4()

        async def _seed():
            svc = AuditLogService(repo)
            await svc.log(
                AuditEventType.CASE_CREATED,
                org_id=org_id,
                case_id=case_id,
                actor_username="alice",
                details={"n": 1},
            )
            await svc.log(
                AuditEventType.EVIDENCE_UPLOAD_REQUESTED,
                org_id=org_id,
                case_id=case_id,
                details={"n": 2},
            )

        asyncio.run(_seed())

        resp = client.get("/api/audit/export")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        assert "attachment" in resp.headers["content-disposition"]
        assert "kronos-audit-export-testorg-" in resp.headers["content-disposition"]

        events = json.loads(resp.content)
        assert len(events) == 2
        for ev in events:
            assert set(ev.keys()) == self._EXPECTED_KEYS
            assert ev["org_id"] == str(org_id)
            assert ev["case_id"] == str(case_id)
        assert events[0]["event_type"] == "case.created"
        assert events[0]["actor_username"] == "alice"
        assert events[0]["sequence_number"] == 1
        assert events[1]["event_type"] == "evidence.upload_requested"
        assert events[1]["sequence_number"] == 2
        # row_hash/prev_row_hash present (not stripped) -- required by
        # kronos_attest.verifier.ChainVerifier.
        assert events[0]["prev_row_hash"] is not None
        assert events[0]["row_hash"] is not None

    def test_export_does_not_include_another_orgs_events(self):
        """Tenant isolation: two orgs share the InMemory repo; only the
        caller's org_id should appear in the export."""
        client, repo, org_id = _build_client_with_roles(frozenset({Role.ORG_ADMIN}))
        other_org = uuid.uuid4()

        async def _seed():
            svc = AuditLogService(repo)
            await svc.log(AuditEventType.CASE_CREATED, org_id=org_id, details={})
            await svc.log(AuditEventType.CASE_CREATED, org_id=other_org, details={})
            await svc.log(AuditEventType.CASE_CREATED, org_id=other_org, details={})

        asyncio.run(_seed())

        resp = client.get("/api/audit/export")
        events = json.loads(resp.content)
        assert len(events) == 1
        assert events[0]["org_id"] == str(org_id)
        assert all(e["org_id"] != str(other_org) for e in events)

    def test_non_admin_role_is_rejected_with_403(self):
        client, _repo, _org_id = _build_client_with_roles(frozenset({Role.ANALYST}))
        resp = client.get("/api/audit/export")
        assert resp.status_code == 403

    def test_case_lead_role_is_also_rejected_with_403(self):
        """ORG_ADMIN-only per the route's docstring reasoning -- CASE_LEAD is
        not sufficient for a whole-org export."""
        client, _repo, _org_id = _build_client_with_roles(frozenset({Role.CASE_LEAD}))
        resp = client.get("/api/audit/export")
        assert resp.status_code == 403

    def test_response_body_is_valid_parseable_json_with_matching_count(self):
        client, repo, org_id = _build_client_with_roles(frozenset({Role.ORG_ADMIN}))

        async def _seed():
            svc = AuditLogService(repo)
            for _ in range(5):
                await svc.log(AuditEventType.EVIDENCE_UPLOAD_FINALIZED, org_id=org_id, details={})

        asyncio.run(_seed())

        resp = client.get("/api/audit/export")
        data = json.loads(resp.content)
        assert isinstance(data, list)
        assert len(data) == 5
        assert [e["sequence_number"] for e in data] == [1, 2, 3, 4, 5]

    def test_empty_org_returns_empty_json_array(self):
        client, _repo, _org_id = _build_client_with_roles(frozenset({Role.ORG_ADMIN}))
        resp = client.get("/api/audit/export")
        assert resp.status_code == 200
        assert json.loads(resp.content) == []
