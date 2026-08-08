"""Unit tests for the /api/admin/org/quota routes via TestClient."""

from __future__ import annotations

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient

from src.adapter.queue.task_queue import InMemoryTaskQueue
from src.adapter.repository.quota import InMemoryOrgQuotaRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.evidence import EvidenceState
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_audit_log_service,
    get_evidence_repository,
    get_org_quota_repository,
    get_task_queue,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence


@pytest.fixture
def quota_client():  # type: ignore[no-untyped-def]
    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    quota_repo = InMemoryOrgQuotaRepository()
    task_queue = InMemoryTaskQueue()
    fixed_org = uuid.uuid4()

    def _admin_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=uuid.uuid4(),
            username="admin",
            roles=frozenset({Role.ORG_ADMIN}),
            correlation_id=str(uuid.uuid4()),
            acr="aal2",
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _admin_tenant
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo
    app.dependency_overrides[get_org_quota_repository] = lambda: quota_repo
    app.dependency_overrides[get_task_queue] = lambda: task_queue
    app.dependency_overrides[get_audit_log_service] = lambda: AuditLogService(audit_repo)

    return TestClient(app), evidence_repo, quota_repo, audit_repo, task_queue, fixed_org


def test_get_quota_defaults_to_unlimited(quota_client) -> None:  # type: ignore[no-untyped-def]
    client, *_ = quota_client
    resp = client.get("/api/admin/org/quota")
    assert resp.status_code == 200
    body = resp.json()
    assert body["storageQuotaBytes"] is None
    assert body["currentUsageBytes"] == 0


def test_get_quota_reflects_real_usage(quota_client) -> None:  # type: ignore[no-untyped-def]
    client, evidence_repo, _quota_repo, _audit_repo, _task_queue, org_id = quota_client
    asyncio.run(
        evidence_repo.save(
            make_evidence(state=EvidenceState.RECEIVED, org_id=org_id, size_bytes=555)
        )
    )
    resp = client.get("/api/admin/org/quota")
    assert resp.status_code == 200
    assert resp.json()["currentUsageBytes"] == 555


def test_patch_quota_persists_and_audits(quota_client) -> None:  # type: ignore[no-untyped-def]
    client, _evidence_repo, quota_repo, audit_repo, _task_queue, org_id = quota_client
    resp = client.patch("/api/admin/org/quota", json={"storageQuotaBytes": 5_000_000})
    assert resp.status_code == 200
    assert resp.json()["storageQuotaBytes"] == 5_000_000

    stored = asyncio.run(quota_repo.get(org_id))
    assert stored is not None
    assert stored.storage_quota_bytes == 5_000_000

    updated_events = [e for e in audit_repo.events if e.event_type == AuditEventType.QUOTA_UPDATED]
    assert len(updated_events) == 1
    assert updated_events[0].org_id == org_id


def test_patch_quota_resumes_held_evidence_immediately(quota_client) -> None:  # type: ignore[no-untyped-def]
    client, evidence_repo, quota_repo, _audit_repo, task_queue, org_id = quota_client
    from src.domain.quota import OrgQuota

    # Seed a held evidence row (usage already at the old, low quota).
    held = make_evidence(
        state=EvidenceState.RECEIVED, org_id=org_id, size_bytes=1_000
    ).with_quota_held(True)
    asyncio.run(evidence_repo.save(held))
    asyncio.run(quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=1_000)))

    resp = client.patch("/api/admin/org/quota", json={"storageQuotaBytes": 1_000_000})
    assert resp.status_code == 200

    # The route's direct-trigger resume must have enqueued dispatch_parse
    # for the held evidence without waiting for the beat sweep.
    dispatches = [e for e in task_queue.enqueued if e[0] == "dispatch"]
    assert len(dispatches) == 1
    assert dispatches[0][1] == held.evidence_id


def test_patch_quota_requires_org_admin(quota_client) -> None:  # type: ignore[no-untyped-def]
    client, *_rest, org_id = quota_client
    app = client.app
    from src.external.dependencies import get_tenant_context as _get_tc

    def _analyst_tenant() -> TenantContext:
        return TenantContext(
            org_id=org_id,
            org_alias="testorg",
            user_id=uuid.uuid4(),
            username="analyst",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
            acr="aal2",
        )

    app.dependency_overrides[_get_tc] = _analyst_tenant
    resp = client.patch("/api/admin/org/quota", json={"storageQuotaBytes": 100})
    assert resp.status_code == 403
