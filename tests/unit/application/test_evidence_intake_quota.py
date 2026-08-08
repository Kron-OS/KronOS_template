"""Unit tests for EvidenceIntakeService's quota enforcement hook (request_upload)."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from src.adapter.repository.quota import InMemoryOrgQuotaRepository
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.quota_gate import StorageQuotaGate
from src.application.scanning import NoOpScanner
from src.application.tenant_usage import TenantUsageService
from src.application.validation import default_validator_chain
from src.domain.audit import AuditEventType
from src.domain.evidence import EvidenceState
from src.domain.quota import OrgQuota
from src.exceptions import StorageQuotaExceededError
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence, make_tenant_context


def _make_intake(
    evidence_repo: InMemoryEvidenceRepository,
    audit_repo: InMemoryAuditLogRepository,
    local_storage: LocalEvidenceStorage,
    quota_gate: StorageQuotaGate | None,
) -> EvidenceIntakeService:
    return EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=local_storage,
        audit_log=AuditLogService(audit_repo),
        validator=default_validator_chain(max_upload_bytes=100_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=100_000,
        quota_gate=quota_gate,
    )


@pytest.mark.asyncio
async def test_upload_succeeds_when_no_quota_gate_configured(tmp_path: Path) -> None:
    """Constructing without a quota_gate (existing callers/tests) must keep working."""
    evidence_repo = InMemoryEvidenceRepository()
    audit_repo = InMemoryAuditLogRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    intake = _make_intake(evidence_repo, audit_repo, storage, quota_gate=None)
    tenant = make_tenant_context()

    evidence, _presigned = await intake.request_upload(
        filename="a.json",
        content_type="application/json",
        size_bytes=100,
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    assert evidence.state == EvidenceState.UPLOADING


@pytest.mark.asyncio
async def test_upload_denied_once_quota_hard_ceiling_exceeded(tmp_path: Path) -> None:
    evidence_repo = InMemoryEvidenceRepository()
    audit_repo = InMemoryAuditLogRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    tenant = make_tenant_context()

    # Existing usage already at 2900 bytes; quota=2000 -> hard ceiling=3000.
    await evidence_repo.save(
        make_evidence(state=EvidenceState.COMPLETE, org_id=tenant.org_id, size_bytes=2_900)
    )
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=tenant.org_id, storage_quota_bytes=2_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))
    intake = _make_intake(evidence_repo, audit_repo, storage, quota_gate=gate)

    with pytest.raises(StorageQuotaExceededError) as exc_info:
        await intake.request_upload(
            filename="too_big.json",
            content_type="application/json",
            size_bytes=200,  # 2900+200=3100 > 3000
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
    assert exc_info.value.context["current_usage_bytes"] == 2_900
    assert exc_info.value.context["quota_bytes"] == 2_000

    denied_events = [
        e for e in audit_repo.events if e.event_type == AuditEventType.QUOTA_UPLOAD_DENIED
    ]
    assert len(denied_events) == 1
    assert denied_events[0].org_id == tenant.org_id


@pytest.mark.asyncio
async def test_upload_org_id_comes_from_tenant_context_not_request(tmp_path: Path) -> None:
    """A caller cannot claim a different org's quota headroom -- the quota check
    is always scoped to tenant.org_id, which the route derives from the
    authenticated JWT, never from client-supplied fields."""
    evidence_repo = InMemoryEvidenceRepository()
    audit_repo = InMemoryAuditLogRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    tenant = make_tenant_context()
    other_org = uuid.uuid4()

    # A different org is completely maxed out; tenant's own org has no usage.
    await evidence_repo.save(
        make_evidence(state=EvidenceState.COMPLETE, org_id=other_org, size_bytes=1_000_000)
    )
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=other_org, storage_quota_bytes=100))
    await quota_repo.upsert(OrgQuota(org_id=tenant.org_id, storage_quota_bytes=1_000_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))
    intake = _make_intake(evidence_repo, audit_repo, storage, quota_gate=gate)

    evidence, _ = await intake.request_upload(
        filename="fine.json",
        content_type="application/json",
        size_bytes=100,
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    assert evidence.state == EvidenceState.UPLOADING
