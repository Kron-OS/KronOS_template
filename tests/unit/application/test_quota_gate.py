"""Unit tests for StorageQuotaGate -- the 1.5x hard / 1.0x soft ceiling logic."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.quota import InMemoryOrgQuotaRepository
from src.application.quota_gate import StorageQuotaGate
from src.application.tenant_usage import TenantUsageService
from src.domain.evidence import EvidenceState
from src.domain.quota import OrgQuota
from src.exceptions import StorageError
from tests.conftest import InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence


class _FailingEvidenceRepository(InMemoryEvidenceRepository):
    """Raises StorageError on get_total_size_bytes to simulate a Postgres outage."""

    async def get_total_size_bytes(self, org_id: uuid.UUID) -> int:
        raise StorageError("connection refused", context={"org_id": str(org_id)})


def _make_gate(evidence_repo: InMemoryEvidenceRepository) -> StorageQuotaGate:
    return StorageQuotaGate(InMemoryOrgQuotaRepository(), TenantUsageService(evidence_repo))


@pytest.mark.asyncio
async def test_upload_allowed_when_org_has_no_quota_configured() -> None:
    gate = _make_gate(InMemoryEvidenceRepository())
    decision = await gate.check_upload_allowed(uuid.uuid4(), incoming_size_bytes=10_000)
    assert decision.allowed is True
    assert decision.quota_bytes is None


@pytest.mark.asyncio
async def test_upload_allowed_under_hard_ceiling() -> None:
    org_id = uuid.uuid4()
    evidence_repo = InMemoryEvidenceRepository()
    await evidence_repo.save(
        make_evidence(state=EvidenceState.COMPLETE, org_id=org_id, size_bytes=1_000)
    )
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=2_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))

    # usage=1000, +500 incoming = 1500, hard ceiling = 2000*1.5=3000 -> allowed
    decision = await gate.check_upload_allowed(org_id, incoming_size_bytes=500)
    assert decision.allowed is True
    assert decision.current_usage_bytes == 1_000
    assert decision.quota_bytes == 2_000


@pytest.mark.asyncio
async def test_upload_denied_once_hard_ceiling_would_be_exceeded() -> None:
    org_id = uuid.uuid4()
    evidence_repo = InMemoryEvidenceRepository()
    await evidence_repo.save(
        make_evidence(state=EvidenceState.COMPLETE, org_id=org_id, size_bytes=2_900)
    )
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=2_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))

    # usage=2900, +200 = 3100 > hard ceiling 3000 -> denied
    decision = await gate.check_upload_allowed(org_id, incoming_size_bytes=200)
    assert decision.allowed is False
    assert decision.reason == "storage_hard_ceiling_exceeded"


@pytest.mark.asyncio
async def test_upload_allowed_exactly_at_hard_ceiling_boundary() -> None:
    org_id = uuid.uuid4()
    evidence_repo = InMemoryEvidenceRepository()
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=2_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))

    # 0 usage + 3000 incoming == hard ceiling exactly -> allowed (not exceeded)
    decision = await gate.check_upload_allowed(org_id, incoming_size_bytes=3_000)
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_ingestion_not_held_below_soft_ceiling() -> None:
    org_id = uuid.uuid4()
    evidence_repo = InMemoryEvidenceRepository()
    await evidence_repo.save(
        make_evidence(state=EvidenceState.RECEIVED, org_id=org_id, size_bytes=900)
    )
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=1_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))

    assert await gate.is_ingestion_held(org_id) is False


@pytest.mark.asyncio
async def test_ingestion_held_at_or_above_soft_ceiling() -> None:
    org_id = uuid.uuid4()
    evidence_repo = InMemoryEvidenceRepository()
    await evidence_repo.save(
        make_evidence(state=EvidenceState.RECEIVED, org_id=org_id, size_bytes=1_000)
    )
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=org_id, storage_quota_bytes=1_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))

    # usage == quota exactly -> "at or above" -> held
    assert await gate.is_ingestion_held(org_id) is True


@pytest.mark.asyncio
async def test_ingestion_never_held_when_quota_unlimited() -> None:
    org_id = uuid.uuid4()
    evidence_repo = InMemoryEvidenceRepository()
    await evidence_repo.save(
        make_evidence(state=EvidenceState.RECEIVED, org_id=org_id, size_bytes=10_000_000)
    )
    gate = _make_gate(evidence_repo)
    assert await gate.is_ingestion_held(org_id) is False


@pytest.mark.asyncio
async def test_check_upload_allowed_fails_open_on_storage_error() -> None:
    org_id = uuid.uuid4()
    gate = StorageQuotaGate(
        InMemoryOrgQuotaRepository(), TenantUsageService(_FailingEvidenceRepository())
    )
    decision = await gate.check_upload_allowed(org_id, incoming_size_bytes=100)
    assert decision.allowed is True
    assert decision.reason == "quota_check_unavailable_fail_open"


@pytest.mark.asyncio
async def test_is_ingestion_held_fails_open_on_storage_error() -> None:
    org_id = uuid.uuid4()
    gate = StorageQuotaGate(
        InMemoryOrgQuotaRepository(), TenantUsageService(_FailingEvidenceRepository())
    )
    assert await gate.is_ingestion_held(org_id) is False
