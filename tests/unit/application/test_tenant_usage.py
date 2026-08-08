"""Unit tests for TenantUsageService against InMemoryEvidenceRepository."""

from __future__ import annotations

import uuid

import pytest

from src.application.tenant_usage import TenantUsageService
from src.domain.evidence import EvidenceState
from tests.conftest import InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence


@pytest.mark.asyncio
async def test_usage_is_zero_for_org_with_no_evidence() -> None:
    repo = InMemoryEvidenceRepository()
    usage = TenantUsageService(repo)
    assert await usage.get_current_usage_bytes(uuid.uuid4()) == 0


@pytest.mark.asyncio
async def test_usage_sums_non_purged_evidence_for_org() -> None:
    repo = InMemoryEvidenceRepository()
    org_id = uuid.uuid4()
    other_org_id = uuid.uuid4()

    await repo.save(make_evidence(state=EvidenceState.RECEIVED, org_id=org_id, size_bytes=100))
    await repo.save(make_evidence(state=EvidenceState.COMPLETE, org_id=org_id, size_bytes=250))
    # A different org's evidence must not count toward this org's usage.
    await repo.save(
        make_evidence(state=EvidenceState.RECEIVED, org_id=other_org_id, size_bytes=999)
    )

    usage = TenantUsageService(repo)
    assert await usage.get_current_usage_bytes(org_id) == 350


@pytest.mark.asyncio
async def test_usage_excludes_purged_evidence() -> None:
    repo = InMemoryEvidenceRepository()
    org_id = uuid.uuid4()

    await repo.save(make_evidence(state=EvidenceState.RECEIVED, org_id=org_id, size_bytes=100))
    await repo.save(make_evidence(state=EvidenceState.PURGED, org_id=org_id, size_bytes=5000))

    usage = TenantUsageService(repo)
    assert await usage.get_current_usage_bytes(org_id) == 100
