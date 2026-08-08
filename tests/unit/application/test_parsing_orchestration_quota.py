"""Unit tests for ParsingOrchestrationService's quota enforcement hook (start_parsing)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from src.adapter.queue.task_queue import InMemoryTaskQueue
from src.adapter.repository.quota import InMemoryOrgQuotaRepository
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.application.quota_gate import StorageQuotaGate
from src.application.tenant_usage import TenantUsageService
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceState
from src.domain.quota import OrgQuota
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence_metadata, make_tenant_context

_CLOUDTRAIL_BYTES = b'{"Records": []}'


class _FakeParser(ForensicParser):
    @property
    def parser_name(self) -> str:
        return "cloudtrail"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return b'"Records"' in header_bytes

    async def parse(  # type: ignore[override]
        self, stream: AsyncIterator[bytes], evidence: Evidence, tenant: TenantContext
    ) -> AsyncIterator[TimelineRecord]:
        return
        yield  # pragma: no cover -- makes this an async generator


async def _seed_received_evidence(
    evidence_repo: InMemoryEvidenceRepository,
    local_storage: LocalEvidenceStorage,
    tenant: TenantContext,
    size_bytes: int = 1_000,
) -> Evidence:
    meta = make_evidence_metadata(org_id=tenant.org_id, size_bytes=size_bytes)
    evidence_key = f"{meta.org_alias}/{meta.case_id}/{uuid.uuid4()}"
    local_storage.write_evidence(evidence_key, _CLOUDTRAIL_BYTES)
    evidence = Evidence(
        metadata=meta,
        state=EvidenceState.RECEIVED,
        sha256="a" * 64,
        minio_evidence_key=evidence_key,
    )
    await evidence_repo.save(evidence)
    return evidence


def _make_orchestrator(
    evidence_repo: InMemoryEvidenceRepository,
    local_storage: LocalEvidenceStorage,
    audit_repo: InMemoryAuditLogRepository,
    quota_gate: StorageQuotaGate | None,
) -> ParsingOrchestrationService:
    registry = ParserRegistry()
    registry.register(_FakeParser())
    return ParsingOrchestrationService(
        evidence_repository=evidence_repo,
        storage=local_storage,
        audit_log=AuditLogService(audit_repo),
        parser_registry=registry,
        task_queue=InMemoryTaskQueue(),
        quota_gate=quota_gate,
    )


@pytest.mark.asyncio
async def test_start_parsing_proceeds_when_no_quota_gate_configured(tmp_path: Path) -> None:
    evidence_repo = InMemoryEvidenceRepository()
    audit_repo = InMemoryAuditLogRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    tenant = make_tenant_context()
    evidence = await _seed_received_evidence(evidence_repo, storage, tenant)

    orchestrator = _make_orchestrator(evidence_repo, storage, audit_repo, quota_gate=None)
    result = await orchestrator.start_parsing(evidence.evidence_id, tenant)
    assert result.state == EvidenceState.PARSING


@pytest.mark.asyncio
async def test_start_parsing_held_when_usage_at_soft_ceiling(tmp_path: Path) -> None:
    evidence_repo = InMemoryEvidenceRepository()
    audit_repo = InMemoryAuditLogRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    tenant = make_tenant_context()

    # This evidence's own 1000 bytes already brings usage to the 1000-byte quota.
    evidence = await _seed_received_evidence(evidence_repo, storage, tenant, size_bytes=1_000)
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=tenant.org_id, storage_quota_bytes=1_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))
    orchestrator = _make_orchestrator(evidence_repo, storage, audit_repo, quota_gate=gate)

    result = await orchestrator.start_parsing(evidence.evidence_id, tenant)

    # Held, not COMPLETE and not even PARSING -- stays RECEIVED with the flag set.
    assert result.state == EvidenceState.RECEIVED
    assert result.quota_held is True

    held_events = [
        e for e in audit_repo.events if e.event_type == AuditEventType.QUOTA_INGESTION_HELD
    ]
    assert len(held_events) == 1
    assert held_events[0].evidence_id == evidence.evidence_id


@pytest.mark.asyncio
async def test_start_parsing_does_not_reaudit_already_held_evidence(tmp_path: Path) -> None:
    """Idempotent: a re-dispatch of already-held evidence must not spam audits."""
    evidence_repo = InMemoryEvidenceRepository()
    audit_repo = InMemoryAuditLogRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    tenant = make_tenant_context()

    evidence = await _seed_received_evidence(evidence_repo, storage, tenant, size_bytes=1_000)
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=tenant.org_id, storage_quota_bytes=1_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))
    orchestrator = _make_orchestrator(evidence_repo, storage, audit_repo, quota_gate=gate)

    await orchestrator.start_parsing(evidence.evidence_id, tenant)
    await orchestrator.start_parsing(evidence.evidence_id, tenant)

    held_events = [
        e for e in audit_repo.events if e.event_type == AuditEventType.QUOTA_INGESTION_HELD
    ]
    assert len(held_events) == 1


@pytest.mark.asyncio
async def test_start_parsing_resumes_after_quota_raised(tmp_path: Path) -> None:
    evidence_repo = InMemoryEvidenceRepository()
    audit_repo = InMemoryAuditLogRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    tenant = make_tenant_context()

    evidence = await _seed_received_evidence(evidence_repo, storage, tenant, size_bytes=1_000)
    quota_repo = InMemoryOrgQuotaRepository()
    await quota_repo.upsert(OrgQuota(org_id=tenant.org_id, storage_quota_bytes=1_000))
    gate = StorageQuotaGate(quota_repo, TenantUsageService(evidence_repo))
    orchestrator = _make_orchestrator(evidence_repo, storage, audit_repo, quota_gate=gate)

    held = await orchestrator.start_parsing(evidence.evidence_id, tenant)
    assert held.quota_held is True

    # Admin raises the quota -- usage (1000) now well under the new ceiling.
    await quota_repo.upsert(OrgQuota(org_id=tenant.org_id, storage_quota_bytes=1_000_000))

    resumed = await orchestrator.start_parsing(evidence.evidence_id, tenant)
    assert resumed.state == EvidenceState.PARSING
    assert resumed.quota_held is False

    resumed_events = [
        e for e in audit_repo.events if e.event_type == AuditEventType.QUOTA_INGESTION_RESUMED
    ]
    assert len(resumed_events) == 1
