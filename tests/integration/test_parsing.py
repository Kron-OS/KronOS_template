"""Integration tests for parsing workflow with real parsers and LocalEvidenceStorage.

These tests use LocalEvidenceStorage (no Docker needed) but are marked integration
because they exercise the full orchestration stack end-to-end.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from src.adapter.queue.task_queue import InMemoryTaskQueue
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.parser_registry import ParserRegistry
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceState
from src.external.parsers.cloudtrail import CloudTrailParser
from src.external.parsers.nginx import NginxParser
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence_metadata, make_tenant_context

SAMPLES = Path(__file__).parent.parent / "fixtures" / "samples"

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_repo() -> InMemoryAuditLogRepository:
    return InMemoryAuditLogRepository()


@pytest.fixture
def evidence_repo() -> InMemoryEvidenceRepository:
    return InMemoryEvidenceRepository()


@pytest.fixture
def task_queue() -> InMemoryTaskQueue:
    return InMemoryTaskQueue()


@pytest.fixture
def local_storage(tmp_path: Path) -> LocalEvidenceStorage:
    return LocalEvidenceStorage(base_dir=tmp_path)


@pytest.fixture
def tenant():  # type: ignore[no-untyped-def]
    return make_tenant_context()


def _build_orchestrator(
    evidence_repo: InMemoryEvidenceRepository,
    local_storage: LocalEvidenceStorage,
    audit_repo: InMemoryAuditLogRepository,
    task_queue: InMemoryTaskQueue,
) -> ParsingOrchestrationService:
    registry = ParserRegistry()
    registry.register(CloudTrailParser())
    registry.register(NginxParser())
    return ParsingOrchestrationService(
        evidence_repository=evidence_repo,
        storage=local_storage,
        audit_log=AuditLogService(audit_repo),
        parser_registry=registry,
        task_queue=task_queue,
    )


async def _seed_received(
    evidence_repo: InMemoryEvidenceRepository,
    local_storage: LocalEvidenceStorage,
    tenant,  # type: ignore[no-untyped-def]
    filename: str,
    data: bytes,
) -> Evidence:
    meta = make_evidence_metadata(org_id=tenant.org_id)
    meta = meta.model_copy(update={"original_filename": filename})
    key = f"{meta.org_alias}/{meta.case_id}/{uuid.uuid4()}"
    local_storage.write_evidence(key, data)
    evidence = Evidence(
        metadata=meta,
        state=EvidenceState.RECEIVED,
        sha256="a" * 64,
        minio_evidence_key=key,
    )
    await evidence_repo.save(evidence)
    return evidence


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cloudtrail_full_workflow(
    evidence_repo, local_storage, audit_repo, task_queue, tenant
) -> None:
    """CloudTrail file: start_parsing → execute_parse → COMPLETE."""
    data = (SAMPLES / "cloudtrail.json").read_bytes()
    evidence = await _seed_received(evidence_repo, local_storage, tenant, "cloudtrail.json", data)
    orchestrator = _build_orchestrator(evidence_repo, local_storage, audit_repo, task_queue)

    started = await orchestrator.start_parsing(evidence.evidence_id, tenant)
    assert started.state == EvidenceState.PARSING
    assert len(task_queue.enqueued) == 1

    count = await orchestrator.execute_parse(evidence.evidence_id, tenant)
    assert count == 2

    stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
    assert stored is not None
    assert stored.state == EvidenceState.COMPLETE


@pytest.mark.asyncio
async def test_nginx_full_workflow(
    evidence_repo, local_storage, audit_repo, task_queue, tenant
) -> None:
    """Nginx log file: start_parsing → execute_parse → COMPLETE with 5 records."""
    data = (SAMPLES / "nginx.log").read_bytes()
    evidence = await _seed_received(evidence_repo, local_storage, tenant, "access.log", data)
    orchestrator = _build_orchestrator(evidence_repo, local_storage, audit_repo, task_queue)

    await orchestrator.start_parsing(evidence.evidence_id, tenant)
    count = await orchestrator.execute_parse(evidence.evidence_id, tenant)

    assert count == 5
    stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
    assert stored is not None
    assert stored.state == EvidenceState.COMPLETE


@pytest.mark.asyncio
async def test_audit_events_emitted(
    evidence_repo, local_storage, audit_repo, task_queue, tenant
) -> None:
    """Both PARSE_STARTED and PARSE_COMPLETED should appear in the audit log."""
    data = (SAMPLES / "cloudtrail.json").read_bytes()
    evidence = await _seed_received(evidence_repo, local_storage, tenant, "cloudtrail.json", data)
    orchestrator = _build_orchestrator(evidence_repo, local_storage, audit_repo, task_queue)

    await orchestrator.start_parsing(evidence.evidence_id, tenant)
    await orchestrator.execute_parse(evidence.evidence_id, tenant)

    types = [e.event_type for e in audit_repo.events]
    assert AuditEventType.PARSE_STARTED in types
    assert AuditEventType.PARSE_COMPLETED in types


@pytest.mark.asyncio
async def test_unknown_file_raises_parsing_error(
    evidence_repo, local_storage, audit_repo, task_queue, tenant
) -> None:
    """Unknown binary file not supported by any parser raises ParsingError."""
    from src.exceptions import ParsingError

    data = b"\xff\xfe\x00\x01" * 500
    evidence = await _seed_received(evidence_repo, local_storage, tenant, "unknown.bin", data)
    orchestrator = _build_orchestrator(evidence_repo, local_storage, audit_repo, task_queue)

    with pytest.raises(ParsingError, match="No parser found"):
        await orchestrator.start_parsing(evidence.evidence_id, tenant)


@pytest.mark.asyncio
async def test_cloudtrail_record_count_in_audit_details(
    evidence_repo, local_storage, audit_repo, task_queue, tenant
) -> None:
    """PARSE_COMPLETED audit event should include record_count in details."""
    data = (SAMPLES / "cloudtrail.json").read_bytes()
    evidence = await _seed_received(evidence_repo, local_storage, tenant, "cloudtrail.json", data)
    orchestrator = _build_orchestrator(evidence_repo, local_storage, audit_repo, task_queue)

    await orchestrator.start_parsing(evidence.evidence_id, tenant)
    await orchestrator.execute_parse(evidence.evidence_id, tenant)

    completed = next(e for e in audit_repo.events if e.event_type == AuditEventType.PARSE_COMPLETED)
    assert completed.details.get("record_count") == 2
