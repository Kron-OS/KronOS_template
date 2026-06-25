"""Unit tests for ParsingOrchestrationService."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.adapter.queue.task_queue import InMemoryTaskQueue
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType
from src.application.parsing_orchestration import ParsingOrchestrationService, _make_document_id
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceState
from src.domain.timeline import KronosProvenance, TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import ParsingError, ValidationError
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence_metadata, make_tenant_context

# ---------------------------------------------------------------------------
# Parser doubles
# ---------------------------------------------------------------------------

_CLOUDTRAIL_BYTES = (
    b'{"Records": [{"eventTime": "2024-01-15T10:30:00Z", "eventName": "Describe",'
    b' "eventSource": "ec2.amazonaws.com",'
    b' "userIdentity": {"userName": "alice", "accountId": "123"}}]}'
)


class _FakeCloudTrailParser(ForensicParser):
    """Minimal parser that accepts JSON with 'Records' and yields 2 records."""

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
        for i in range(2):
            yield TimelineRecord(
                **{
                    "@timestamp": datetime(2024, 1, 15, 10, i, 0, tzinfo=UTC),
                    "event.kind": "event",
                },
                kronos=KronosProvenance(
                    evidence_id=evidence.evidence_id,
                    case_id=evidence.metadata.case_id,
                    org_id=evidence.metadata.org_id,
                    sha256="",
                    parser=self.parser_name,
                    parser_version=self.parser_version,
                    record_index=i,
                    ingest_timestamp=datetime.now(UTC),
                ),
            )


class _HeavyParser(_FakeCloudTrailParser):
    @property
    def parser_name(self) -> str:
        return "heavy-parser"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.HEAVY


class _FailingParser(_FakeCloudTrailParser):
    async def parse(  # type: ignore[override]
        self, stream: AsyncIterator[bytes], evidence: Evidence, tenant: TenantContext
    ) -> AsyncIterator[TimelineRecord]:
        raise RuntimeError("intentional parse error")
        yield  # type: ignore[misc]


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
def local_storage(tmp_path: Path) -> LocalEvidenceStorage:
    return LocalEvidenceStorage(base_dir=tmp_path)


@pytest.fixture
def task_queue() -> InMemoryTaskQueue:
    return InMemoryTaskQueue()


@pytest.fixture
def tenant() -> TenantContext:
    return make_tenant_context()


def _make_orchestrator(
    evidence_repo: InMemoryEvidenceRepository,
    local_storage: LocalEvidenceStorage,
    audit_repo: InMemoryAuditLogRepository,
    task_queue: InMemoryTaskQueue,
    parser: ForensicParser,
) -> ParsingOrchestrationService:
    registry = ParserRegistry()
    registry.register(parser)
    return ParsingOrchestrationService(
        evidence_repository=evidence_repo,
        storage=local_storage,
        audit_log=AuditLogService(audit_repo),
        parser_registry=registry,
        task_queue=task_queue,
    )


async def _seed_received_evidence(
    evidence_repo: InMemoryEvidenceRepository,
    local_storage: LocalEvidenceStorage,
    tenant: TenantContext,
    data: bytes = _CLOUDTRAIL_BYTES,
) -> Evidence:
    """Create evidence in RECEIVED state with file data in the evidence store."""
    meta = make_evidence_metadata(org_id=tenant.org_id)
    evidence_key = f"{meta.org_alias}/{meta.case_id}/{uuid.uuid4()}"
    local_storage.write_evidence(evidence_key, data)
    evidence = Evidence(
        metadata=meta,
        state=EvidenceState.RECEIVED,
        sha256="a" * 64,
        minio_evidence_key=evidence_key,
    )
    await evidence_repo.save(evidence)
    return evidence


# ---------------------------------------------------------------------------
# Tests: start_parsing
# ---------------------------------------------------------------------------


class TestStartParsing:
    @pytest.mark.asyncio
    async def test_start_parsing_transitions_to_parsing(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_received_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        result = await orchestrator.start_parsing(evidence.evidence_id, tenant)
        assert result.state == EvidenceState.PARSING

    @pytest.mark.asyncio
    async def test_start_parsing_enqueues_fast_task(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_received_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        await orchestrator.start_parsing(evidence.evidence_id, tenant)
        assert len(task_queue.enqueued) == 1
        assert task_queue.enqueued[0][0] == "fast"

    @pytest.mark.asyncio
    async def test_start_parsing_enqueues_heavy_task(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_received_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _HeavyParser()
        )
        await orchestrator.start_parsing(evidence.evidence_id, tenant)
        assert len(task_queue.enqueued) == 1
        assert task_queue.enqueued[0][0] == "heavy"

    @pytest.mark.asyncio
    async def test_start_parsing_logs_parse_started(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_received_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        await orchestrator.start_parsing(evidence.evidence_id, tenant)
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.PARSE_STARTED in types

    @pytest.mark.asyncio
    async def test_start_parsing_no_parser_raises(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_received_evidence(evidence_repo, local_storage, tenant)
        registry = ParserRegistry()  # empty — no parser registered
        orchestrator = ParsingOrchestrationService(
            evidence_repository=evidence_repo,
            storage=local_storage,
            audit_log=AuditLogService(audit_repo),
            parser_registry=registry,
            task_queue=task_queue,
        )
        with pytest.raises(ParsingError, match="No parser found"):
            await orchestrator.start_parsing(evidence.evidence_id, tenant)

    @pytest.mark.asyncio
    async def test_start_parsing_wrong_state_raises(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        meta = make_evidence_metadata(org_id=tenant.org_id)
        evidence = Evidence(metadata=meta, state=EvidenceState.UPLOADING)
        await evidence_repo.save(evidence)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        with pytest.raises(ValidationError, match="expected RECEIVED"):
            await orchestrator.start_parsing(evidence.evidence_id, tenant)


# ---------------------------------------------------------------------------
# Tests: execute_parse
# ---------------------------------------------------------------------------


class TestExecuteParse:
    async def _seed_parsing_evidence(
        self,
        evidence_repo: InMemoryEvidenceRepository,
        local_storage: LocalEvidenceStorage,
        tenant: TenantContext,
        data: bytes = _CLOUDTRAIL_BYTES,
    ) -> Evidence:
        evidence_key = f"testorg/case/{uuid.uuid4()}"
        local_storage.write_evidence(evidence_key, data)
        meta = make_evidence_metadata(org_id=tenant.org_id)
        evidence = Evidence(
            metadata=meta,
            state=EvidenceState.PARSING,
            sha256="a" * 64,
            minio_evidence_key=evidence_key,
        )
        await evidence_repo.save(evidence)
        return evidence

    @pytest.mark.asyncio
    async def test_execute_parse_returns_record_count(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        count = await orchestrator.execute_parse(evidence.evidence_id, tenant)
        assert count == 2

    @pytest.mark.asyncio
    async def test_execute_parse_transitions_to_complete(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        await orchestrator.execute_parse(evidence.evidence_id, tenant)
        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.COMPLETE

    @pytest.mark.asyncio
    async def test_execute_parse_logs_parse_completed(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        await orchestrator.execute_parse(evidence.evidence_id, tenant)
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.PARSE_COMPLETED in types
        completed_event = next(
            e for e in audit_repo.events if e.event_type == AuditEventType.PARSE_COMPLETED
        )
        assert completed_event.details.get("record_count") == 2

    @pytest.mark.asyncio
    async def test_execute_parse_transitions_to_error_on_failure(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FailingParser()
        )
        with pytest.raises(ParsingError):
            await orchestrator.execute_parse(evidence.evidence_id, tenant)
        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.ERROR

    @pytest.mark.asyncio
    async def test_execute_parse_logs_parse_failed(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FailingParser()
        )
        with pytest.raises(ParsingError):
            await orchestrator.execute_parse(evidence.evidence_id, tenant)
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.PARSE_FAILED in types

    @pytest.mark.asyncio
    async def test_document_id_is_stable_across_calls(self) -> None:
        eid = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        d1 = _make_document_id(eid, "cloudtrail", 5)
        d2 = _make_document_id(eid, "cloudtrail", 5)
        assert d1 == d2
        assert len(d1) == 40
