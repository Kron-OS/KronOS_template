"""Unit tests for ParsingOrchestrationService."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.adapter.opensearch.client import InMemoryOpenSearchClient
from src.adapter.queue.task_queue import InMemoryTaskQueue
from src.adapter.repository.asset import InMemoryAssetRepository
from src.adapter.repository.ioc_feed import InMemoryIOCFeedRepository
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.asset_enrichment import AssetContextEnricher
from src.application.audit_log import AuditLogService
from src.application.enrichment import EnrichmentPipeline
from src.application.ioc_enrichment import IOCMatchEnricher
from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType
from src.application.parsing_orchestration import ParsingOrchestrationService, _make_document_id
from src.application.timeline_ingest import TimelineIngestionService
from src.application.yara_rules import yara_scan_org_var
from src.domain.artifact import StructuredArtifact
from src.domain.asset import Asset
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceState
from src.domain.ioc_feed import IOCFeedVersion, IOCIndicator, IOCType
from src.domain.timeline import KronosProvenance, TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import EvidenceStateConflictError, ParsingError
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


class _OrgContextCapturingParser(_FakeCloudTrailParser):
    """Records yara_scan_org_var's value observed inside extract_artifacts(),
    without yielding any artifact -- used to prove ParsingOrchestrationService
    binds the org context (roadmap E4) around its extract_artifacts() call,
    without requiring any change to ZipArchiveParser/TarArchiveParser
    themselves (see src/application/yara_rules.py's module docstring)."""

    def __init__(self) -> None:
        self.observed_org_ids: list[uuid.UUID | None] = []

    async def extract_artifacts(  # type: ignore[override]
        self, stream: AsyncIterator[bytes], evidence: Evidence, tenant: TenantContext
    ) -> AsyncIterator[StructuredArtifact]:
        self.observed_org_ids.append(yara_scan_org_var.get())
        return
        yield  # pragma: no cover -- makes this an async generator


class _HostNamedParser(_FakeCloudTrailParser):
    """Yields one record with a real host_name set (roadmap F1 enrichment
    test needs a first-class ECS field to match an Asset against)."""

    def __init__(self, host_name: str) -> None:
        self._host_name = host_name

    async def parse(  # type: ignore[override]
        self, stream: AsyncIterator[bytes], evidence: Evidence, tenant: TenantContext
    ) -> AsyncIterator[TimelineRecord]:
        yield TimelineRecord(
            **{"@timestamp": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), "event.kind": "event"},
            host_name=self._host_name,
            kronos=KronosProvenance(
                evidence_id=evidence.evidence_id,
                case_id=evidence.metadata.case_id,
                org_id=evidence.metadata.org_id,
                sha256="",
                parser=self.parser_name,
                parser_version=self.parser_version,
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )


class _SourceIpParser(_FakeCloudTrailParser):
    """Yields one record with a real extra["source.ip"] set (roadmap F2
    enrichment test needs a real, currently-matchable field for
    IOCMatchEnricher to check)."""

    def __init__(self, source_ip: str) -> None:
        self._source_ip = source_ip

    async def parse(  # type: ignore[override]
        self, stream: AsyncIterator[bytes], evidence: Evidence, tenant: TenantContext
    ) -> AsyncIterator[TimelineRecord]:
        yield TimelineRecord(
            **{"@timestamp": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), "event.kind": "event"},
            extra={"source.ip": self._source_ip},
            kronos=KronosProvenance(
                evidence_id=evidence.evidence_id,
                case_id=evidence.metadata.case_id,
                org_id=evidence.metadata.org_id,
                sha256="",
                parser=self.parser_name,
                parser_version=self.parser_version,
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )


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
    async def test_start_parsing_no_parser_transitions_to_error(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        # dispatch_parse (celery_app.py) has no exception handling of its own
        # — without persisting ERROR here, a "no parser found" failure left
        # the evidence stuck in RECEIVED forever with no audit trail, even
        # though the Celery task itself crashed and got logged.
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

        persisted = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert persisted is not None
        assert persisted.state == EvidenceState.ERROR
        assert persisted.error_reason == "no_parser_found"
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.PARSE_FAILED in types

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
        with pytest.raises(EvidenceStateConflictError, match="expected RECEIVED"):
            await orchestrator.start_parsing(evidence.evidence_id, tenant)


# ---------------------------------------------------------------------------
# Tests: retry_parse
# ---------------------------------------------------------------------------


async def _seed_parse_error_evidence(
    evidence_repo: InMemoryEvidenceRepository,
    local_storage: LocalEvidenceStorage,
    tenant: TenantContext,
    error_reason: str = "ingest_failed",
    data: bytes = _CLOUDTRAIL_BYTES,
) -> Evidence:
    """Create ERROR evidence with a parse-stage reason, object still in the
    evidence bucket (intake already succeeded; only parsing/indexing failed)."""
    meta = make_evidence_metadata(org_id=tenant.org_id)
    evidence_key = f"{meta.org_alias}/{meta.case_id}/{uuid.uuid4()}"
    local_storage.write_evidence(evidence_key, data)
    evidence = Evidence(
        metadata=meta,
        state=EvidenceState.PARSING,
        sha256="a" * 64,
        minio_evidence_key=evidence_key,
    ).with_error(error_reason)
    await evidence_repo.save(evidence)
    return evidence


class TestRetryParse:
    @pytest.mark.asyncio
    async def test_retry_parse_transitions_to_parsing(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_parse_error_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        result = await orchestrator.retry_parse(evidence.evidence_id, tenant)
        assert result.state == EvidenceState.PARSING
        assert result.error_reason is None

    @pytest.mark.asyncio
    async def test_retry_parse_enqueues_fast_task(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_parse_error_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        await orchestrator.retry_parse(evidence.evidence_id, tenant)
        assert len(task_queue.enqueued) == 1
        assert task_queue.enqueued[0][0] == "fast"

    @pytest.mark.asyncio
    async def test_retry_parse_enqueues_heavy_task(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_parse_error_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _HeavyParser()
        )
        await orchestrator.retry_parse(evidence.evidence_id, tenant)
        assert len(task_queue.enqueued) == 1
        assert task_queue.enqueued[0][0] == "heavy"

    @pytest.mark.asyncio
    async def test_retry_parse_logs_parse_started_with_retry_flag(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_parse_error_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        await orchestrator.retry_parse(evidence.evidence_id, tenant)
        started = next(e for e in audit_repo.events if e.event_type == AuditEventType.PARSE_STARTED)
        assert started.details.get("retry") is True

    @pytest.mark.asyncio
    async def test_retry_parse_wrong_state_raises(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await _seed_received_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        with pytest.raises(EvidenceStateConflictError, match="expected ERROR"):
            await orchestrator.retry_parse(evidence.evidence_id, tenant)

    @pytest.mark.asyncio
    async def test_retry_parse_end_to_end_reaches_complete(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        """Full loop: ERROR (parse-stage) -> retry_parse -> PARSING ->
        execute_parse (simulating the re-enqueued Celery task) -> COMPLETE,
        against the same still-promoted evidence-bucket object -- no
        re-upload, no re-scan."""
        evidence = await _seed_parse_error_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FakeCloudTrailParser()
        )
        await orchestrator.retry_parse(evidence.evidence_id, tenant)
        count = await orchestrator.execute_parse(evidence.evidence_id, tenant)
        assert count == 2
        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.COMPLETE


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
    async def test_execute_parse_non_final_attempt_leaves_evidence_parsing(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        """Regression: a Celery retry re-runs execute_parse with the evidence
        still in PARSING (its own precondition). If a non-final failure
        transitioned evidence to the terminal ERROR state, that retry would
        immediately blow up with EvidenceStateConflictError instead of trying
        again — turning a transient failure (e.g. OpenSearch briefly
        returning 503 right after stack startup) into a permanently stuck,
        confusingly-logged evidence. Non-final attempts must leave evidence
        in PARSING so the retry's state check still passes.
        """
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FailingParser()
        )
        with pytest.raises(ParsingError):
            await orchestrator.execute_parse(evidence.evidence_id, tenant, is_final_attempt=False)
        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.PARSING
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.PARSE_FAILED not in types

    @pytest.mark.asyncio
    async def test_execute_parse_final_attempt_transitions_to_error(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, _FailingParser()
        )
        with pytest.raises(ParsingError):
            await orchestrator.execute_parse(evidence.evidence_id, tenant, is_final_attempt=True)
        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.ERROR
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.PARSE_FAILED in types

    @pytest.mark.asyncio
    async def test_indexes_under_evidence_org_alias_not_task_placeholder(
        self, evidence_repo, local_storage, audit_repo, task_queue
    ) -> None:
        """Records must route to the evidence's real per-tenant index.

        The Celery parse task rebuilds a tenant with org_alias="system" (its
        payload carries only org_id/user_id). Without reconciliation, every
        org's evidence landed in a single kronos-system-case-* index. The
        authoritative alias is on the immutable evidence metadata; execute_parse
        must use it so records route to kronos-<realorg>-case-*.
        """
        from src.adapter.opensearch.client import InMemoryOpenSearchClient
        from src.application.timeline_ingest import TimelineIngestionService
        from src.domain.evidence import EvidenceMetadata
        from src.domain.user import Role

        org_id = uuid.uuid4()
        # Evidence captured at upload for org "acmecorp".
        evidence_key = f"acmecorp/case/{uuid.uuid4()}"
        local_storage.write_evidence(evidence_key, _CLOUDTRAIL_BYTES)
        meta = EvidenceMetadata(
            original_filename="trail.json",
            content_type="application/json",
            size_bytes=len(_CLOUDTRAIL_BYTES),
            uploader_user_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=org_id,
            org_alias="acmecorp",
        )
        evidence = Evidence(
            metadata=meta,
            state=EvidenceState.PARSING,
            sha256="a" * 64,
            minio_evidence_key=evidence_key,
        )
        await evidence_repo.save(evidence)

        # The task-built tenant: same org_id, but the placeholder alias.
        task_tenant = TenantContext(
            org_id=org_id,
            org_alias="system",
            user_id=uuid.uuid4(),
            username="celery-worker",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

        opensearch = InMemoryOpenSearchClient()
        ingest = TimelineIngestionService(opensearch, AuditLogService(audit_repo))
        registry = ParserRegistry()
        registry.register(_FakeCloudTrailParser())
        orchestrator = ParsingOrchestrationService(
            evidence_repository=evidence_repo,
            storage=local_storage,
            audit_log=AuditLogService(audit_repo),
            parser_registry=registry,
            task_queue=task_queue,
            timeline_ingest=ingest,
        )

        await orchestrator.execute_parse(evidence.evidence_id, task_tenant)

        indices = opensearch.all_indices()
        assert indices, "no documents were indexed"
        assert all(idx.startswith("kronos-acmecorp-case-") for idx in indices), indices
        assert not any("system" in idx for idx in indices)

    @pytest.mark.asyncio
    async def test_yara_scan_org_var_bound_around_extract_artifacts(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        """Roadmap E4: ParsingOrchestrationService must bind yara_scan_org_var
        to the tenant's org_id for the duration of extract_artifacts(), and
        reset it afterward -- the mechanism SignedYaraRulePackProvider relies
        on since get_rule_source() itself takes no tenant argument."""
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        parser = _OrgContextCapturingParser()
        orchestrator = _make_orchestrator(
            evidence_repo, local_storage, audit_repo, task_queue, parser
        )

        assert yara_scan_org_var.get() is None
        await orchestrator.execute_parse(evidence.evidence_id, tenant)

        assert parser.observed_org_ids == [tenant.org_id]
        assert yara_scan_org_var.get() is None  # reset after the call, no leakage

    @pytest.mark.asyncio
    async def test_enrichment_pipeline_applies_real_derived_fields_before_indexing(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        """Roadmap F1: an EnrichmentPipeline configured on the orchestrator
        must run before indexing, attaching real derived enrichment.asset.*
        fields for a record whose host_name matches a real seeded Asset --
        end to end through the real TimelineIngestionService/
        InMemoryOpenSearchClient, not just the pipeline in isolation."""
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        asset_repo = InMemoryAssetRepository()
        await asset_repo.upsert(
            Asset(org_id=tenant.org_id, hostname="WIN-DC01", criticality="critical", owner="secops")
        )
        pipeline = EnrichmentPipeline([AssetContextEnricher(asset_repo)])
        opensearch = InMemoryOpenSearchClient()
        ingest = TimelineIngestionService(opensearch, AuditLogService(audit_repo))
        registry = ParserRegistry()
        registry.register(_HostNamedParser("WIN-DC01"))
        orchestrator = ParsingOrchestrationService(
            evidence_repository=evidence_repo,
            storage=local_storage,
            audit_log=AuditLogService(audit_repo),
            parser_registry=registry,
            task_queue=task_queue,
            timeline_ingest=ingest,
            enrichment_pipeline=pipeline,
        )

        await orchestrator.execute_parse(evidence.evidence_id, tenant)

        docs = [
            d for idx in opensearch.all_indices() for d in opensearch.get_documents(idx).values()
        ]
        assert len(docs) == 1
        assert docs[0]["enrichment"]["asset"]["criticality"] == "critical"
        assert docs[0]["enrichment"]["asset"]["owner"] == "secops"
        # Every original field is untouched by enrichment.
        assert docs[0]["host"]["name"] == "WIN-DC01"
        assert docs[0]["event"]["kind"] == "event"

    @pytest.mark.asyncio
    async def test_no_enrichment_pipeline_configured_is_a_true_no_op(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        """Honest disabled state (roadmap F1): no enrichment_pipeline means
        records are indexed exactly as parsed, no enrichment.* keys at all."""
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        opensearch = InMemoryOpenSearchClient()
        ingest = TimelineIngestionService(opensearch, AuditLogService(audit_repo))
        registry = ParserRegistry()
        registry.register(_HostNamedParser("WIN-DC01"))
        orchestrator = ParsingOrchestrationService(
            evidence_repository=evidence_repo,
            storage=local_storage,
            audit_log=AuditLogService(audit_repo),
            parser_registry=registry,
            task_queue=task_queue,
            timeline_ingest=ingest,
        )

        await orchestrator.execute_parse(evidence.evidence_id, tenant)

        docs = [
            d for idx in opensearch.all_indices() for d in opensearch.get_documents(idx).values()
        ]
        assert len(docs) == 1
        assert "enrichment" not in docs[0]

    @pytest.mark.asyncio
    async def test_ioc_match_enricher_applies_real_derived_fields_before_indexing(
        self, evidence_repo, local_storage, audit_repo, task_queue, tenant
    ) -> None:
        """Roadmap F2: an EnrichmentPipeline configured with IOCMatchEnricher
        must run before indexing, attaching real derived enrichment.ioc.*
        fields for a record whose extra["source.ip"] matches a real,
        ingested IOC -- end to end through the real
        TimelineIngestionService/InMemoryOpenSearchClient, mirroring F1's
        own enrichment.asset.* end-to-end test exactly."""
        evidence = await self._seed_parsing_evidence(evidence_repo, local_storage, tenant)
        ioc_repo = InMemoryIOCFeedRepository()
        feed = await ioc_repo.get_or_create_feed(tenant.org_id, "poc-feed")
        await ioc_repo.save_version(
            IOCFeedVersion(
                feed_id=feed.feed_id,
                version=1,
                org_id=tenant.org_id,
                source_format="stix2.1",
                indicators=(
                    IOCIndicator(
                        ioc_type=IOCType.IP,
                        value="203.0.113.66",
                        confidence=85,
                        description="C2 IP",
                    ),
                ),
            )
        )
        pipeline = EnrichmentPipeline([IOCMatchEnricher(ioc_repo)])
        opensearch = InMemoryOpenSearchClient()
        ingest = TimelineIngestionService(opensearch, AuditLogService(audit_repo))
        registry = ParserRegistry()
        registry.register(_SourceIpParser("203.0.113.66"))
        orchestrator = ParsingOrchestrationService(
            evidence_repository=evidence_repo,
            storage=local_storage,
            audit_log=AuditLogService(audit_repo),
            parser_registry=registry,
            task_queue=task_queue,
            timeline_ingest=ingest,
            enrichment_pipeline=pipeline,
        )

        await orchestrator.execute_parse(evidence.evidence_id, tenant)

        docs = [
            d for idx in opensearch.all_indices() for d in opensearch.get_documents(idx).values()
        ]
        assert len(docs) == 1
        assert docs[0]["enrichment"]["ioc"]["matched"] is True
        assert docs[0]["enrichment"]["ioc"]["ioc_type"] == "ip"
        assert docs[0]["enrichment"]["ioc"]["feed_name"] == "poc-feed"
        assert docs[0]["enrichment"]["ioc"]["confidence"] == 85
        # Every original field is untouched by enrichment.
        assert docs[0]["source"]["ip"] == "203.0.113.66"
        assert docs[0]["event"]["kind"] == "event"

    @pytest.mark.asyncio
    async def test_document_id_is_stable_across_calls(self) -> None:
        eid = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        d1 = _make_document_id(eid, "cloudtrail", 5)
        d2 = _make_document_id(eid, "cloudtrail", 5)
        assert d1 == d2
        assert len(d1) == 40
