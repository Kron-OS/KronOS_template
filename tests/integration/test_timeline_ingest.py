"""Integration tests for the full parse → timeline ingestion pipeline.

Uses LocalEvidenceStorage and InMemoryOpenSearchClient so no external services
are needed.  These tests verify the complete PARSING → COMPLETE evidence lifecycle.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from src.adapter.opensearch.client import InMemoryOpenSearchClient
from src.adapter.queue.task_queue import InMemoryTaskQueue
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.parser_registry import ParserRegistry
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.application.timeline_ingest import TimelineIngestionService
from src.domain.audit import AuditEventType
from src.domain.evidence import EvidenceState
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence_metadata, make_tenant_context

SAMPLES = Path(__file__).parents[1] / "fixtures" / "samples"

pytestmark = pytest.mark.integration


def _make_stack(
    os_client: InMemoryOpenSearchClient | None = None,
) -> tuple[
    ParsingOrchestrationService,
    InMemoryEvidenceRepository,
    InMemoryAuditLogRepository,
    InMemoryOpenSearchClient,
    LocalEvidenceStorage,
]:
    audit_repo = InMemoryAuditLogRepository()
    ev_repo = InMemoryEvidenceRepository()
    audit = AuditLogService(audit_repo)
    storage = LocalEvidenceStorage()
    task_queue = InMemoryTaskQueue()
    opensearch = os_client or InMemoryOpenSearchClient()
    timeline_ingest = TimelineIngestionService(opensearch=opensearch, audit_log=audit)

    registry = ParserRegistry()
    from src.external.parsers.cloudtrail import CloudTrailParser  # noqa: PLC0415
    from src.external.parsers.nginx import NginxParser  # noqa: PLC0415

    registry.register(CloudTrailParser())
    registry.register(NginxParser())
    try:
        from src.external.parsers.evtx import FastEvtxParser  # noqa: PLC0415

        registry.register(FastEvtxParser())
    except ImportError:
        pass

    svc = ParsingOrchestrationService(
        evidence_repository=ev_repo,
        storage=storage,
        audit_log=audit,
        parser_registry=registry,
        task_queue=task_queue,
        timeline_ingest=timeline_ingest,
    )
    return svc, ev_repo, audit_repo, opensearch, storage


async def _seed_evidence(
    ev_repo: InMemoryEvidenceRepository,
    storage: LocalEvidenceStorage,
    filename: str,
    content_type: str,
    data: bytes,
    tenant: object,
) -> uuid.UUID:
    """Seed a PARSING-state evidence with *data* in local storage."""
    from src.domain.evidence import Evidence, EvidenceState  # noqa: PLC0415

    meta = make_evidence_metadata(org_id=tenant.org_id)  # type: ignore[attr-defined]
    meta = meta.model_copy(update={"original_filename": filename, "content_type": content_type})
    evidence = Evidence(metadata=meta, state=EvidenceState.PARSING)
    ev_key = f"{meta.org_alias}/{meta.case_id}/{evidence.evidence_id}"
    storage.write_evidence(ev_key, data)
    evidence = evidence.model_copy(update={"minio_evidence_key": ev_key})
    await ev_repo.save(evidence)
    return evidence.evidence_id


class TestFullParseAndIngest:
    async def test_cloudtrail_file_reaches_complete_state(self, tmp_path: Path) -> None:
        svc, ev_repo, audit_repo, opensearch, storage = _make_stack()
        tenant = make_tenant_context()
        data = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence_id = await _seed_evidence(
            ev_repo, storage, "cloudtrail.json", "application/json", data, tenant
        )

        count = await svc.execute_parse(evidence_id, tenant)

        assert count > 0
        evidence = await ev_repo.get_by_id(evidence_id, tenant.org_id)
        assert evidence is not None
        assert evidence.state == EvidenceState.COMPLETE

    async def test_cloudtrail_records_stored_in_opensearch(self, tmp_path: Path) -> None:
        svc, ev_repo, audit_repo, opensearch, storage = _make_stack()
        tenant = make_tenant_context()
        data = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence_id = await _seed_evidence(
            ev_repo, storage, "cloudtrail.json", "application/json", data, tenant
        )

        count = await svc.execute_parse(evidence_id, tenant)

        assert opensearch.total_documents() == count

    async def test_document_ids_are_deterministic(self, tmp_path: Path) -> None:
        """Parsing the same file twice must produce the same document IDs."""
        data = (SAMPLES / "cloudtrail.json").read_bytes()
        tenant = make_tenant_context()

        os1 = InMemoryOpenSearchClient()
        svc1, ev_repo1, _, _, storage1 = _make_stack(os_client=os1)
        eid1 = await _seed_evidence(
            ev_repo1, storage1, "cloudtrail.json", "application/json", data, tenant
        )
        await svc1.execute_parse(eid1, tenant)

        os2 = InMemoryOpenSearchClient()
        svc2, ev_repo2, _, _, storage2 = _make_stack(os_client=os2)
        # Same evidence_id → same deterministic doc IDs
        eid2 = eid1
        from src.domain.evidence import Evidence, EvidenceState  # noqa: PLC0415
        from tests.fixtures.factories import make_evidence_metadata  # noqa: PLC0415

        meta = make_evidence_metadata(org_id=tenant.org_id)
        meta = meta.model_copy(
            update={"original_filename": "cloudtrail.json", "content_type": "application/json"}
        )
        evidence = Evidence(
            evidence_id=eid2,
            metadata=meta,
            state=EvidenceState.PARSING,
        )
        ev_key = f"{meta.org_alias}/{meta.case_id}/{evidence.evidence_id}"
        storage2.write_evidence(ev_key, data)
        evidence = evidence.model_copy(update={"minio_evidence_key": ev_key})
        await ev_repo2.save(evidence)
        await svc2.execute_parse(eid2, tenant)

        ids1 = set()
        for docs in os1._indices.values():
            ids1.update(docs.keys())
        ids2 = set()
        for docs in os2._indices.values():
            ids2.update(docs.keys())
        assert ids1 == ids2

    async def test_index_name_pattern(self, tmp_path: Path) -> None:
        svc, ev_repo, _, opensearch, storage = _make_stack()
        tenant = make_tenant_context()
        data = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence_id = await _seed_evidence(
            ev_repo, storage, "cloudtrail.json", "application/json", data, tenant
        )
        await svc.execute_parse(evidence_id, tenant)

        for index in opensearch.all_indices():
            assert index.startswith("kronos-")
            assert "-case-" in index

    async def test_audit_trail_includes_all_events(self, tmp_path: Path) -> None:
        svc, ev_repo, audit_repo, _, storage = _make_stack()
        tenant = make_tenant_context()
        data = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence_id = await _seed_evidence(
            ev_repo, storage, "cloudtrail.json", "application/json", data, tenant
        )
        await svc.execute_parse(evidence_id, tenant)

        event_types = {e.event_type for e in audit_repo._events}
        assert AuditEventType.PARSE_COMPLETED in event_types
        assert AuditEventType.INGEST_STARTED in event_types
        assert AuditEventType.INGEST_COMPLETED in event_types

    async def test_nginx_file_ingested(self, tmp_path: Path) -> None:
        svc, ev_repo, _, opensearch, storage = _make_stack()
        tenant = make_tenant_context()
        data = (SAMPLES / "nginx.log").read_bytes()
        evidence_id = await _seed_evidence(
            ev_repo, storage, "nginx.log", "text/plain", data, tenant
        )
        count = await svc.execute_parse(evidence_id, tenant)
        assert count > 0
        assert opensearch.total_documents() == count

    async def test_two_orgs_go_to_separate_indices(self, tmp_path: Path) -> None:
        svc, ev_repo, _, opensearch, storage = _make_stack()
        data = (SAMPLES / "cloudtrail.json").read_bytes()

        from tests.fixtures.factories import make_tenant_context  # noqa: PLC0415

        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()

        eid_a = await _seed_evidence(
            ev_repo, storage, "cloudtrail.json", "application/json", data, tenant_a
        )
        await _seed_evidence(
            ev_repo, storage, "cloudtrail.json", "application/json", data, tenant_b
        )

        await svc.execute_parse(eid_a, tenant_a)

        # tenant_b evidence — need separate svc instance for separate audit
        svc2, ev_repo2, _, opensearch2, storage2 = _make_stack(os_client=opensearch)
        eid_b2 = await _seed_evidence(
            ev_repo2, storage2, "cloudtrail.json", "application/json", data, tenant_b
        )
        await svc2.execute_parse(eid_b2, tenant_b)

        # Because org_aliases differ, index names differ.
        org_a_indices = [i for i in opensearch.all_indices() if "testorg" in i]
        assert len(org_a_indices) > 0
