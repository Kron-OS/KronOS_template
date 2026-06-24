"""Unit tests for TimelineIngestionService."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.opensearch.client import InMemoryOpenSearchClient
from src.application.audit_log import AuditLogService
from src.application.timeline_ingest import TimelineIngestionService
from src.domain.audit import AuditEventType
from src.exceptions import StorageError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context, make_timeline_record


async def _records(*recs):  # type: ignore[no-untyped-def]
    for r in recs:
        yield r


class TestTimelineIngestionService:
    def setup_method(self) -> None:
        self.repo = InMemoryAuditLogRepository()
        self.audit = AuditLogService(self.repo)
        self.os_client = InMemoryOpenSearchClient()
        self.svc = TimelineIngestionService(
            opensearch=self.os_client,
            audit_log=self.audit,
            batch_size=10,
        )
        self.tenant = make_tenant_context()
        self.evidence_id = uuid.uuid4()

    async def test_returns_correct_count(self) -> None:
        records = [make_timeline_record(record_index=i) for i in range(3)]
        count = await self.svc.ingest_records(_records(*records), self.tenant, self.evidence_id)
        assert count == 3

    async def test_zero_records(self) -> None:
        count = await self.svc.ingest_records(_records(), self.tenant, self.evidence_id)
        assert count == 0

    async def test_calls_bulk_index(self) -> None:
        records = [make_timeline_record(record_index=i) for i in range(2)]
        await self.svc.ingest_records(_records(*records), self.tenant, self.evidence_id)
        assert len(self.os_client.bulk_calls) == 1
        assert len(self.os_client.bulk_calls[0]) == 2

    async def test_flushes_on_batch_size(self) -> None:
        svc = TimelineIngestionService(
            opensearch=self.os_client,
            audit_log=self.audit,
            batch_size=2,
        )
        records = [make_timeline_record(record_index=i) for i in range(5)]
        count = await svc.ingest_records(_records(*records), self.tenant, self.evidence_id)
        assert count == 5
        # 5 records with batch_size=2 → flushes at 2, 4 (2 full batches) + 1 remainder
        assert len(self.os_client.bulk_calls) == 3

    async def test_documents_stored_in_opensearch(self) -> None:
        record = make_timeline_record()
        record = record.model_copy(update={"document_id": "test-doc-id"})
        await self.svc.ingest_records(_records(record), self.tenant, self.evidence_id)
        assert self.os_client.total_documents() == 1

    async def test_logs_ingest_started(self) -> None:
        await self.svc.ingest_records(_records(), self.tenant, self.evidence_id)
        event_types = [e.event_type for e in self.repo._events]
        assert AuditEventType.INGEST_STARTED in event_types

    async def test_logs_ingest_completed(self) -> None:
        await self.svc.ingest_records(_records(), self.tenant, self.evidence_id)
        event_types = [e.event_type for e in self.repo._events]
        assert AuditEventType.INGEST_COMPLETED in event_types

    async def test_ingest_completed_has_record_count(self) -> None:
        records = [make_timeline_record(record_index=i) for i in range(4)]
        await self.svc.ingest_records(_records(*records), self.tenant, self.evidence_id)
        completed = next(
            e for e in self.repo._events if e.event_type == AuditEventType.INGEST_COMPLETED
        )
        assert completed.details["record_count"] == 4

    async def test_logs_ingest_failed_on_error(self) -> None:
        class _BrokenClient(InMemoryOpenSearchClient):
            async def bulk_index(self, documents):  # type: ignore[override]
                raise RuntimeError("opensearch down")

        broken_svc = TimelineIngestionService(
            opensearch=_BrokenClient(),
            audit_log=self.audit,
            batch_size=1,
        )
        with pytest.raises(StorageError):
            await broken_svc.ingest_records(
                _records(make_timeline_record()), self.tenant, self.evidence_id
            )
        event_types = [e.event_type for e in self.repo._events]
        assert AuditEventType.INGEST_FAILED in event_types
        assert AuditEventType.INGEST_COMPLETED not in event_types

    async def test_index_name_follows_pattern(self) -> None:
        record = make_timeline_record()
        await self.svc.ingest_records(_records(record), self.tenant, self.evidence_id)
        indices = self.os_client.all_indices()
        assert len(indices) == 1
        assert indices[0].startswith("kronos-")
        assert "-case-" in indices[0]

    async def test_fallback_id_used_when_document_id_missing(self) -> None:
        record = make_timeline_record()
        assert record.document_id is None
        await self.svc.ingest_records(_records(record), self.tenant, self.evidence_id)
        # Document should still be stored with a generated ID.
        assert self.os_client.total_documents() == 1

    async def test_documents_from_different_months_go_to_different_indices(self) -> None:
        from src.domain.timeline import KronosProvenance, TimelineRecord

        def _rec(ts: datetime) -> TimelineRecord:
            return TimelineRecord(
                **{"@timestamp": ts, "message": "x"},
                kronos=KronosProvenance(
                    evidence_id=uuid.uuid4(),
                    case_id=uuid.uuid4(),
                    org_id=uuid.uuid4(),
                    sha256="d" * 64,
                    parser="nginx",
                    parser_version="1.0.0",
                    record_index=0,
                    ingest_timestamp=datetime.now(UTC),
                ),
            )

        r1 = _rec(datetime(2024, 1, 15, tzinfo=UTC))
        r2 = _rec(datetime(2024, 2, 15, tzinfo=UTC))
        await self.svc.ingest_records(_records(r1, r2), self.tenant, self.evidence_id)
        assert len(self.os_client.all_indices()) == 2
