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


_SHARED_CASE_ID = uuid.uuid4()


def _same_case_record(record_index: int = 0):  # type: ignore[no-untyped-def]
    """make_timeline_record() gives every record a fresh random case_id, so
    it can't be used to test "N records, same index" behavior -- build one
    directly with a shared case_id instead, same pattern as
    test_documents_from_different_months_go_to_different_indices below."""
    from src.domain.timeline import KronosProvenance, TimelineRecord

    return TimelineRecord(
        **{"@timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC), "message": "x"},
        kronos=KronosProvenance(
            evidence_id=uuid.uuid4(),
            case_id=_SHARED_CASE_ID,
            org_id=uuid.uuid4(),
            sha256="a" * 64,
            parser="evtx-rs",
            parser_version="1.0.0",
            record_index=record_index,
            ingest_timestamp=datetime.now(UTC),
        ),
    )


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

    async def test_generic_tenant_role_skipped_when_security_disabled(self) -> None:
        await self.svc.ingest_records(_records(), self.tenant, self.evidence_id)
        assert self.os_client.generic_tenant_role_created is False

    async def test_generic_tenant_role_created_once_when_security_enabled(self) -> None:
        """Verified design (poc/keycloak_opensearch_dls/): ONE generic,
        org-agnostic role, created once ever -- not per-org. A second
        ingest_records() call (even for a different org) must not call
        ensure_generic_tenant_role() again.
        """
        svc = TimelineIngestionService(
            opensearch=self.os_client,
            audit_log=self.audit,
            batch_size=10,
            security_enabled=True,
        )
        await svc.ingest_records(_records(make_timeline_record()), self.tenant, self.evidence_id)
        assert self.os_client.generic_tenant_role_created is True

        self.os_client.generic_tenant_role_created = False
        other_tenant = make_tenant_context()
        await svc.ingest_records(_records(make_timeline_record()), other_tenant, self.evidence_id)
        assert self.os_client.generic_tenant_role_created is False

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


class TestIsmSelfHealingWiring:
    """Roadmap M1/B3: TimelineIngestionService must explicitly call
    ensure_managed() after each flush -- ism_template's implicit auto-attach
    alone was found (poc/ism_tiering_legal_hold/) to leave real indices
    stuck with management disabled, with no automatic recovery."""

    def setup_method(self) -> None:
        self.repo = InMemoryAuditLogRepository()
        self.audit = AuditLogService(self.repo)
        self.os_client = InMemoryOpenSearchClient()
        self.tenant = make_tenant_context()
        self.evidence_id = uuid.uuid4()

    async def test_ensure_managed_not_called_when_no_ism_manager_configured(self) -> None:
        svc = TimelineIngestionService(
            opensearch=self.os_client, audit_log=self.audit, batch_size=10
        )
        await svc.ingest_records(_records(make_timeline_record()), self.tenant, self.evidence_id)
        # No exception, no-op -- ism_manager=None is a valid, explicit "not configured" state.

    async def test_ensure_managed_called_once_per_unique_index_after_flush(self) -> None:
        from unittest.mock import AsyncMock

        ism_manager = AsyncMock()
        svc = TimelineIngestionService(
            opensearch=self.os_client,
            audit_log=self.audit,
            batch_size=10,
            ism_manager=ism_manager,
        )
        records = [_same_case_record(record_index=i) for i in range(3)]
        await svc.ingest_records(_records(*records), self.tenant, self.evidence_id)

        assert ism_manager.ensure_managed.call_count == 1
        index_arg, policy_arg = ism_manager.ensure_managed.call_args[0]
        assert index_arg in self.os_client.all_indices()
        assert policy_arg == "kronos-rollover"

    async def test_ensure_managed_uses_tier_resolver_when_configured(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        ism_manager = AsyncMock()
        tier_resolver = MagicMock()
        tier_resolver.policy_id_for_source.return_value = "some-custom-policy"
        svc = TimelineIngestionService(
            opensearch=self.os_client,
            audit_log=self.audit,
            batch_size=10,
            ism_manager=ism_manager,
            ism_tier_resolver=tier_resolver,
        )
        await svc.ingest_records(_records(make_timeline_record()), self.tenant, self.evidence_id)

        tier_resolver.policy_id_for_source.assert_called_with(None)
        _, policy_arg = ism_manager.ensure_managed.call_args[0]
        assert policy_arg == "some-custom-policy"

    async def test_ensure_managed_not_repeated_for_the_same_index_across_flushes(self) -> None:
        from unittest.mock import AsyncMock

        ism_manager = AsyncMock()
        svc = TimelineIngestionService(
            opensearch=self.os_client,
            audit_log=self.audit,
            batch_size=1,  # flush after every single record
            ism_manager=ism_manager,
        )
        records = [_same_case_record(record_index=i) for i in range(3)]
        await svc.ingest_records(_records(*records), self.tenant, self.evidence_id)

        # All 3 records land in the same (single) index for this tenant/case
        # this month -- ensure_managed must only be called once, not per flush.
        assert ism_manager.ensure_managed.call_count == 1
