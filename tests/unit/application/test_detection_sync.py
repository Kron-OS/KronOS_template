"""Unit tests for DetectionSyncService (mock only the OpenSearch findings client)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from src.adapter.opensearch.findings_client import FindingsClient
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.detection_sync import DetectionSyncService, _extract_case_id
from src.domain.audit import AuditEventType
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context

_CASE_ID = "1a49dcd0-b6a6-4410-83aa-def7ffc9f9fa"


def _real_finding_hit(
    finding_id: str,
    *,
    monitor_name: str = "kronos-testorg-network-detector",
    source_index: str = f"kronos-testorg-case-{_CASE_ID}-202601",
    timestamp_ms: int = 1785423677843,
) -> dict[str, Any]:
    """Shaped exactly like a real SA finding document (verified against a
    live OpenSearch 2.11.1 cluster -- see poc/detection_finding_sync/)."""
    return {
        "_index": ".opensearch-sap-network-findings-2026.07.29-1",
        "_id": finding_id,
        "_source": {
            "id": finding_id,
            "related_doc_ids": ["f648d8e8-32fd-4217-b51d-1645d34d83a4"],
            "correlated_doc_ids": ["f648d8e8-32fd-4217-b51d-1645d34d83a4"],
            "monitor_id": "S8yIs58BG52zb-VTinMn",
            "monitor_name": monitor_name,
            "index": source_index,
            "queries": [
                {
                    "id": "1fc0809e-06bf-4de3-ad52-25e5263b7623",
                    "name": "1fc0809e-06bf-4de3-ad52-25e5263b7623",
                    "tags": ["high", "network", "attack.t1021.001"],
                }
            ],
            "timestamp": timestamp_ms,
            "execution_id": None,
        },
    }


class _FakeFindingsClient(FindingsClient):
    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self._hits = hits
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    async def fetch_org_findings(self, org_alias: str, log_types: tuple[str, ...]) -> list[dict[str, Any]]:
        self.calls.append((org_alias, log_types))
        return self._hits


def _make_service(hits: list[dict[str, Any]]) -> tuple[DetectionSyncService, InMemoryDetectionRepository, InMemoryAuditLogRepository]:
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    detection_repo = InMemoryDetectionRepository()
    findings_client = _FakeFindingsClient(hits)
    service = DetectionSyncService(findings_client, detection_repo, audit_log, log_types=("network",))
    return service, detection_repo, audit_repo


class TestExtractCaseId:
    def test_extracts_case_id_from_real_index_naming_convention(self) -> None:
        assert _extract_case_id(f"kronos-acme-case-{_CASE_ID}-202601") == uuid.UUID(_CASE_ID)

    def test_returns_none_for_unrecognized_index_name(self) -> None:
        assert _extract_case_id("kronos-acme-stream-syslog-202601") is None

    def test_returns_none_for_empty_string(self) -> None:
        assert _extract_case_id("") is None


class TestDetectionSyncService:
    @pytest.mark.asyncio
    async def test_creates_one_detection_per_new_finding(self) -> None:
        hits = [_real_finding_hit("finding-1"), _real_finding_hit("finding-2")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        created = await service.sync_org_findings(tenant)

        assert created == 2
        stored = [d async for d in repo.stream_by_org(tenant.org_id)]
        assert {d.finding_id for d in stored} == {"finding-1", "finding-2"}

    @pytest.mark.asyncio
    async def test_org_id_comes_from_tenant_never_from_finding(self) -> None:
        """Invariant #3: even if a finding claimed a different org somehow,
        the stored Detection's org_id must be the syncing tenant's own."""
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.org_id == tenant.org_id
        assert stored.org_alias == tenant.org_alias

    @pytest.mark.asyncio
    async def test_new_detection_starts_in_new_triage_state(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.triage_state.value == "NEW"

    @pytest.mark.asyncio
    async def test_stores_real_rule_id_for_replayability(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.rule_matches[0].rule_id == "1fc0809e-06bf-4de3-ad52-25e5263b7623"
        assert stored.attack_tags == ("attack.t1021.001",)

    @pytest.mark.asyncio
    async def test_case_id_extracted_from_source_index(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.case_id == uuid.UUID(_CASE_ID)

    @pytest.mark.asyncio
    async def test_rerun_is_idempotent_no_duplicates(self) -> None:
        hits = [_real_finding_hit("finding-1"), _real_finding_hit("finding-2")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        first_created = await service.sync_org_findings(tenant)
        second_created = await service.sync_org_findings(tenant)

        assert first_created == 2
        assert second_created == 0
        stored = [d async for d in repo.stream_by_org(tenant.org_id)]
        assert len(stored) == 2

    @pytest.mark.asyncio
    async def test_sync_creates_audit_event_per_new_detection(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, _, audit_repo = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        synced_events = [e for e in events if e.event_type == AuditEventType.DETECTION_SYNCED]
        assert len(synced_events) == 1
        assert synced_events[0].details["finding_id"] == "finding-1"

    @pytest.mark.asyncio
    async def test_rerun_produces_no_additional_audit_events(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, _, audit_repo = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)
        await service.sync_org_findings(tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        synced_events = [e for e in events if e.event_type == AuditEventType.DETECTION_SYNCED]
        assert len(synced_events) == 1

    @pytest.mark.asyncio
    async def test_findings_client_queried_with_tenant_org_alias(self) -> None:
        hits: list[dict[str, Any]] = []
        service, _, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        findings_client = service._findings_client  # noqa: SLF001
        assert findings_client.calls == [(tenant.org_alias, ("network",))]

    @pytest.mark.asyncio
    async def test_no_findings_returns_zero(self) -> None:
        service, repo, _ = _make_service([])
        tenant = make_tenant_context()

        created = await service.sync_org_findings(tenant)

        assert created == 0
        assert [d async for d in repo.stream_by_org(tenant.org_id)] == []

    @pytest.mark.asyncio
    async def test_pre_existing_detection_is_not_recreated(self) -> None:
        """If a Detection for this finding already exists (e.g. a previous
        sync call, or one that lost a race), the pre-check must find it and
        skip -- must not raise, must not double count."""
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        from datetime import UTC as _UTC
        from datetime import datetime as _datetime

        from src.domain.detection import Detection

        await repo.save(
            Detection(
                org_id=tenant.org_id,
                org_alias=tenant.org_alias,
                finding_id="finding-1",
                detector_name="kronos-testorg-network-detector",
                source_index=f"kronos-testorg-case-{_CASE_ID}-202601",
                finding_timestamp=_datetime.now(_UTC),
            )
        )

        created = await service.sync_org_findings(tenant)

        assert created == 0
        assert len([d async for d in repo.stream_by_org(tenant.org_id)]) == 1

    @pytest.mark.asyncio
    async def test_save_race_after_precheck_is_swallowed_not_raised(self) -> None:
        """A concurrent sync call can win the (org_id, finding_id) uniqueness
        race strictly between our own get_by_finding_id pre-check and our
        save() call. The repository's save() is the real backstop for this
        (a unique constraint in Postgres) -- verify DetectionSyncService
        treats that specific failure as "already synced elsewhere", not a
        hard error that aborts the whole sync run."""
        from src.exceptions import StorageError

        hits = [_real_finding_hit("finding-1"), _real_finding_hit("finding-2")]

        class _RaceyRepository(InMemoryDetectionRepository):
            async def save(self, detection):  # type: ignore[override]
                if detection.finding_id == "finding-1":
                    raise StorageError("simulated unique-constraint race")
                return await super().save(detection)

        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = _RaceyRepository()
        findings_client = _FakeFindingsClient(hits)
        service = DetectionSyncService(findings_client, repo, audit_log, log_types=("network",))
        tenant = make_tenant_context()

        created = await service.sync_org_findings(tenant)

        # finding-1 raced and lost (not counted, not raised); finding-2 is
        # entirely unaffected -- one failure must not abort the whole sync.
        assert created == 1
        stored = [d async for d in repo.stream_by_org(tenant.org_id)]
        assert {d.finding_id for d in stored} == {"finding-2"}
