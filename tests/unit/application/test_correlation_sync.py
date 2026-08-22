"""Unit / true end-to-end tests for CorrelationSyncService (mock only the
OpenSearch correlation client -- everything else is the real class:
InMemoryDetectionRepository, InMemoryDetectionCorrelationRepository,
AuditLogService, mirroring test_detection_sync.py's own style).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from src.adapter.opensearch.correlation_client import CorrelationClient
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.adapter.repository.detection_correlation import (
    InMemoryDetectionCorrelationRepository,
)
from src.application.audit_log import AuditLogService
from src.application.correlation_sync import CorrelationSyncService
from src.domain.audit import AuditEventType
from src.domain.detection import Detection
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class _FakeCorrelationClient(CorrelationClient):
    def __init__(self, pairs: list[dict[str, Any]]) -> None:
        self._pairs = pairs
        self.calls: list[tuple[int, int]] = []

    async def fetch_correlations(self, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
        self.calls.append((start_ms, end_ms))
        return self._pairs


def _pair(finding1: str, finding2: str, rules: tuple[str, ...] = ("rule-1",)) -> dict[str, Any]:
    """Shaped exactly like a real SA GET .../correlations response entry --
    see poc/security_analytics_correlation/README.md."""
    return {
        "finding1": finding1,
        "logType1": "windows",
        "finding2": finding2,
        "logType2": "network",
        "rules": list(rules),
    }


async def _seed_detection(
    repo: InMemoryDetectionRepository,
    org_id: uuid.UUID,
    finding_id: str,
    case_id: uuid.UUID | None = None,
) -> Detection:
    detection = Detection(
        org_id=org_id,
        org_alias="acme",
        case_id=case_id,
        finding_id=finding_id,
        detector_name="kronos-acme-windows-detector",
        source_index="kronos-acme-case-abc-202601",
        finding_timestamp=datetime.now(UTC),
    )
    return await repo.save(detection)


def _make_service(
    pairs: list[dict[str, Any]],
) -> tuple[
    CorrelationSyncService,
    InMemoryDetectionRepository,
    InMemoryDetectionCorrelationRepository,
    InMemoryAuditLogRepository,
    _FakeCorrelationClient,
]:
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    detection_repo = InMemoryDetectionRepository()
    correlation_repo = InMemoryDetectionCorrelationRepository()
    client = _FakeCorrelationClient(pairs)
    service = CorrelationSyncService(client, detection_repo, correlation_repo, audit_log)
    return service, detection_repo, correlation_repo, audit_repo, client


class TestCorrelationSyncService:
    @pytest.mark.asyncio
    async def test_creates_correlation_when_both_findings_already_synced_for_org(self) -> None:
        tenant = make_tenant_context()
        service, detection_repo, correlation_repo, _, _ = _make_service(
            [_pair("finding-a", "finding-b")]
        )
        det_a = await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        det_b = await _seed_detection(detection_repo, tenant.org_id, "finding-b")

        created = await service.sync_org_correlations(tenant, 0, 1)

        assert created == 1
        stored = [c async for c in correlation_repo.stream_by_org(tenant.org_id)]
        assert len(stored) == 1
        assert {stored[0].detection_id_a, stored[0].detection_id_b} == {
            det_a.detection_id,
            det_b.detection_id,
        }
        assert stored[0].rule_ids == ("rule-1",)

    @pytest.mark.asyncio
    async def test_org_id_comes_from_tenant_never_from_the_correlations_response(self) -> None:
        """Invariant #3: the real correlations API is cluster-wide with no
        org field at all -- the stored org_id must be the syncing tenant's own."""
        tenant = make_tenant_context()
        service, detection_repo, correlation_repo, _, _ = _make_service(
            [_pair("finding-a", "finding-b")]
        )
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        await _seed_detection(detection_repo, tenant.org_id, "finding-b")

        await service.sync_org_correlations(tenant, 0, 1)

        stored = [c async for c in correlation_repo.stream_by_org(tenant.org_id)][0]
        assert stored.org_id == tenant.org_id

    @pytest.mark.asyncio
    async def test_pair_skipped_when_one_finding_belongs_to_another_org(self) -> None:
        """Tenant-isolation gate: the raw correlations API is cluster-wide,
        so a pair must never be recorded unless BOTH findings already
        resolve to a Detection this exact org synced."""
        tenant = make_tenant_context()
        other_org_id = uuid.uuid4()
        service, detection_repo, correlation_repo, _, _ = _make_service(
            [_pair("finding-a", "finding-b")]
        )
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        # finding-b belongs to a DIFFERENT org -- this org never synced it.
        await _seed_detection(detection_repo, other_org_id, "finding-b")

        created = await service.sync_org_correlations(tenant, 0, 1)

        assert created == 0
        assert [c async for c in correlation_repo.stream_by_org(tenant.org_id)] == []

    @pytest.mark.asyncio
    async def test_pair_skipped_when_neither_finding_synced_yet(self) -> None:
        tenant = make_tenant_context()
        service, _, correlation_repo, _, _ = _make_service([_pair("finding-a", "finding-b")])

        created = await service.sync_org_correlations(tenant, 0, 1)

        assert created == 0
        assert [c async for c in correlation_repo.stream_by_org(tenant.org_id)] == []

    @pytest.mark.asyncio
    async def test_self_pair_ignored(self) -> None:
        tenant = make_tenant_context()
        service, detection_repo, correlation_repo, _, _ = _make_service(
            [_pair("finding-a", "finding-a")]
        )
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")

        created = await service.sync_org_correlations(tenant, 0, 1)

        assert created == 0
        assert [c async for c in correlation_repo.stream_by_org(tenant.org_id)] == []

    @pytest.mark.asyncio
    async def test_rerun_is_idempotent_no_duplicates(self) -> None:
        tenant = make_tenant_context()
        service, detection_repo, correlation_repo, _, _ = _make_service(
            [_pair("finding-a", "finding-b")]
        )
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        await _seed_detection(detection_repo, tenant.org_id, "finding-b")

        first = await service.sync_org_correlations(tenant, 0, 1)
        second = await service.sync_org_correlations(tenant, 0, 1)

        assert first == 1
        assert second == 0
        assert len([c async for c in correlation_repo.stream_by_org(tenant.org_id)]) == 1

    @pytest.mark.asyncio
    async def test_rerun_idempotent_even_if_pair_order_is_reversed(self) -> None:
        """The real API can report the same pair with finding1/finding2
        swapped across two calls (no stable ordering) -- must still dedupe."""
        tenant = make_tenant_context()
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        detection_repo = InMemoryDetectionRepository()
        correlation_repo = InMemoryDetectionCorrelationRepository()
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        await _seed_detection(detection_repo, tenant.org_id, "finding-b")

        client1 = _FakeCorrelationClient([_pair("finding-a", "finding-b")])
        service1 = CorrelationSyncService(client1, detection_repo, correlation_repo, audit_log)
        first = await service1.sync_org_correlations(tenant, 0, 1)

        client2 = _FakeCorrelationClient([_pair("finding-b", "finding-a")])
        service2 = CorrelationSyncService(client2, detection_repo, correlation_repo, audit_log)
        second = await service2.sync_org_correlations(tenant, 0, 1)

        assert first == 1
        assert second == 0
        assert len([c async for c in correlation_repo.stream_by_org(tenant.org_id)]) == 1

    @pytest.mark.asyncio
    async def test_sync_creates_audit_event_per_new_correlation(self) -> None:
        tenant = make_tenant_context()
        service, detection_repo, _, audit_repo, _ = _make_service([_pair("finding-a", "finding-b")])
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        await _seed_detection(detection_repo, tenant.org_id, "finding-b")

        await service.sync_org_correlations(tenant, 0, 1)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        correlated_events = [
            e for e in events if e.event_type == AuditEventType.DETECTION_CORRELATED
        ]
        assert len(correlated_events) == 1
        assert correlated_events[0].details["finding_id_a"] == "finding-a"
        assert correlated_events[0].details["finding_id_b"] == "finding-b"

    @pytest.mark.asyncio
    async def test_rerun_produces_no_additional_audit_events(self) -> None:
        tenant = make_tenant_context()
        service, detection_repo, _, audit_repo, _ = _make_service([_pair("finding-a", "finding-b")])
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        await _seed_detection(detection_repo, tenant.org_id, "finding-b")

        await service.sync_org_correlations(tenant, 0, 1)
        await service.sync_org_correlations(tenant, 0, 1)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        correlated_events = [
            e for e in events if e.event_type == AuditEventType.DETECTION_CORRELATED
        ]
        assert len(correlated_events) == 1

    @pytest.mark.asyncio
    async def test_client_queried_with_the_given_time_window(self) -> None:
        tenant = make_tenant_context()
        service, _, _, _, client = _make_service([])

        await service.sync_org_correlations(tenant, 1000, 2000)

        assert client.calls == [(1000, 2000)]

    @pytest.mark.asyncio
    async def test_no_pairs_returns_zero(self) -> None:
        tenant = make_tenant_context()
        service, _, correlation_repo, _, _ = _make_service([])

        created = await service.sync_org_correlations(tenant, 0, 1)

        assert created == 0
        assert [c async for c in correlation_repo.stream_by_org(tenant.org_id)] == []

    @pytest.mark.asyncio
    async def test_audit_event_case_id_when_both_detections_share_one_case(self) -> None:
        """Gap Audit Milestone NN: when both correlated detections DO belong
        to the same case, the audit row must be case-scoped so it shows up
        in that case's own audit trail (kronos-attest case-report /
        GET /api/cases/{id}/audit)."""
        tenant = make_tenant_context()
        shared_case_id = uuid.uuid4()
        service, detection_repo, _, audit_repo, _ = _make_service([_pair("finding-a", "finding-b")])
        await _seed_detection(detection_repo, tenant.org_id, "finding-a", case_id=shared_case_id)
        await _seed_detection(detection_repo, tenant.org_id, "finding-b", case_id=shared_case_id)

        await service.sync_org_correlations(tenant, 0, 1)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        correlated = next(e for e in events if e.event_type == AuditEventType.DETECTION_CORRELATED)
        assert correlated.case_id == shared_case_id

    @pytest.mark.asyncio
    async def test_audit_event_case_id_is_none_when_detections_belong_to_different_cases(
        self,
    ) -> None:
        """A correlation can genuinely span two different cases (case
        correlation is only a best-effort parse of each finding's own
        source_index) -- the audit row must NOT claim either case's id in
        that situation, an honest None rather than a guessed/first-wins
        value (mirrors DetectionSinkPushService's own multi-case-batch
        handling, Gap Audit Milestone LL)."""
        tenant = make_tenant_context()
        service, detection_repo, _, audit_repo, _ = _make_service([_pair("finding-a", "finding-b")])
        await _seed_detection(detection_repo, tenant.org_id, "finding-a", case_id=uuid.uuid4())
        await _seed_detection(detection_repo, tenant.org_id, "finding-b", case_id=uuid.uuid4())

        await service.sync_org_correlations(tenant, 0, 1)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        correlated = next(e for e in events if e.event_type == AuditEventType.DETECTION_CORRELATED)
        assert correlated.case_id is None

    @pytest.mark.asyncio
    async def test_multiple_rule_ids_on_one_pair_are_preserved(self) -> None:
        tenant = make_tenant_context()
        service, detection_repo, correlation_repo, _, _ = _make_service(
            [_pair("finding-a", "finding-b", rules=("rule-1", "rule-2"))]
        )
        await _seed_detection(detection_repo, tenant.org_id, "finding-a")
        await _seed_detection(detection_repo, tenant.org_id, "finding-b")

        await service.sync_org_correlations(tenant, 0, 1)

        stored = [c async for c in correlation_repo.stream_by_org(tenant.org_id)][0]
        assert stored.rule_ids == ("rule-1", "rule-2")
