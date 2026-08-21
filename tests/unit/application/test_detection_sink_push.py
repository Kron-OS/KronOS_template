"""Unit tests for DetectionSinkPushService (roadmap R1).

Real InMemoryAuditLogRepository + real AuditLogService (mirrors
test_ticket_sync_action.py's own style) -- IntegrationSink/DetectionEventMapper
are minimal, real, in-process test doubles here since the real
HTTP/syslog-speaking implementations already have their own dedicated tests
(test_http_json_sink.py, test_syslog_sink.py) per CLAUDE.md SS B.5 "mock
only external dependencies."
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.application.audit_log import AuditLogService
from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent
from src.application.detection_sink_push import DetectionSinkPushService
from src.domain.audit import AuditEventType
from src.domain.detection import Detection, DetectionRuleMatch
from src.domain.integration_sink import SinkAck, SinkAckStatus
from src.exceptions import IntegrationSinkError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


def _make_detection(org_id: uuid.UUID, finding_id: str | None = None) -> Detection:
    return Detection(
        org_id=org_id,
        org_alias="testorg",
        case_id=uuid.uuid4(),
        finding_id=finding_id or str(uuid.uuid4()),
        detector_name="kronos-testorg-network-detector",
        source_index="kronos-testorg-case-abc-202601",
        rule_matches=(DetectionRuleMatch(rule_id="r1", tags=("high", "attack.t1021.001")),),
        finding_timestamp=datetime.now(UTC),
    )


class _PassthroughJsonMapper(DetectionEventMapper):
    def map(self, detection: Detection) -> MappedSinkEvent:
        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            payload={"finding_id": detection.finding_id},
        )


class _FakeIntegrationSink(IntegrationSink):
    """A minimal, real, in-process IntegrationSink -- proves the service's
    own map -> batch -> push -> audit sequence without needing a real
    transport (which HttpJsonIntegrationSink/SyslogIntegrationSink already
    have their own dedicated, transport-level tests for)."""

    def __init__(
        self,
        *,
        fail: bool = False,
        max_batch_events: int | None = None,
        ack_status: SinkAckStatus = SinkAckStatus.ACKNOWLEDGED,
    ) -> None:
        self.fail = fail
        self._max_batch_events = max_batch_events
        self._ack_status = ack_status
        self.push_calls: list[list[MappedSinkEvent]] = []

    @property
    def max_batch_events(self) -> int | None:
        return self._max_batch_events

    async def push_events(self, events):  # type: ignore[no-untyped-def]
        if self.fail:
            raise IntegrationSinkError("real, deliberate backend failure for this test")
        self.push_calls.append(list(events))
        return SinkAck(status=self._ack_status, detail={"event_count": len(events)})


def _make_service(
    sink: IntegrationSink,
) -> tuple[DetectionSinkPushService, InMemoryAuditLogRepository]:
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    service = DetectionSinkPushService(sink, _PassthroughJsonMapper(), audit_log)
    return service, audit_repo


class TestDetectionSinkPushServiceSuccess:
    @pytest.mark.asyncio
    async def test_single_batch_push_returns_acknowledged_result(self) -> None:
        sink = _FakeIntegrationSink()
        service, _ = _make_service(sink)
        tenant = make_tenant_context()
        detections = [_make_detection(tenant.org_id) for _ in range(3)]

        result = await service.push(detections, tenant)

        assert result.detection_count == 3
        assert result.batch_count == 1
        assert result.all_acknowledged is True
        assert len(sink.push_calls) == 1
        assert len(sink.push_calls[0]) == 3

    @pytest.mark.asyncio
    async def test_batching_respects_sink_max_batch_events(self) -> None:
        sink = _FakeIntegrationSink(max_batch_events=2)
        service, _ = _make_service(sink)
        tenant = make_tenant_context()
        detections = [_make_detection(tenant.org_id) for _ in range(5)]

        result = await service.push(detections, tenant)

        assert result.batch_count == 3
        assert [len(c) for c in sink.push_calls] == [2, 2, 1]

    @pytest.mark.asyncio
    async def test_unacknowledged_ack_surfaces_honestly_in_result(self) -> None:
        sink = _FakeIntegrationSink(ack_status=SinkAckStatus.UNACKNOWLEDGED)
        service, _ = _make_service(sink)
        tenant = make_tenant_context()
        detections = [_make_detection(tenant.org_id)]

        result = await service.push(detections, tenant)

        assert result.all_acknowledged is False
        assert result.acks[0].status == SinkAckStatus.UNACKNOWLEDGED

    @pytest.mark.asyncio
    async def test_audits_attempted_and_executed_per_batch(self) -> None:
        sink = _FakeIntegrationSink(max_batch_events=2)
        service, audit_repo = _make_service(sink)
        tenant = make_tenant_context()
        detections = [_make_detection(tenant.org_id) for _ in range(3)]

        await service.push(detections, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        attempted = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_ATTEMPTED]
        executed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
        assert len(attempted) == 2  # 2 batches: [2, 1]
        assert len(executed) == 2
        assert executed[0].details["ack_status"] == SinkAckStatus.ACKNOWLEDGED.value
        assert executed[0].row_hash is not None

    @pytest.mark.asyncio
    async def test_audit_rows_are_case_scoped_for_a_single_detection_batch(self) -> None:
        """Gap Audit Milestone LL: case_id must be populated so these rows
        are visible to kronos-attest case-report / GET /api/cases/{id}/audit,
        mirroring DetectionTriageService.transition()'s own real pattern."""
        sink = _FakeIntegrationSink()
        service, audit_repo = _make_service(sink)
        tenant = make_tenant_context()
        detection = _make_detection(tenant.org_id)

        await service.push([detection], tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        assert len(events) == 2  # ATTEMPTED, EXECUTED
        assert all(e.case_id == detection.case_id for e in events)

    @pytest.mark.asyncio
    async def test_case_id_is_none_for_a_batch_spanning_multiple_cases(self) -> None:
        """A batch is never assumed to share one case just because it's one
        batch -- an honest None beats a guessed/first-wins value when the
        real detections in it actually belong to different cases."""
        sink = _FakeIntegrationSink()
        service, audit_repo = _make_service(sink)
        tenant = make_tenant_context()
        detections = [_make_detection(tenant.org_id), _make_detection(tenant.org_id)]
        assert detections[0].case_id != detections[1].case_id  # real, independent case_ids

        await service.push(detections, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        assert all(e.case_id is None for e in events)

    @pytest.mark.asyncio
    async def test_empty_detections_produces_zero_batches_no_audit(self) -> None:
        sink = _FakeIntegrationSink()
        service, audit_repo = _make_service(sink)
        tenant = make_tenant_context()

        result = await service.push([], tenant)

        assert result.detection_count == 0
        assert result.batch_count == 0
        assert result.acks == ()
        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        assert events == []


class TestDetectionSinkPushServiceFailure:
    @pytest.mark.asyncio
    async def test_sink_failure_is_audited_as_failed_and_reraised(self) -> None:
        sink = _FakeIntegrationSink(fail=True)
        service, audit_repo = _make_service(sink)
        tenant = make_tenant_context()
        detections = [_make_detection(tenant.org_id)]

        with pytest.raises(IntegrationSinkError):
            await service.push(detections, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        attempted = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_ATTEMPTED]
        failed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_FAILED]
        executed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
        assert len(attempted) == 1
        assert len(failed) == 1
        assert len(executed) == 0
        assert "real, deliberate backend failure" in failed[0].details["error"]

    @pytest.mark.asyncio
    async def test_attempted_logged_before_the_failure_never_erased(self) -> None:
        # Even though push_events() raises, ATTEMPTED must already be a
        # durable, persisted fact (mirrors ContainmentAction/
        # SyncDetectionTicketAction's own "ATTEMPTED before the real call"
        # discipline exactly).
        sink = _FakeIntegrationSink(fail=True)
        service, audit_repo = _make_service(sink)
        tenant = make_tenant_context()

        with pytest.raises(IntegrationSinkError):
            await service.push([_make_detection(tenant.org_id)], tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        assert events[0].event_type == AuditEventType.SINK_PUSH_ATTEMPTED

    @pytest.mark.asyncio
    async def test_partial_batch_failure_halts_remaining_batches(self) -> None:
        # First batch succeeds, second is configured to fail -- the service
        # must not silently continue to a third batch (fail-fast, mirrors
        # TicketingSystem/ContainmentAction's own "raise, don't return a
        # partial success" idiom).
        class _FlakyAfterFirstSink(IntegrationSink):
            def __init__(self) -> None:
                self.calls = 0

            @property
            def max_batch_events(self) -> int | None:
                return 1

            async def push_events(self, events):  # type: ignore[no-untyped-def]
                self.calls += 1
                if self.calls == 2:
                    raise IntegrationSinkError("second batch deliberately fails")
                return SinkAck(status=SinkAckStatus.ACKNOWLEDGED)

        sink = _FlakyAfterFirstSink()
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        service = DetectionSinkPushService(sink, _PassthroughJsonMapper(), audit_log)
        tenant = make_tenant_context()
        detections = [_make_detection(tenant.org_id) for _ in range(3)]

        with pytest.raises(IntegrationSinkError):
            await service.push(detections, tenant)

        assert sink.calls == 2  # never attempted the 3rd batch
