"""Unit tests for SyncDetectionToSiemAction (Gap Audit 2026-08 P1-1 /
roadmap Milestone V2, item a).

Real InMemoryDetectionRepository + real AuditLogService + real
DetectionSinkPushService (mirrors test_ticket_sync_action.py's own style)
-- only IntegrationSink is a minimal, real, in-process test double (the
real HTTP/syslog-speaking sinks already have their own dedicated tests)
per CLAUDE.md SS B.5 "mock only external dependencies."
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent
from src.application.detection_sink_push import DetectionSinkPushService
from src.application.sync_detection_to_siem_action import SyncDetectionToSiemAction
from src.domain.audit import AuditEventType
from src.domain.detection import Detection, DetectionRuleMatch
from src.domain.integration_sink import SinkAck, SinkAckStatus
from src.exceptions import IntegrationSinkError, PlaybookError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


def _make_detection(org_id: uuid.UUID) -> Detection:
    return Detection(
        org_id=org_id,
        org_alias="testorg",
        case_id=uuid.uuid4(),
        finding_id=str(uuid.uuid4()),
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
    """Minimal, real, in-process IntegrationSink -- same shape as
    test_detection_sink_push.py's own double, reused here since this
    action's own job is to be a thin adapter in front of that already-
    tested map -> batch -> push -> audit sequence, not to re-prove it."""

    def __init__(
        self, *, fail: bool = False, ack_status: SinkAckStatus = SinkAckStatus.ACKNOWLEDGED
    ) -> None:
        self.fail = fail
        self._ack_status = ack_status
        self.push_calls: list[list[MappedSinkEvent]] = []

    async def push_events(self, events):  # type: ignore[no-untyped-def]
        if self.fail:
            raise IntegrationSinkError("real, deliberate backend failure for this test")
        self.push_calls.append(list(events))
        return SinkAck(status=self._ack_status, detail={"event_count": len(events)})


def _make_action(
    sink: IntegrationSink, *, sink_name: str = "splunk"
) -> tuple[SyncDetectionToSiemAction, InMemoryDetectionRepository, InMemoryAuditLogRepository]:
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    repo = InMemoryDetectionRepository()
    push_service = DetectionSinkPushService(sink, _PassthroughJsonMapper(), audit_log)
    return SyncDetectionToSiemAction(sink_name, repo, push_service), repo, audit_repo


class TestSyncDetectionToSiemActionSuccess:
    def test_action_name_is_derived_from_sink_name(self) -> None:
        action, _, _ = _make_action(_FakeIntegrationSink(), sink_name="sentinel")
        assert action.action_name == "sync_detection_to_siem_sentinel"

    @pytest.mark.asyncio
    async def test_pushes_detection_and_returns_real_result(self) -> None:
        sink = _FakeIntegrationSink()
        action, repo, _ = _make_action(sink)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        output = await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        assert output["detection_id"] == str(detection.detection_id)
        assert output["sink"] == "splunk"
        assert output["batch_count"] == 1
        assert output["all_acknowledged"] is True
        assert output["ack_statuses"] == ["acknowledged"]
        assert len(sink.push_calls) == 1
        assert sink.push_calls[0][0].payload == {"finding_id": detection.finding_id}

    @pytest.mark.asyncio
    async def test_unacknowledged_sink_is_reported_honestly(self) -> None:
        sink = _FakeIntegrationSink(ack_status=SinkAckStatus.UNACKNOWLEDGED)
        action, repo, _ = _make_action(sink, sink_name="cef")
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        output = await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        assert output["all_acknowledged"] is False
        assert output["ack_statuses"] == ["unacknowledged"]

    @pytest.mark.asyncio
    async def test_delegates_audit_to_detection_sink_push_service(self) -> None:
        """This action's own execute() must not duplicate SINK_PUSH_*
        auditing -- DetectionSinkPushService already does it (roadmap
        invariant #4), mirroring TransitionDetectionTriageAction's own
        "collaborator already audits itself" division of labor."""
        sink = _FakeIntegrationSink()
        action, repo, audit_repo = _make_action(sink)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        attempted = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_ATTEMPTED]
        executed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
        assert len(attempted) == 1
        assert len(executed) == 1
        assert attempted[0].details["detection_ids"] == [str(detection.detection_id)]


class TestSyncDetectionToSiemActionFailureModes:
    @pytest.mark.asyncio
    async def test_backend_failure_is_audited_as_failed_and_reraised(self) -> None:
        sink = _FakeIntegrationSink(fail=True)
        action, repo, audit_repo = _make_action(sink)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        with pytest.raises(IntegrationSinkError):
            await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        failed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_FAILED]
        executed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
        assert len(failed) == 1
        assert len(executed) == 0

    @pytest.mark.asyncio
    async def test_malformed_detection_id_raises_playbook_error(self) -> None:
        action, _, _ = _make_action(_FakeIntegrationSink())
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": "not-a-uuid"}, tenant)

    @pytest.mark.asyncio
    async def test_missing_detection_id_raises_playbook_error(self) -> None:
        action, _, _ = _make_action(_FakeIntegrationSink())
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({}, tenant)

    @pytest.mark.asyncio
    async def test_cross_tenant_detection_id_raises_playbook_error(self) -> None:
        action, repo, _ = _make_action(_FakeIntegrationSink())
        owner_tenant = make_tenant_context()
        other_tenant = make_tenant_context()
        detection = await repo.save(_make_detection(owner_tenant.org_id))

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": str(detection.detection_id)}, other_tenant)

    @pytest.mark.asyncio
    async def test_nonexistent_detection_id_raises_playbook_error(self) -> None:
        action, _, _ = _make_action(_FakeIntegrationSink())
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": str(uuid.uuid4())}, tenant)
