"""Unit tests for SyncDetectionToSiemAction's per-org rewrite (connector
marketplace, `/admin/connectors`; originally Gap Audit 2026-08 P1-1 /
roadmap Milestone V2, item a).

Real InMemoryDetectionRepository + real AuditLogService + real
ConnectorConfigService (in-memory repo/secret-store) + real
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
from src.adapter.repository.connector_config import InMemoryConnectorConfigRepository
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.connector_catalog import ConnectorCatalog
from src.application.connector_config import ConnectorConfigService
from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent
from src.application.secret_store import InMemorySecretStore
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


def _make_fixture(*, sink_name: str = "splunk-hec"):  # type: ignore[no-untyped-def]
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    repo = InMemoryDetectionRepository()
    connector_config_service = ConnectorConfigService(
        ConnectorCatalog(), InMemoryConnectorConfigRepository(), InMemorySecretStore(), audit_log
    )
    return repo, audit_repo, connector_config_service, audit_log


def _sink_factory(sink: IntegrationSink, mapper: DetectionEventMapper):  # type: ignore[no-untyped-def]
    """Test double for the ``sink_factory`` constructor param -- ignores
    the (source_type, config) args the real ``build_sink_and_mapper_from_config``
    would use and always returns the same pre-built fake, since these
    tests care about the action's own orchestration, not real sink
    construction (that's ``build_sink_and_mapper_from_config``'s own
    concern, covered separately)."""

    def factory(_source_type: str, _config: dict[str, str]):  # type: ignore[no-untyped-def]
        return sink, mapper

    return factory


async def _configure(
    connector_config_service: ConnectorConfigService, org_id: uuid.UUID, sink_name: str
) -> None:
    """Minimal config so resolve_runtime_config(org_id, sink_name) returns
    non-None -- these tests don't care about the actual field values since
    the sink_factory double ignores them."""
    catalog_entry = ConnectorCatalog().get(sink_name)
    assert catalog_entry is not None
    values = {p.name: "x" for p in catalog_entry.parameters if p.required}
    await connector_config_service.set_config(org_id, sink_name, values, actor_user_id=uuid.uuid4())


class TestSyncDetectionToSiemActionSuccess:
    def test_action_name_is_derived_from_sink_name(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "sentinel", repo, connector_config_service, _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()), audit_log
        )
        assert action.action_name == "sync_detection_to_siem_sentinel"

    @pytest.mark.asyncio
    async def test_pushes_detection_and_returns_real_result(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        sink = _FakeIntegrationSink()
        action = SyncDetectionToSiemAction(
            "splunk-hec", repo, connector_config_service, _sink_factory(sink, _PassthroughJsonMapper()), audit_log
        )
        tenant = make_tenant_context()
        await _configure(connector_config_service, tenant.org_id, "splunk-hec")
        detection = await repo.save(_make_detection(tenant.org_id))

        output = await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        assert output["detection_id"] == str(detection.detection_id)
        assert output["sink"] == "splunk-hec"
        assert output["batch_count"] == 1
        assert output["all_acknowledged"] is True
        assert output["ack_statuses"] == ["acknowledged"]
        assert len(sink.push_calls) == 1
        assert sink.push_calls[0][0].payload == {"finding_id": detection.finding_id}

    @pytest.mark.asyncio
    async def test_unacknowledged_sink_is_reported_honestly(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        sink = _FakeIntegrationSink(ack_status=SinkAckStatus.UNACKNOWLEDGED)
        action = SyncDetectionToSiemAction(
            "cef-syslog", repo, connector_config_service, _sink_factory(sink, _PassthroughJsonMapper()), audit_log
        )
        tenant = make_tenant_context()
        await _configure(connector_config_service, tenant.org_id, "cef-syslog")
        detection = await repo.save(_make_detection(tenant.org_id))

        output = await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        assert output["all_acknowledged"] is False
        assert output["ack_statuses"] == ["unacknowledged"]

    @pytest.mark.asyncio
    async def test_delegates_push_audit_to_detection_sink_push_service(self) -> None:
        """This action's own execute() must not duplicate SINK_PUSH_*
        auditing -- DetectionSinkPushService already does it (roadmap
        invariant #4), mirroring TransitionDetectionTriageAction's own
        "collaborator already audits itself" division of labor."""
        repo, audit_repo, connector_config_service, audit_log = _make_fixture()
        sink = _FakeIntegrationSink()
        action = SyncDetectionToSiemAction(
            "splunk-hec", repo, connector_config_service, _sink_factory(sink, _PassthroughJsonMapper()), audit_log
        )
        tenant = make_tenant_context()
        await _configure(connector_config_service, tenant.org_id, "splunk-hec")
        detection = await repo.save(_make_detection(tenant.org_id))

        await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        attempted = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_ATTEMPTED]
        executed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
        assert len(attempted) == 1
        assert len(executed) == 1
        assert attempted[0].details["detection_ids"] == [str(detection.detection_id)]

    @pytest.mark.asyncio
    async def test_successful_push_resets_consecutive_failure_count(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "splunk-hec",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        tenant = make_tenant_context()
        await _configure(connector_config_service, tenant.org_id, "splunk-hec")
        await connector_config_service.record_failure(tenant.org_id, "splunk-hec")
        detection = await repo.save(_make_detection(tenant.org_id))

        await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        summary = await connector_config_service.get_config(tenant.org_id, "splunk-hec")
        assert summary is not None
        assert summary.consecutive_failure_count == 0


class TestSyncDetectionToSiemActionFailureModes:
    @pytest.mark.asyncio
    async def test_backend_failure_is_audited_as_failed_reraised_and_recorded(self) -> None:
        repo, audit_repo, connector_config_service, audit_log = _make_fixture()
        sink = _FakeIntegrationSink(fail=True)
        action = SyncDetectionToSiemAction(
            "splunk-hec", repo, connector_config_service, _sink_factory(sink, _PassthroughJsonMapper()), audit_log
        )
        tenant = make_tenant_context()
        await _configure(connector_config_service, tenant.org_id, "splunk-hec")
        detection = await repo.save(_make_detection(tenant.org_id))

        with pytest.raises(IntegrationSinkError):
            await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        failed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_FAILED]
        executed = [e for e in events if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
        assert len(failed) == 1
        assert len(executed) == 0

        summary = await connector_config_service.get_config(tenant.org_id, "splunk-hec")
        assert summary is not None
        assert summary.consecutive_failure_count == 1

    @pytest.mark.asyncio
    async def test_unconfigured_org_raises_playbook_error_not_a_global_fallback(self) -> None:
        """The hard requirement: an org with no config for this sink must
        get a loud error, never silently fall back to some other org's
        (or a global) destination."""
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "sentinel",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        with pytest.raises(PlaybookError, match="not configured"):
            await action.execute({"detection_id": str(detection.detection_id)}, tenant)

    @pytest.mark.asyncio
    async def test_disabled_org_config_raises_playbook_error(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "splunk-hec",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        tenant = make_tenant_context()
        await _configure(connector_config_service, tenant.org_id, "splunk-hec")
        await connector_config_service.set_enabled(
            tenant.org_id, "splunk-hec", False, actor_user_id=uuid.uuid4()
        )
        detection = await repo.save(_make_detection(tenant.org_id))

        with pytest.raises(PlaybookError, match="not configured"):
            await action.execute({"detection_id": str(detection.detection_id)}, tenant)

    @pytest.mark.asyncio
    async def test_one_org_configuring_a_sink_never_affects_another_orgs_push(self) -> None:
        """Hard requirement (no collision, independent per client): org_b
        having no config must not be affected by org_a's real config for
        the same sink type."""
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "splunk-hec",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()
        await _configure(connector_config_service, tenant_a.org_id, "splunk-hec")
        detection_b = await repo.save(_make_detection(tenant_b.org_id))

        with pytest.raises(PlaybookError, match="not configured"):
            await action.execute({"detection_id": str(detection_b.detection_id)}, tenant_b)

    @pytest.mark.asyncio
    async def test_malformed_detection_id_raises_playbook_error(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "splunk-hec",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": "not-a-uuid"}, tenant)

    @pytest.mark.asyncio
    async def test_missing_detection_id_raises_playbook_error(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "splunk-hec",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({}, tenant)

    @pytest.mark.asyncio
    async def test_cross_tenant_detection_id_raises_playbook_error(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "splunk-hec",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        owner_tenant = make_tenant_context()
        other_tenant = make_tenant_context()
        detection = await repo.save(_make_detection(owner_tenant.org_id))

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": str(detection.detection_id)}, other_tenant)

    @pytest.mark.asyncio
    async def test_nonexistent_detection_id_raises_playbook_error(self) -> None:
        repo, _audit_repo, connector_config_service, audit_log = _make_fixture()
        action = SyncDetectionToSiemAction(
            "splunk-hec",
            repo,
            connector_config_service,
            _sink_factory(_FakeIntegrationSink(), _PassthroughJsonMapper()),
            audit_log,
        )
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": str(uuid.uuid4())}, tenant)
