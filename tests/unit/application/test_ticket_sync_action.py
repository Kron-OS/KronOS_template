"""Unit tests for SyncDetectionTicketAction (roadmap M7/H4).

Real InMemoryDetectionRepository + real AuditLogService (mirrors
test_detection_triage.py/test_containment_action.py's own style) -- only
TicketingSystem is a minimal, real, in-process test double (never a
web-scale mock), since the real HTTP-speaking implementation
(WebhookTicketingSystem) already has its own dedicated tests
(test_ticketing_system.py) per CLAUDE.md SS B.5 "mock only external
dependencies."
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from src.adapter.repository.detection import InMemoryDetectionRepository
from src.adapter.ticketing.ticketing_system import TicketingSystem, TicketRef
from src.application.audit_log import AuditLogService
from src.application.ticket_sync_action import SyncDetectionTicketAction
from src.domain.audit import AuditEventType
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState
from src.exceptions import PlaybookError, StorageError, TicketingError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class _FakeTicketingSystem(TicketingSystem):
    """A minimal, real, in-process TicketingSystem -- proves the action's
    own create-vs-update decision logic without needing real HTTP."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.create_calls: list[dict[str, Any]] = []
        self.update_calls: list[dict[str, Any]] = []
        self._counter = 0

    async def create_ticket(
        self, *, title: str, description: str, severity: str | None, metadata: dict[str, Any]
    ) -> TicketRef:
        if self.fail:
            raise TicketingError("real, deliberate backend failure for this test")
        self._counter += 1
        self.create_calls.append(
            {"title": title, "description": description, "severity": severity, "metadata": metadata}
        )
        return TicketRef(
            ticket_id=f"TICKET-{self._counter}", url=f"http://itsm.invalid/{self._counter}"
        )

    async def update_ticket(
        self, ticket_id: str, *, note: str, metadata: dict[str, Any]
    ) -> TicketRef:
        if self.fail:
            raise TicketingError("real, deliberate backend failure for this test")
        self.update_calls.append({"ticket_id": ticket_id, "note": note, "metadata": metadata})
        return TicketRef(ticket_id=ticket_id)


def _make_detection(
    org_id: uuid.UUID, external_ticket_id: str | None = None, case_id: uuid.UUID | None = None
) -> Detection:
    return Detection(
        org_id=org_id,
        org_alias="testorg",
        case_id=case_id if case_id is not None else uuid.uuid4(),
        finding_id=str(uuid.uuid4()),
        detector_name="kronos-testorg-network-detector",
        source_index="kronos-testorg-case-abc-202601",
        rule_matches=(DetectionRuleMatch(rule_id="r1", tags=("high", "attack.t1021.001")),),
        finding_timestamp=datetime.now(UTC),
        triage_state=DetectionTriageState.NEW,
        external_ticket_id=external_ticket_id,
    )


def _make_action(
    ticketing: TicketingSystem,
) -> tuple[SyncDetectionTicketAction, InMemoryDetectionRepository, InMemoryAuditLogRepository]:
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    repo = InMemoryDetectionRepository()
    return SyncDetectionTicketAction(repo, ticketing, audit_log), repo, audit_repo


class TestSyncDetectionTicketActionCreate:
    def test_action_name(self) -> None:
        action, _, _ = _make_action(_FakeTicketingSystem())
        assert action.action_name == "sync_detection_ticket"

    @pytest.mark.asyncio
    async def test_first_sync_creates_a_ticket(self) -> None:
        ticketing = _FakeTicketingSystem()
        action, repo, _ = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        output = await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        assert output["operation"] == "create"
        assert output["external_ticket_id"] == "TICKET-1"
        assert len(ticketing.create_calls) == 1
        assert ticketing.create_calls[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_create_persists_external_ticket_id_on_detection(self) -> None:
        ticketing = _FakeTicketingSystem()
        action, repo, _ = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        persisted = await repo.get_by_id(detection.detection_id, tenant.org_id)
        assert persisted is not None
        assert persisted.external_ticket_id == "TICKET-1"

    @pytest.mark.asyncio
    async def test_create_does_not_touch_triage_state(self) -> None:
        ticketing = _FakeTicketingSystem()
        action, repo, _ = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        persisted = await repo.get_by_id(detection.detection_id, tenant.org_id)
        assert persisted is not None
        assert persisted.triage_state == DetectionTriageState.NEW

    @pytest.mark.asyncio
    async def test_create_audits_attempted_and_executed(self) -> None:
        ticketing = _FakeTicketingSystem()
        action, repo, audit_repo = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        attempted = [e for e in events if e.event_type == AuditEventType.TICKET_SYNC_ATTEMPTED]
        executed = [e for e in events if e.event_type == AuditEventType.TICKET_SYNC_EXECUTED]
        assert len(attempted) == 1
        assert attempted[0].details["operation"] == "create"
        assert attempted[0].details["existing_ticket_id"] is None
        assert len(executed) == 1
        assert executed[0].details["external_ticket_id"] == "TICKET-1"
        assert executed[0].row_hash is not None


class TestSyncDetectionTicketActionUpdate:
    @pytest.mark.asyncio
    async def test_second_sync_updates_the_existing_ticket(self) -> None:
        ticketing = _FakeTicketingSystem()
        action, repo, _ = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id, external_ticket_id="TICKET-99"))

        output = await action.execute(
            {"detection_id": str(detection.detection_id), "note": "escalated"}, tenant
        )

        assert output["operation"] == "update"
        assert output["external_ticket_id"] == "TICKET-99"
        assert len(ticketing.update_calls) == 1
        assert ticketing.update_calls[0]["note"] == "escalated"
        assert len(ticketing.create_calls) == 0

    @pytest.mark.asyncio
    async def test_update_uses_default_note_when_not_supplied(self) -> None:
        ticketing = _FakeTicketingSystem()
        action, repo, _ = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id, external_ticket_id="TICKET-99"))

        await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        assert ticketing.update_calls[0]["note"]


class TestSyncDetectionTicketActionFailureModes:
    @pytest.mark.asyncio
    async def test_backend_failure_is_audited_as_failed_and_reraised(self) -> None:
        ticketing = _FakeTicketingSystem(fail=True)
        action, repo, audit_repo = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        with pytest.raises(TicketingError):
            await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        failed = [e for e in events if e.event_type == AuditEventType.TICKET_SYNC_FAILED]
        executed = [e for e in events if e.event_type == AuditEventType.TICKET_SYNC_EXECUTED]
        assert len(failed) == 1
        assert len(executed) == 0
        # Detection itself must be unchanged -- no fabricated ticket id.
        persisted = await repo.get_by_id(detection.detection_id, tenant.org_id)
        assert persisted is not None
        assert persisted.external_ticket_id is None

    @pytest.mark.asyncio
    async def test_malformed_detection_id_raises_playbook_error(self) -> None:
        action, _, _ = _make_action(_FakeTicketingSystem())
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": "not-a-uuid"}, tenant)

    @pytest.mark.asyncio
    async def test_missing_detection_id_raises_playbook_error(self) -> None:
        action, _, _ = _make_action(_FakeTicketingSystem())
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({}, tenant)

    @pytest.mark.asyncio
    async def test_cross_tenant_detection_id_raises_playbook_error(self) -> None:
        action, repo, _ = _make_action(_FakeTicketingSystem())
        owner_tenant = make_tenant_context()
        other_tenant = make_tenant_context()
        detection = await repo.save(_make_detection(owner_tenant.org_id))

        with pytest.raises(PlaybookError):
            await action.execute({"detection_id": str(detection.detection_id)}, other_tenant)

    @pytest.mark.asyncio
    async def test_concurrent_triage_change_is_a_real_conflict_not_a_silent_overwrite(self) -> None:
        """If the Detection's triage_state changed between this action's own
        read and its write-back, the optimistic-concurrency check on
        `update(..., expected_state=...)` must reject the write rather than
        silently reverting the concurrent triage transition (roadmap
        invariant #5 applied to a race, not just a single-threaded flow)."""
        ticketing = _FakeTicketingSystem()
        action, repo, audit_repo = _make_action(ticketing)
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        # Simulate a concurrent, legitimate triage transition landing between
        # this action's own get_by_id() and its later update() call by
        # monkeypatching get_by_id to return the ORIGINAL snapshot while the
        # repo's real stored row has already moved on.
        original_get_by_id = repo.get_by_id
        call_count = {"n": 0}

        async def racy_get_by_id(detection_id: uuid.UUID, org_id: uuid.UUID) -> Detection | None:
            call_count["n"] += 1
            result = await original_get_by_id(detection_id, org_id)
            if call_count["n"] == 1 and result is not None:
                # Land the "concurrent" transition only after this action has
                # already captured its own stale in-memory snapshot.
                investigating = result.with_triage_state(DetectionTriageState.INVESTIGATING)
                await repo.update(investigating, expected_state=DetectionTriageState.NEW)
            return result

        repo.get_by_id = racy_get_by_id  # type: ignore[method-assign]

        with pytest.raises(StorageError):
            await action.execute({"detection_id": str(detection.detection_id)}, tenant)

        persisted = await original_get_by_id(detection.detection_id, tenant.org_id)
        assert persisted is not None
        # The concurrent transition must survive -- never rolled back.
        assert persisted.triage_state == DetectionTriageState.INVESTIGATING
        # And the ticket call that DID succeed is reported, not silently lost.
        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        failed = [e for e in events if e.event_type == AuditEventType.TICKET_SYNC_FAILED]
        assert len(failed) == 1
        assert failed[0].details["external_ticket_id"] == "TICKET-1"
