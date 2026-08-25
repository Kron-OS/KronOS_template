"""Unit tests for DetectionTriageService (mock nothing external -- InMemoryDetectionRepository
is a legitimate adapter double, same pattern as InMemoryCaseRepository elsewhere)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.detection_triage import DetectionTriageService
from src.domain.audit import AuditEventType
from src.domain.detection import Detection, DetectionTriageState
from src.exceptions import DetectionStateError, ValidationError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


def _make_detection(
    org_id: uuid.UUID, state: DetectionTriageState = DetectionTriageState.NEW
) -> Detection:
    return Detection(
        org_id=org_id,
        org_alias="testorg",
        case_id=uuid.uuid4(),
        finding_id=str(uuid.uuid4()),
        detector_name="kronos-testorg-network-detector",
        source_index="kronos-testorg-case-abc-202601",
        finding_timestamp=datetime.now(UTC),
        triage_state=state,
    )


def _make_service() -> (
    tuple[DetectionTriageService, InMemoryDetectionRepository, InMemoryAuditLogRepository]
):
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    repo = InMemoryDetectionRepository()
    return DetectionTriageService(repo, audit_log), repo, audit_repo


class TestDetectionTriageServiceValidTransitions:
    @pytest.mark.asyncio
    async def test_new_to_investigating(self) -> None:
        service, repo, _ = _make_service()
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        updated = await service.transition(
            detection.detection_id, DetectionTriageState.INVESTIGATING, tenant
        )

        assert updated.triage_state == DetectionTriageState.INVESTIGATING
        persisted = await repo.get_by_id(detection.detection_id, tenant.org_id)
        assert persisted is not None
        assert persisted.triage_state == DetectionTriageState.INVESTIGATING

    @pytest.mark.asyncio
    async def test_investigating_to_true_positive(self) -> None:
        service, repo, _ = _make_service()
        tenant = make_tenant_context()
        detection = await repo.save(
            _make_detection(tenant.org_id, DetectionTriageState.INVESTIGATING)
        )

        updated = await service.transition(
            detection.detection_id, DetectionTriageState.TRUE_POSITIVE, tenant
        )

        assert updated.triage_state == DetectionTriageState.TRUE_POSITIVE

    @pytest.mark.asyncio
    async def test_valid_transition_creates_real_audit_event(self) -> None:
        service, repo, audit_repo = _make_service()
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        await service.transition(detection.detection_id, DetectionTriageState.INVESTIGATING, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        transitioned = [
            e for e in events if e.event_type == AuditEventType.DETECTION_TRIAGE_TRANSITIONED
        ]
        assert len(transitioned) == 1
        assert transitioned[0].details["from_state"] == "NEW"
        assert transitioned[0].details["to_state"] == "INVESTIGATING"
        assert transitioned[0].row_hash is not None

    @pytest.mark.asyncio
    async def test_audit_event_hash_chain_links_correctly(self) -> None:
        """Two consecutive real transitions must produce a correctly linked
        hash chain (prev_row_hash of the second == row_hash of the first)."""
        service, repo, audit_repo = _make_service()
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        await service.transition(detection.detection_id, DetectionTriageState.INVESTIGATING, tenant)
        await service.transition(detection.detection_id, DetectionTriageState.TRUE_POSITIVE, tenant)

        events = sorted(
            [e async for e in audit_repo.stream_by_org(tenant.org_id)],
            key=lambda e: e.sequence_number,
        )
        assert len(events) == 2
        assert events[1].prev_row_hash == events[0].row_hash

        ok, detail = await AuditLogService(audit_repo).verify_chain(tenant.org_id)
        assert ok, detail


class TestDetectionTriageServiceIllegalTransitions:
    @pytest.mark.asyncio
    async def test_new_directly_to_true_positive_rejected(self) -> None:
        service, repo, _ = _make_service()
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        with pytest.raises(DetectionStateError):
            await service.transition(
                detection.detection_id, DetectionTriageState.TRUE_POSITIVE, tenant
            )

        # Rejected transition must not have mutated the stored row.
        persisted = await repo.get_by_id(detection.detection_id, tenant.org_id)
        assert persisted is not None
        assert persisted.triage_state == DetectionTriageState.NEW

    @pytest.mark.asyncio
    async def test_illegal_transition_creates_real_audit_event(self) -> None:
        service, repo, audit_repo = _make_service()
        tenant = make_tenant_context()
        detection = await repo.save(_make_detection(tenant.org_id))

        with pytest.raises(DetectionStateError):
            await service.transition(
                detection.detection_id, DetectionTriageState.FALSE_POSITIVE, tenant
            )

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        failed = [
            e for e in events if e.event_type == AuditEventType.DETECTION_TRIAGE_TRANSITION_FAILED
        ]
        assert len(failed) == 1
        assert failed[0].details["from_state"] == "NEW"
        assert failed[0].details["to_state"] == "FALSE_POSITIVE"

    @pytest.mark.asyncio
    async def test_terminal_state_rejects_further_transitions(self) -> None:
        service, repo, _ = _make_service()
        tenant = make_tenant_context()
        detection = await repo.save(
            _make_detection(tenant.org_id, DetectionTriageState.TRUE_POSITIVE)
        )

        with pytest.raises(DetectionStateError):
            await service.transition(
                detection.detection_id, DetectionTriageState.INVESTIGATING, tenant
            )

    @pytest.mark.asyncio
    async def test_transition_on_nonexistent_detection_raises_validation_error(self) -> None:
        service, _, _ = _make_service()
        tenant = make_tenant_context()

        with pytest.raises(ValidationError):
            await service.transition(uuid.uuid4(), DetectionTriageState.INVESTIGATING, tenant)

    @pytest.mark.asyncio
    async def test_transition_scoped_to_org_cannot_touch_other_orgs_detection(self) -> None:
        service, repo, _ = _make_service()
        owner_tenant = make_tenant_context()
        other_tenant = make_tenant_context()
        detection = await repo.save(_make_detection(owner_tenant.org_id))

        with pytest.raises(ValidationError):
            await service.transition(
                detection.detection_id, DetectionTriageState.INVESTIGATING, other_tenant
            )
