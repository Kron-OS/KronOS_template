"""Unit tests for the concrete PlaybookAction implementations (roadmap M7/H1)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.detection_triage import DetectionTriageService
from src.application.playbook_actions import LogNotificationAction, TransitionDetectionTriageAction
from src.domain.detection import Detection, DetectionTriageState
from src.exceptions import DetectionStateError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class TestTransitionDetectionTriageAction:
    @pytest.mark.asyncio
    async def test_real_transition_succeeds_and_returns_new_state(self) -> None:
        tenant = make_tenant_context()
        repo = InMemoryDetectionRepository()
        detection = Detection(
            org_id=tenant.org_id,
            org_alias=tenant.org_alias,
            finding_id="finding-1",
            detector_name="kronos-testorg-windows-detector",
            source_index="kronos-testorg-case-abc-202601",
            finding_timestamp=datetime.now(UTC),
        )
        await repo.save(detection)
        triage = DetectionTriageService(repo, AuditLogService(InMemoryAuditLogRepository()))
        action = TransitionDetectionTriageAction(triage)

        output = await action.execute(
            {"detection_id": str(detection.detection_id), "target_state": "INVESTIGATING"},
            tenant,
        )

        assert output == {
            "detection_id": str(detection.detection_id),
            "triage_state": "INVESTIGATING",
        }
        stored = await repo.get_by_id(detection.detection_id, tenant.org_id)
        assert stored is not None
        assert stored.triage_state == DetectionTriageState.INVESTIGATING

    @pytest.mark.asyncio
    async def test_illegal_fsm_transition_raises_the_real_underlying_error(self) -> None:
        tenant = make_tenant_context()
        repo = InMemoryDetectionRepository()
        detection = Detection(
            org_id=tenant.org_id,
            org_alias=tenant.org_alias,
            finding_id="finding-2",
            detector_name="kronos-testorg-windows-detector",
            source_index="kronos-testorg-case-abc-202601",
            finding_timestamp=datetime.now(UTC),
        )
        await repo.save(detection)
        triage = DetectionTriageService(repo, AuditLogService(InMemoryAuditLogRepository()))
        action = TransitionDetectionTriageAction(triage)

        # NEW -> TRUE_POSITIVE directly is not a legal transition.
        with pytest.raises(DetectionStateError):
            await action.execute(
                {"detection_id": str(detection.detection_id), "target_state": "TRUE_POSITIVE"},
                tenant,
            )

    @pytest.mark.asyncio
    async def test_malformed_params_raise_playbook_error_not_a_silent_no_op(self) -> None:
        tenant = make_tenant_context()
        repo = InMemoryDetectionRepository()
        triage = DetectionTriageService(repo, AuditLogService(InMemoryAuditLogRepository()))
        action = TransitionDetectionTriageAction(triage)

        from src.exceptions import PlaybookError

        with pytest.raises(PlaybookError):
            await action.execute(
                {"detection_id": "not-a-uuid", "target_state": "INVESTIGATING"}, tenant
            )

        with pytest.raises(PlaybookError):
            await action.execute(
                {"detection_id": str(uuid.uuid4()), "target_state": "NOT_A_REAL_STATE"}, tenant
            )


class TestLogNotificationAction:
    @pytest.mark.asyncio
    async def test_returns_the_message_verbatim(self) -> None:
        action = LogNotificationAction()
        tenant = make_tenant_context()

        output = await action.execute({"message": "real notification text"}, tenant)

        assert output == {"message": "real notification text"}

    @pytest.mark.asyncio
    async def test_missing_message_raises_playbook_error(self) -> None:
        from src.exceptions import PlaybookError

        action = LogNotificationAction()
        tenant = make_tenant_context()

        with pytest.raises(PlaybookError):
            await action.execute({}, tenant)

        with pytest.raises(PlaybookError):
            await action.execute({"message": ""}, tenant)
