"""Unit / true end-to-end tests for PlaybookExecutionService (roadmap M7/H1).

Mirrors test_correlation_sync.py's own style: real InMemoryAuditLogRepository
+ real AuditLogService, only fake/stub the collaborators that would
otherwise need real I/O.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.application.audit_log import AuditLogService
from src.application.playbook import PlaybookAction, PlaybookActionRegistry
from src.application.playbook_execution import PlaybookExecutionService
from src.domain.audit import AuditEventType
from src.domain.playbook import Playbook, PlaybookStep, PlaybookStepOutcome
from src.domain.user import TenantContext
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class _EchoAction(PlaybookAction):
    """A real, minimal action: returns its own params verbatim as output."""

    @property
    def action_name(self) -> str:
        return "echo"

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        return dict(params)


class _AlwaysFailsAction(PlaybookAction):
    @property
    def action_name(self) -> str:
        return "always_fails"

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        raise RuntimeError("real, deliberate failure for this test")


class _SecondRealAction(PlaybookAction):
    """A second, independently-authored action -- proves the registry needs
    zero changes to run a brand-new action alongside an existing one."""

    @property
    def action_name(self) -> str:
        return "second_action"

    async def execute(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        return {"ran": "second_action", "org_id": str(tenant.org_id)}


@pytest.fixture
def audit_repo() -> InMemoryAuditLogRepository:
    return InMemoryAuditLogRepository()


@pytest.fixture
def audit_log(audit_repo: InMemoryAuditLogRepository) -> AuditLogService:
    return AuditLogService(audit_repo)


class TestPlaybookActionRegistry:
    def test_new_action_is_registration_only_no_engine_change(self) -> None:
        """Registering a second, independently-authored action requires
        zero edits to PlaybookActionRegistry or PlaybookExecutionService --
        roadmap H1's own binding "new action = registration, not an edit"
        requirement, proved directly rather than asserted."""
        registry = PlaybookActionRegistry()
        registry.register(_EchoAction())
        registry.register(_SecondRealAction())

        assert registry.get_action("echo") is not None
        assert registry.get_action("second_action") is not None

    def test_unregistered_action_returns_none_not_a_fabricated_default(self) -> None:
        registry = PlaybookActionRegistry()
        assert registry.get_action("nonexistent") is None


class TestPlaybookExecutionServiceSuccessPath:
    @pytest.mark.asyncio
    async def test_every_step_success_output_and_input_recorded(
        self, audit_log: AuditLogService
    ) -> None:
        registry = PlaybookActionRegistry()
        registry.register(_EchoAction())
        service = PlaybookExecutionService(registry, audit_log)
        tenant = make_tenant_context()

        playbook = Playbook(
            name="two-step-echo",
            steps=(
                PlaybookStep(step_id="s1", action_name="echo", params={"a": 1}),
                PlaybookStep(step_id="s2", action_name="echo", params={"b": 2}),
            ),
        )

        result = await service.execute(playbook, tenant)

        assert result.succeeded is True
        assert result.halted_early is False
        assert len(result.step_results) == 2
        assert result.step_results[0].outcome == PlaybookStepOutcome.SUCCESS
        assert result.step_results[0].output == {"a": 1}
        assert result.step_results[1].output == {"b": 2}

    @pytest.mark.asyncio
    async def test_real_audit_rows_cover_start_each_step_and_completion(
        self, audit_log: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        registry = PlaybookActionRegistry()
        registry.register(_EchoAction())
        service = PlaybookExecutionService(registry, audit_log)
        tenant = make_tenant_context()

        playbook = Playbook(
            name="one-step",
            steps=(PlaybookStep(step_id="s1", action_name="echo", params={"x": "y"}),),
        )
        await service.execute(playbook, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        event_types = [e.event_type for e in events]
        assert AuditEventType.PLAYBOOK_EXECUTION_STARTED in event_types
        assert AuditEventType.PLAYBOOK_STEP_EXECUTED in event_types
        assert AuditEventType.PLAYBOOK_EXECUTION_COMPLETED in event_types

        step_event = next(
            e for e in events if e.event_type == AuditEventType.PLAYBOOK_STEP_EXECUTED
        )
        assert step_event.details["step_id"] == "s1"
        assert step_event.details["action_name"] == "echo"
        assert step_event.details["params"] == {"x": "y"}
        assert step_event.details["output"] == {"x": "y"}

    @pytest.mark.asyncio
    async def test_real_hash_chain_is_intact_after_a_full_execution(
        self, audit_log: AuditLogService
    ) -> None:
        registry = PlaybookActionRegistry()
        registry.register(_EchoAction())
        service = PlaybookExecutionService(registry, audit_log)
        tenant = make_tenant_context()

        playbook = Playbook(
            name="chain-check",
            steps=(
                PlaybookStep(step_id="s1", action_name="echo", params={}),
                PlaybookStep(step_id="s2", action_name="echo", params={}),
            ),
        )
        await service.execute(playbook, tenant)

        intact, detail = await audit_log.verify_chain(tenant.org_id)
        assert intact is True
        assert detail is None


class TestPlaybookExecutionServiceFailurePath:
    @pytest.mark.asyncio
    async def test_a_failing_step_halts_remaining_steps_and_is_audited(
        self, audit_log: AuditLogService
    ) -> None:
        registry = PlaybookActionRegistry()
        registry.register(_AlwaysFailsAction())
        registry.register(_EchoAction())
        service = PlaybookExecutionService(registry, audit_log)
        tenant = make_tenant_context()

        playbook = Playbook(
            name="fail-then-echo",
            steps=(
                PlaybookStep(step_id="s1", action_name="always_fails", params={}),
                PlaybookStep(step_id="s2", action_name="echo", params={"never": "runs"}),
            ),
        )
        result = await service.execute(playbook, tenant)

        assert result.halted_early is True
        assert result.succeeded is False
        # Only the failing step ran -- the second, unreachable step must
        # not appear in the result at all (fail-fast, see module docstring).
        assert len(result.step_results) == 1
        assert result.step_results[0].outcome == PlaybookStepOutcome.FAILED
        assert "real, deliberate failure" in (result.step_results[0].error or "")

    @pytest.mark.asyncio
    async def test_failure_produces_a_real_audited_step_failed_event(
        self, audit_log: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        registry = PlaybookActionRegistry()
        registry.register(_AlwaysFailsAction())
        service = PlaybookExecutionService(registry, audit_log)
        tenant = make_tenant_context()

        playbook = Playbook(
            name="always-fails",
            steps=(PlaybookStep(step_id="s1", action_name="always_fails", params={}),),
        )
        await service.execute(playbook, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        failed_events = [e for e in events if e.event_type == AuditEventType.PLAYBOOK_STEP_FAILED]
        assert len(failed_events) == 1
        assert failed_events[0].details["step_id"] == "s1"
        assert "real, deliberate failure" in failed_events[0].details["error"]

    @pytest.mark.asyncio
    async def test_unregistered_action_is_an_honest_failure_not_a_silent_skip(
        self, audit_log: AuditLogService
    ) -> None:
        registry = PlaybookActionRegistry()  # nothing registered
        service = PlaybookExecutionService(registry, audit_log)
        tenant = make_tenant_context()

        playbook = Playbook(
            name="missing-action",
            steps=(PlaybookStep(step_id="s1", action_name="does_not_exist", params={}),),
        )
        result = await service.execute(playbook, tenant)

        assert result.halted_early is True
        assert result.step_results[0].outcome == PlaybookStepOutcome.FAILED
        assert "No PlaybookAction registered" in (result.step_results[0].error or "")


class TestPlaybookExecutionResultReplayability:
    @pytest.mark.asyncio
    async def test_execution_result_is_a_complete_self_contained_trace(
        self, audit_log: AuditLogService
    ) -> None:
        """The result object alone (no external lookup) must be enough to
        reconstruct exactly what happened -- the same 'explainable' bar
        G3 already gated for the analytics milestone."""
        registry = PlaybookActionRegistry()
        registry.register(_EchoAction())
        registry.register(_SecondRealAction())
        service = PlaybookExecutionService(registry, audit_log)
        tenant = make_tenant_context()

        playbook = Playbook(
            name="two-real-actions",
            steps=(
                PlaybookStep(step_id="s1", action_name="echo", params={"k": "v"}),
                PlaybookStep(step_id="s2", action_name="second_action", params={}),
            ),
        )
        result = await service.execute(playbook, tenant)

        assert result.step_results[0].action_name == "echo"
        assert result.step_results[0].params == {"k": "v"}
        assert result.step_results[0].output == {"k": "v"}
        assert result.step_results[1].action_name == "second_action"
        assert result.step_results[1].output == {
            "ran": "second_action",
            "org_id": str(tenant.org_id),
        }
