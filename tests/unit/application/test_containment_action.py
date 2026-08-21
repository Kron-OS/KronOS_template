"""Unit tests for ContainmentAction's template-method gate/audit sequence
(roadmap M7/H2).

Real InMemoryAuditLogRepository + real AuditLogService (mirrors
test_playbook_execution.py's own style) -- only the ApprovalGate is a
minimal, real, in-process test double (StaticPolicyApprovalGate), since
that already has zero external dependency itself.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.application.approval_gate import StaticPolicyApprovalGate
from src.application.audit_log import AuditLogService
from src.application.containment_action import ContainmentAction
from src.domain.audit import AuditEventType
from src.domain.user import TenantContext
from src.exceptions import ContainmentActionDeniedError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class _FakeDestructiveAction(ContainmentAction):
    """A minimal, real ContainmentAction subclass whose only job is to prove
    the base class's gate-consult-then-audit sequence -- the "real, external
    side effect" here is just appending to an in-memory list, standing in
    for a real backend call the same way _EchoAction stands in for a real
    PlaybookAction in test_playbook_execution.py."""

    def __init__(self, approval_gate, audit_log: AuditLogService, calls: list[dict[str, Any]]) -> None:
        super().__init__(approval_gate, audit_log)
        self._calls = calls

    @property
    def action_name(self) -> str:
        return "fake_destructive_action"

    def _resource_id(self, params: dict[str, Any]) -> str:
        return str(params.get("target", "unspecified"))

    async def _perform(self, params: dict[str, Any], tenant: TenantContext) -> dict[str, Any]:
        if params.get("force_backend_failure"):
            raise RuntimeError("real, deliberate backend failure for this test")
        self._calls.append(params)
        return {"performed": True}


@pytest.fixture
def audit_repo() -> InMemoryAuditLogRepository:
    return InMemoryAuditLogRepository()


@pytest.fixture
def audit_log(audit_repo: InMemoryAuditLogRepository) -> AuditLogService:
    return AuditLogService(audit_repo)


class TestContainmentActionApproved:
    @pytest.mark.asyncio
    async def test_approved_action_performs_and_returns_real_output(
        self, audit_log: AuditLogService
    ) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset({(tenant.org_id, "fake_destructive_action")}))
        calls: list[dict[str, Any]] = []
        action = _FakeDestructiveAction(gate, audit_log, calls)

        output = await action.execute({"target": "x"}, tenant)

        assert output == {"performed": True}
        assert calls == [{"target": "x"}]

    @pytest.mark.asyncio
    async def test_approved_action_audits_attempted_and_executed(
        self, audit_log: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset({(tenant.org_id, "fake_destructive_action")}))
        action = _FakeDestructiveAction(gate, audit_log, [])

        await action.execute({"target": "x"}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        event_types = [e.event_type for e in events]
        assert AuditEventType.CONTAINMENT_ACTION_ATTEMPTED in event_types
        assert AuditEventType.CONTAINMENT_ACTION_EXECUTED in event_types
        assert AuditEventType.CONTAINMENT_ACTION_DENIED not in event_types
        assert AuditEventType.CONTAINMENT_ACTION_FAILED not in event_types

        executed = next(e for e in events if e.event_type == AuditEventType.CONTAINMENT_ACTION_EXECUTED)
        assert executed.details["output"] == {"performed": True}
        assert executed.details["policy_name"] == "static_policy_allowlist"


class TestContainmentActionDenied:
    @pytest.mark.asyncio
    async def test_denied_action_raises_and_never_performs(self, audit_log: AuditLogService) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset())  # nothing authorized
        calls: list[dict[str, Any]] = []
        action = _FakeDestructiveAction(gate, audit_log, calls)

        with pytest.raises(ContainmentActionDeniedError):
            await action.execute({"target": "x"}, tenant)

        assert calls == []  # the real side effect never ran

    @pytest.mark.asyncio
    async def test_denied_action_audits_attempted_and_denied_only(
        self, audit_log: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset())
        action = _FakeDestructiveAction(gate, audit_log, [])

        with pytest.raises(ContainmentActionDeniedError):
            await action.execute({"target": "x"}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        event_types = [e.event_type for e in events]
        assert AuditEventType.CONTAINMENT_ACTION_ATTEMPTED in event_types
        assert AuditEventType.CONTAINMENT_ACTION_DENIED in event_types
        assert AuditEventType.CONTAINMENT_ACTION_EXECUTED not in event_types
        assert AuditEventType.CONTAINMENT_ACTION_FAILED not in event_types


class TestContainmentActionBackendFailure:
    @pytest.mark.asyncio
    async def test_real_backend_failure_is_audited_as_failed_and_reraised(
        self, audit_log: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset({(tenant.org_id, "fake_destructive_action")}))
        action = _FakeDestructiveAction(gate, audit_log, [])

        with pytest.raises(RuntimeError, match="real, deliberate backend failure"):
            await action.execute({"force_backend_failure": True}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        event_types = [e.event_type for e in events]
        assert AuditEventType.CONTAINMENT_ACTION_ATTEMPTED in event_types
        assert AuditEventType.CONTAINMENT_ACTION_FAILED in event_types
        assert AuditEventType.CONTAINMENT_ACTION_EXECUTED not in event_types
        assert AuditEventType.CONTAINMENT_ACTION_DENIED not in event_types

    @pytest.mark.asyncio
    async def test_hash_chain_stays_intact_after_a_denied_attempt(
        self, audit_log: AuditLogService
    ) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset())
        action = _FakeDestructiveAction(gate, audit_log, [])

        with pytest.raises(ContainmentActionDeniedError):
            await action.execute({"target": "x"}, tenant)

        intact, detail = await audit_log.verify_chain(tenant.org_id)
        assert intact is True, detail
