"""Unit tests for ApprovalGate implementations (roadmap M7/H2).

Mocks only the external TicketStore collaborator (CLAUDE.md SS B.5) --
StaticPolicyApprovalGate has no external dependency at all, so it is
exercised directly.
"""

from __future__ import annotations

import uuid

import pytest

from src.application.approval_gate import StaticPolicyApprovalGate, StepUpApprovalGate
from src.external.middleware.step_up_store import InMemoryTicketStore
from tests.fixtures.factories import make_tenant_context


class TestStepUpApprovalGate:
    @pytest.mark.asyncio
    async def test_denies_when_no_ticket_supplied(self) -> None:
        gate = StepUpApprovalGate(InMemoryTicketStore())
        tenant = make_tenant_context()

        decision = await gate.authorize("revoke_keycloak_session", {}, tenant)

        assert decision.authorized is False
        assert decision.policy_name == "step_up_mfa"

    @pytest.mark.asyncio
    async def test_denies_malformed_ticket_id(self) -> None:
        gate = StepUpApprovalGate(InMemoryTicketStore())
        tenant = make_tenant_context()

        decision = await gate.authorize(
            "revoke_keycloak_session",
            {"approval_ticket_id": "not-a-uuid", "approval_resource_id": "sess-1"},
            tenant,
        )

        assert decision.authorized is False

    @pytest.mark.asyncio
    async def test_authorizes_and_consumes_a_real_matching_ticket(self) -> None:
        store = InMemoryTicketStore()
        tenant = make_tenant_context()
        ticket_id = uuid.uuid4()
        store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-1")
        gate = StepUpApprovalGate(store)

        decision = await gate.authorize(
            "revoke_keycloak_session",
            {"approval_ticket_id": str(ticket_id), "approval_resource_id": "sess-1"},
            tenant,
        )

        assert decision.authorized is True
        assert decision.policy_name == "step_up_mfa"

    @pytest.mark.asyncio
    async def test_ticket_is_single_use(self) -> None:
        store = InMemoryTicketStore()
        tenant = make_tenant_context()
        ticket_id = uuid.uuid4()
        store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-1")
        gate = StepUpApprovalGate(store)
        params = {"approval_ticket_id": str(ticket_id), "approval_resource_id": "sess-1"}

        first = await gate.authorize("revoke_keycloak_session", params, tenant)
        second = await gate.authorize("revoke_keycloak_session", params, tenant)

        assert first.authorized is True
        assert second.authorized is False

    @pytest.mark.asyncio
    async def test_denies_a_ticket_scoped_to_a_different_resource(self) -> None:
        store = InMemoryTicketStore()
        tenant = make_tenant_context()
        ticket_id = uuid.uuid4()
        store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-1")
        gate = StepUpApprovalGate(store)

        decision = await gate.authorize(
            "revoke_keycloak_session",
            {"approval_ticket_id": str(ticket_id), "approval_resource_id": "sess-DIFFERENT"},
            tenant,
        )

        assert decision.authorized is False

    @pytest.mark.asyncio
    async def test_denies_a_ticket_scoped_to_a_different_action(self) -> None:
        store = InMemoryTicketStore()
        tenant = make_tenant_context()
        ticket_id = uuid.uuid4()
        store.put(ticket_id, tenant.user_id, "some_other_action", "sess-1")
        gate = StepUpApprovalGate(store)

        decision = await gate.authorize(
            "revoke_keycloak_session",
            {"approval_ticket_id": str(ticket_id), "approval_resource_id": "sess-1"},
            tenant,
        )

        assert decision.authorized is False


class TestStaticPolicyApprovalGate:
    @pytest.mark.asyncio
    async def test_authorizes_an_allow_listed_org_action_pair(self) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(
            frozenset({(tenant.org_id, "revoke_keycloak_session")})
        )

        decision = await gate.authorize("revoke_keycloak_session", {}, tenant)

        assert decision.authorized is True
        assert decision.policy_name == "static_policy_allowlist"

    @pytest.mark.asyncio
    async def test_denies_an_org_not_on_the_allow_list(self) -> None:
        gate = StaticPolicyApprovalGate(frozenset())
        tenant = make_tenant_context()

        decision = await gate.authorize("revoke_keycloak_session", {}, tenant)

        assert decision.authorized is False

    @pytest.mark.asyncio
    async def test_denies_an_allow_listed_org_for_a_different_action(self) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset({(tenant.org_id, "block_ip")}))

        decision = await gate.authorize("revoke_keycloak_session", {}, tenant)

        assert decision.authorized is False
