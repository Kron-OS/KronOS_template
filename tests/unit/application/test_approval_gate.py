"""Unit tests for ApprovalGate implementations (roadmap M7/H2).

Mocks only the external TicketStore collaborator (CLAUDE.md SS B.5) --
StaticPolicyApprovalGate has no external dependency at all, so it is
exercised directly.

Gap Audit Milestone JJ: authorize() now takes an explicit, server-computed
resource_id argument rather than reading a caller-supplied
"approval_resource_id" out of params -- these tests pass resource_id
directly, matching the new real contract.
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

        decision = await gate.authorize("revoke_keycloak_session", "sess-1", {}, tenant)

        assert decision.authorized is False
        assert decision.policy_name == "step_up_mfa"

    @pytest.mark.asyncio
    async def test_denies_malformed_ticket_id(self) -> None:
        gate = StepUpApprovalGate(InMemoryTicketStore())
        tenant = make_tenant_context()

        decision = await gate.authorize(
            "revoke_keycloak_session",
            "sess-1",
            {"approval_ticket_id": "not-a-uuid"},
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
            "sess-1",
            {"approval_ticket_id": str(ticket_id)},
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
        params = {"approval_ticket_id": str(ticket_id)}

        first = await gate.authorize("revoke_keycloak_session", "sess-1", params, tenant)
        second = await gate.authorize("revoke_keycloak_session", "sess-1", params, tenant)

        assert first.authorized is True
        assert second.authorized is False

    @pytest.mark.asyncio
    async def test_denies_a_ticket_scoped_to_a_different_resource(self) -> None:
        store = InMemoryTicketStore()
        tenant = make_tenant_context()
        ticket_id = uuid.uuid4()
        store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-1")
        gate = StepUpApprovalGate(store)

        # The real resource_id argument (server-computed from the actual
        # target, e.g. RevokeKeycloakSessionAction._resource_id()) differs
        # from what the ticket was minted for -- must be denied.
        decision = await gate.authorize(
            "revoke_keycloak_session",
            "sess-DIFFERENT",
            {"approval_ticket_id": str(ticket_id)},
            tenant,
        )

        assert decision.authorized is False

    @pytest.mark.asyncio
    async def test_ticket_cannot_be_replayed_against_a_different_real_resource(self) -> None:
        """Gap Audit Milestone JJ regression test: the real attack this fix
        closes. A caller who holds a real, valid ticket for one resource
        must not be able to authorize acting on a DIFFERENT resource just
        by presenting the same ticket -- resource_id is now the caller
        ContainmentAction's own server-computed real target, not a
        separate, independently-supplied params field the ticket-holder
        could set to whatever matches their ticket."""
        store = InMemoryTicketStore()
        tenant = make_tenant_context()
        ticket_id = uuid.uuid4()
        store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-X")
        gate = StepUpApprovalGate(store)

        # Attack: real target is sess-Y, but the caller only holds a
        # ticket minted for sess-X. Before this fix, a caller-supplied
        # "approval_resource_id": "sess-X" in params would have made this
        # authorize successfully even though the real target is sess-Y.
        decision = await gate.authorize(
            "revoke_keycloak_session",
            "sess-Y",
            {"approval_ticket_id": str(ticket_id)},
            tenant,
        )

        assert decision.authorized is False
        # The ticket must remain unconsumed -- a denied mismatch is not a
        # real use of the ticket, so a subsequent real attempt against the
        # ticket's own true resource (sess-X) must still succeed.
        retry = await gate.authorize(
            "revoke_keycloak_session",
            "sess-X",
            {"approval_ticket_id": str(ticket_id)},
            tenant,
        )
        assert retry.authorized is True

    @pytest.mark.asyncio
    async def test_denies_a_ticket_scoped_to_a_different_action(self) -> None:
        store = InMemoryTicketStore()
        tenant = make_tenant_context()
        ticket_id = uuid.uuid4()
        store.put(ticket_id, tenant.user_id, "some_other_action", "sess-1")
        gate = StepUpApprovalGate(store)

        decision = await gate.authorize(
            "revoke_keycloak_session",
            "sess-1",
            {"approval_ticket_id": str(ticket_id)},
            tenant,
        )

        assert decision.authorized is False


class TestStaticPolicyApprovalGate:
    @pytest.mark.asyncio
    async def test_authorizes_an_allow_listed_org_action_pair(self) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset({(tenant.org_id, "revoke_keycloak_session")}))

        decision = await gate.authorize("revoke_keycloak_session", "sess-1", {}, tenant)

        assert decision.authorized is True
        assert decision.policy_name == "static_policy_allowlist"

    @pytest.mark.asyncio
    async def test_denies_an_org_not_on_the_allow_list(self) -> None:
        gate = StaticPolicyApprovalGate(frozenset())
        tenant = make_tenant_context()

        decision = await gate.authorize("revoke_keycloak_session", "sess-1", {}, tenant)

        assert decision.authorized is False

    @pytest.mark.asyncio
    async def test_denies_an_allow_listed_org_for_a_different_action(self) -> None:
        tenant = make_tenant_context()
        gate = StaticPolicyApprovalGate(frozenset({(tenant.org_id, "block_ip")}))

        decision = await gate.authorize("revoke_keycloak_session", "sess-1", {}, tenant)

        assert decision.authorized is False
