"""Unit tests for RevokeKeycloakSessionAction (roadmap M7/H2).

Mocks only the external KeycloakAdminClient collaborator (CLAUDE.md SS
B.5) -- a hand-written fake, not the real HttpxKeycloakAdminClient, mirrors
this repo's established pattern of a small typed fake for a small ABC
(see InMemoryDetectionRepository for the same idea applied to a repository).
"""

from __future__ import annotations

import uuid

import pytest

from src.adapter.keycloak.admin_client import (
    KeycloakAdminClient,
    KeycloakOrganization,
    KeycloakSession,
)
from src.application.approval_gate import StaticPolicyApprovalGate
from src.application.audit_log import AuditLogService
from src.application.containment_actions import RevokeKeycloakSessionAction
from src.domain.audit import AuditEventType
from src.domain.user import TenantContext
from src.exceptions import AuthorizationError, ValidationError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class _FakeKeycloakAdminClient(KeycloakAdminClient):
    """Configurable in-memory fake -- the one external dependency this
    action's own unit tests mock, per CLAUDE.md SS B.5."""

    def __init__(
        self,
        *,
        org_members: set[uuid.UUID] | None = None,
        sessions_by_user: dict[uuid.UUID, tuple[KeycloakSession, ...]] | None = None,
    ) -> None:
        self.org_members = org_members or set()
        self.sessions_by_user = sessions_by_user or {}
        self.revoked_session_ids: list[str] = []
        self.org_aliases: dict[uuid.UUID, str] = {}

    async def list_user_sessions(self, user_id: uuid.UUID) -> tuple[KeycloakSession, ...]:
        return self.sessions_by_user.get(user_id, ())

    async def revoke_session(self, session_id: str) -> None:
        self.revoked_session_ids.append(session_id)

    async def is_org_member(self, org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        return user_id in self.org_members

    async def get_organization_alias(self, org_id: uuid.UUID) -> str | None:
        return self.org_aliases.get(org_id)

    async def list_organizations(self) -> tuple[KeycloakOrganization, ...]:
        return tuple(
            KeycloakOrganization(org_id=org_id, alias=alias)
            for org_id, alias in self.org_aliases.items()
        )


def _approved_gate(tenant: TenantContext) -> StaticPolicyApprovalGate:
    return StaticPolicyApprovalGate(frozenset({(tenant.org_id, "revoke_keycloak_session")}))


@pytest.fixture
def audit_repo() -> InMemoryAuditLogRepository:
    return InMemoryAuditLogRepository()


@pytest.fixture
def audit_log(audit_repo: InMemoryAuditLogRepository) -> AuditLogService:
    return AuditLogService(audit_repo)


class TestRevokeKeycloakSessionActionApproved:
    @pytest.mark.asyncio
    async def test_revokes_a_real_session_belonging_to_the_tenants_own_org(
        self, audit_log: AuditLogService
    ) -> None:
        tenant = make_tenant_context()
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClient(
            org_members={target_user},
            sessions_by_user={
                target_user: (
                    KeycloakSession(
                        session_id="sess-1",
                        user_id=str(target_user),
                        username="victim",
                        ip_address="10.0.0.5",
                        started_at_epoch_ms=0,
                    ),
                )
            },
        )
        action = RevokeKeycloakSessionAction(admin, _approved_gate(tenant), audit_log)

        output = await action.execute({"user_id": str(target_user), "session_id": "sess-1"}, tenant)

        assert output == {"user_id": str(target_user), "session_id": "sess-1", "revoked": True}
        assert admin.revoked_session_ids == ["sess-1"]

    @pytest.mark.asyncio
    async def test_executed_audit_row_records_real_output(
        self, audit_log: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        tenant = make_tenant_context()
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClient(
            org_members={target_user},
            sessions_by_user={
                target_user: (KeycloakSession("sess-1", str(target_user), "victim", "10.0.0.5", 0),)
            },
        )
        action = RevokeKeycloakSessionAction(admin, _approved_gate(tenant), audit_log)

        await action.execute({"user_id": str(target_user), "session_id": "sess-1"}, tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        executed = next(
            e for e in events if e.event_type == AuditEventType.CONTAINMENT_ACTION_EXECUTED
        )
        assert executed.details["output"]["revoked"] is True


class TestRevokeKeycloakSessionActionTenantIsolation:
    @pytest.mark.asyncio
    async def test_rejects_a_target_user_outside_the_tenants_own_org(
        self, audit_log: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        """Roadmap invariant #3: org_id is computed from TenantContext, never
        supplied by playbook params -- a step naming another org's user must
        be rejected even though it named a real, currently-live session."""
        tenant = make_tenant_context()
        other_org_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClient(
            org_members=set(),  # target user is NOT a member of tenant's org
            sessions_by_user={
                other_org_user: (
                    KeycloakSession("sess-cross-org", str(other_org_user), "other", "1.2.3.4", 0),
                )
            },
        )
        action = RevokeKeycloakSessionAction(admin, _approved_gate(tenant), audit_log)

        with pytest.raises(AuthorizationError):
            await action.execute(
                {"user_id": str(other_org_user), "session_id": "sess-cross-org"}, tenant
            )

        assert admin.revoked_session_ids == []  # the real destructive call never ran

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        assert any(e.event_type == AuditEventType.CONTAINMENT_ACTION_FAILED for e in events)
        assert not any(e.event_type == AuditEventType.CONTAINMENT_ACTION_EXECUTED for e in events)

    @pytest.mark.asyncio
    async def test_rejects_a_session_id_not_belonging_to_the_named_user(
        self, audit_log: AuditLogService
    ) -> None:
        """Defense in depth: even a real org member's user_id cannot be
        paired with an arbitrary session_id that isn't actually theirs."""
        tenant = make_tenant_context()
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClient(
            org_members={target_user},
            sessions_by_user={target_user: ()},  # no real sessions for this user
        )
        action = RevokeKeycloakSessionAction(admin, _approved_gate(tenant), audit_log)

        with pytest.raises(ValidationError):
            await action.execute(
                {"user_id": str(target_user), "session_id": "sess-not-theirs"}, tenant
            )

        assert admin.revoked_session_ids == []


class TestRevokeKeycloakSessionActionDenied:
    @pytest.mark.asyncio
    async def test_no_approval_never_reaches_the_real_backend(
        self, audit_log: AuditLogService
    ) -> None:
        tenant = make_tenant_context()
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClient(
            org_members={target_user},
            sessions_by_user={
                target_user: (KeycloakSession("sess-1", str(target_user), "victim", "1.2.3.4", 0),)
            },
        )
        denying_gate = StaticPolicyApprovalGate(frozenset())  # nothing authorized
        action = RevokeKeycloakSessionAction(admin, denying_gate, audit_log)

        from src.exceptions import ContainmentActionDeniedError

        with pytest.raises(ContainmentActionDeniedError):
            await action.execute({"user_id": str(target_user), "session_id": "sess-1"}, tenant)

        assert admin.revoked_session_ids == []


class TestRevokeKeycloakSessionActionMalformedParams:
    @pytest.mark.asyncio
    async def test_missing_params_raise_validation_error(self, audit_log: AuditLogService) -> None:
        tenant = make_tenant_context()
        admin = _FakeKeycloakAdminClient()
        action = RevokeKeycloakSessionAction(admin, _approved_gate(tenant), audit_log)

        with pytest.raises(ValidationError):
            await action.execute({}, tenant)

    @pytest.mark.asyncio
    async def test_non_uuid_user_id_raises_validation_error(
        self, audit_log: AuditLogService
    ) -> None:
        tenant = make_tenant_context()
        admin = _FakeKeycloakAdminClient()
        action = RevokeKeycloakSessionAction(admin, _approved_gate(tenant), audit_log)

        with pytest.raises(ValidationError):
            await action.execute({"user_id": "not-a-uuid", "session_id": "sess-1"}, tenant)
