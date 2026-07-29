"""Unit tests for requires_role RBAC dependency."""

import uuid

import pytest
from fastapi import HTTPException

from src.domain.case import Case, CaseMetadata
from src.domain.user import Role, TenantContext
from src.external.middleware.rbac import (
    assert_case_access,
    assert_case_lead_or_admin,
    requires_role,
)


def _make_tenant(**kwargs) -> TenantContext:
    defaults = {
        "org_id": uuid.uuid4(),
        "org_alias": "testorg",
        "user_id": uuid.uuid4(),
        "username": "testuser",
        "roles": frozenset({Role.ANALYST}),
        "correlation_id": str(uuid.uuid4()),
    }
    defaults.update(kwargs)
    return TenantContext(**defaults)


async def test_requires_role_grants_access() -> None:
    admin_tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}))
    checker = requires_role(Role.ORG_ADMIN)
    result = await checker(tenant=admin_tenant)
    assert result is admin_tenant


async def test_requires_role_denies_access() -> None:
    analyst_tenant = _make_tenant(roles=frozenset({Role.ANALYST}))
    checker = requires_role(Role.ORG_ADMIN)
    with pytest.raises(HTTPException) as exc_info:
        await checker(tenant=analyst_tenant)
    assert exc_info.value.status_code == 403


async def test_requires_one_of_multiple_roles_granted() -> None:
    lead_tenant = _make_tenant(roles=frozenset({Role.CASE_LEAD}))
    checker = requires_role(Role.ANALYST, Role.CASE_LEAD)
    result = await checker(tenant=lead_tenant)
    assert result is lead_tenant


async def test_requires_role_403_includes_detail() -> None:
    read_only = _make_tenant(roles=frozenset({Role.READ_ONLY}))
    checker = requires_role(Role.ORG_ADMIN)
    with pytest.raises(HTTPException) as exc_info:
        await checker(tenant=read_only)
    assert exc_info.value.status_code == 403
    assert "org_admin" in exc_info.value.detail


def _make_case(
    owner_user_id: uuid.UUID, member_user_ids: frozenset[uuid.UUID] = frozenset()
) -> Case:
    return Case(
        org_id=uuid.uuid4(),
        org_alias="testorg",
        owner_user_id=owner_user_id,
        member_user_ids=member_user_ids,
        metadata=CaseMetadata(title="Test Case"),
    )


class TestAssertCaseAccess:
    """AUTH-007: the shared case-scoping rule reused by cases.py and evidence.py."""

    def test_org_admin_always_allowed(self) -> None:
        case = _make_case(owner_user_id=uuid.uuid4())
        admin = _make_tenant(roles=frozenset({Role.ORG_ADMIN}))
        assert_case_access(admin, case)  # does not raise

    def test_owner_allowed(self) -> None:
        owner_id = uuid.uuid4()
        case = _make_case(owner_user_id=owner_id)
        tenant = _make_tenant(user_id=owner_id, roles=frozenset({Role.CASE_LEAD}))
        assert_case_access(tenant, case)  # does not raise

    def test_member_allowed(self) -> None:
        member_id = uuid.uuid4()
        case = _make_case(owner_user_id=uuid.uuid4(), member_user_ids=frozenset({member_id}))
        tenant = _make_tenant(user_id=member_id, roles=frozenset({Role.ANALYST}))
        assert_case_access(tenant, case)  # does not raise

    def test_unrelated_user_forbidden(self) -> None:
        case = _make_case(owner_user_id=uuid.uuid4())
        tenant = _make_tenant(roles=frozenset({Role.ANALYST}))
        with pytest.raises(HTTPException) as exc_info:
            assert_case_access(tenant, case)
        assert exc_info.value.status_code == 403


class TestAssertCaseLeadOrAdmin:
    """AUTH-009: the stricter "(of case)" rule — membership alone is not enough."""

    def test_org_admin_always_allowed(self) -> None:
        case = _make_case(owner_user_id=uuid.uuid4())
        admin = _make_tenant(roles=frozenset({Role.ORG_ADMIN}))
        assert_case_lead_or_admin(admin, case)  # does not raise

    def test_owner_allowed(self) -> None:
        owner_id = uuid.uuid4()
        case = _make_case(owner_user_id=owner_id)
        tenant = _make_tenant(user_id=owner_id, roles=frozenset({Role.CASE_LEAD}))
        assert_case_lead_or_admin(tenant, case)  # does not raise

    def test_member_not_owner_forbidden(self) -> None:
        """A case-lead who is a *member* but not the *owner/lead* of this case
        is still forbidden — membership satisfies assert_case_access but not
        this stricter check."""
        member_id = uuid.uuid4()
        case = _make_case(owner_user_id=uuid.uuid4(), member_user_ids=frozenset({member_id}))
        tenant = _make_tenant(user_id=member_id, roles=frozenset({Role.CASE_LEAD}))
        with pytest.raises(HTTPException) as exc_info:
            assert_case_lead_or_admin(tenant, case)
        assert exc_info.value.status_code == 403
