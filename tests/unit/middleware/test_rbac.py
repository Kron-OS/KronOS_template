"""Unit tests for requires_role RBAC dependency."""

import uuid

import pytest
from fastapi import HTTPException

from src.domain.user import Role, TenantContext
from src.external.middleware.rbac import requires_role


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
