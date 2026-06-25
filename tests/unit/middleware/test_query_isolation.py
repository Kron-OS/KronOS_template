"""Unit tests for QueryIsolationGuard."""

from __future__ import annotations

import uuid

import pytest

from src.domain.user import Role, TenantContext
from src.exceptions import AuthorizationError
from src.external.middleware.query_isolation import QueryIsolationGuard


def _make_tenant(org_id: uuid.UUID | None = None) -> TenantContext:
    return TenantContext(
        org_id=org_id or uuid.uuid4(),
        org_alias="testorg",
        user_id=uuid.uuid4(),
        username="testuser",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def test_assert_org_scope_same_org_passes() -> None:
    org_id = uuid.uuid4()
    tenant = _make_tenant(org_id)
    QueryIsolationGuard.assert_org_scope(tenant, org_id)  # must not raise


def test_assert_org_scope_different_org_raises() -> None:
    tenant = _make_tenant()
    other_org = uuid.uuid4()
    with pytest.raises(AuthorizationError, match="different organization"):
        QueryIsolationGuard.assert_org_scope(tenant, other_org)


def test_assert_org_scope_error_has_context() -> None:
    tenant = _make_tenant()
    other_org = uuid.uuid4()
    with pytest.raises(AuthorizationError) as exc_info:
        QueryIsolationGuard.assert_org_scope(tenant, other_org)
    assert "tenant_org_id" in exc_info.value.context
    assert "resource_org_id" in exc_info.value.context
