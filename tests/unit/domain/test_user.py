"""Unit tests for User and TenantContext domain models."""

from __future__ import annotations

import uuid

from src.domain.user import Role
from tests.fixtures.factories import make_tenant_context, make_user


class TestRole:
    def test_role_values(self) -> None:
        assert Role.ORG_ADMIN.value == "org_admin"
        assert Role.CASE_LEAD.value == "case_lead"
        assert Role.ANALYST.value == "analyst"
        assert Role.READ_ONLY.value == "read_only"


class TestUser:
    def test_has_role_true(self) -> None:
        user = make_user(roles={Role.ANALYST})
        assert user.has_role(Role.ANALYST)

    def test_has_role_false(self) -> None:
        user = make_user(roles={Role.ANALYST})
        assert not user.has_role(Role.ORG_ADMIN)

    def test_has_any_role(self) -> None:
        user = make_user(roles={Role.CASE_LEAD})
        assert user.has_any_role(Role.ANALYST, Role.CASE_LEAD)

    def test_has_any_role_none_match(self) -> None:
        user = make_user(roles={Role.READ_ONLY})
        assert not user.has_any_role(Role.ANALYST, Role.CASE_LEAD)

    def test_frozen(self) -> None:
        user = make_user()
        try:
            user.username = "hacker"  # type: ignore[misc]
            raise AssertionError("Should have raised")
        except Exception:
            pass


class TestTenantContext:
    def test_fields_present(self) -> None:
        ctx = make_tenant_context()
        assert isinstance(ctx.org_id, uuid.UUID)
        assert ctx.org_alias == "testorg"
        assert ctx.correlation_id

    def test_frozen(self) -> None:
        ctx = make_tenant_context()
        try:
            ctx.org_alias = "evil"  # type: ignore[misc]
            raise AssertionError("Should have raised")
        except Exception:
            pass
