"""Unit tests for StepUpAuth (RFC 9470 step-up tickets)."""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from src.domain.user import Role, TenantContext
from src.external.middleware.step_up_auth import StepUpAuth


def _make_tenant(acr: str = "aal1") -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias="testorg",
        user_id=uuid.uuid4(),
        username="testuser",
        roles=frozenset({Role.ORG_ADMIN}),
        correlation_id=str(uuid.uuid4()),
        acr=acr,
    )


@pytest.fixture
def auth() -> StepUpAuth:
    return StepUpAuth()


def test_issue_and_consume_ticket(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal2")
    ticket_id = auth.issue_ticket(tenant.user_id, "evidence.delete", "ev-123")
    auth.consume_ticket(ticket_id, tenant.user_id, "evidence.delete", "ev-123")


def test_ticket_is_single_use(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal2")
    ticket_id = auth.issue_ticket(tenant.user_id, "evidence.delete", "ev-123")
    auth.consume_ticket(ticket_id, tenant.user_id, "evidence.delete", "ev-123")

    with pytest.raises(HTTPException) as exc_info:
        auth.consume_ticket(ticket_id, tenant.user_id, "evidence.delete", "ev-123")
    assert exc_info.value.status_code == 401


def test_ticket_wrong_user_rejected(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal2")
    auth.issue_ticket(tenant.user_id, "evidence.delete", "ev-123")

    with pytest.raises(HTTPException) as exc_info:
        auth.consume_ticket(uuid.uuid4(), tenant.user_id, "evidence.delete", "ev-123")
    assert exc_info.value.status_code == 401


def test_ticket_wrong_operation_rejected(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal2")
    ticket_id = auth.issue_ticket(tenant.user_id, "evidence.delete", "ev-123")

    with pytest.raises(HTTPException) as exc_info:
        auth.consume_ticket(ticket_id, tenant.user_id, "other.op", "ev-123")
    assert exc_info.value.status_code == 401


def test_ticket_wrong_resource_rejected(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal2")
    ticket_id = auth.issue_ticket(tenant.user_id, "evidence.delete", "ev-123")

    with pytest.raises(HTTPException) as exc_info:
        auth.consume_ticket(ticket_id, tenant.user_id, "evidence.delete", "ev-999")
    assert exc_info.value.status_code == 401


def test_nonexistent_ticket_rejected(auth: StepUpAuth) -> None:
    with pytest.raises(HTTPException) as exc_info:
        auth.consume_ticket(uuid.uuid4(), uuid.uuid4(), "evidence.delete", "ev-1")
    assert exc_info.value.status_code == 401


def test_assert_acr_aal2_passes(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal2")
    auth.assert_acr(tenant)  # should not raise


def test_assert_acr_aal1_fails(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal1")
    with pytest.raises(HTTPException) as exc_info:
        auth.assert_acr(tenant)
    assert exc_info.value.status_code == 401
    assert "acr_values" in exc_info.value.headers.get("WWW-Authenticate", "")


def test_assert_acr_rfc9470_header_format(auth: StepUpAuth) -> None:
    tenant = _make_tenant(acr="aal1")
    with pytest.raises(HTTPException) as exc_info:
        auth.assert_acr(tenant)
    www_auth = exc_info.value.headers["WWW-Authenticate"]
    assert "insufficient_user_authentication" in www_auth
    assert "aal2" in www_auth
