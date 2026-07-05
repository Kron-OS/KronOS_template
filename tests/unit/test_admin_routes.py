"""Unit tests for org-admin route helpers."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import HTTPException, status
from pydantic import ValidationError

from src.exceptions import StorageError
from src.external.routes.admin import (
    InviteUserIn,
    OrgUserOut,
    _assert_user_in_org,
    _find_user_by_email,
    _is_org_member,
    _iso_from_epoch_millis,
    _to_http_error,
)
from tests.fixtures.factories import make_tenant_context


class _FakeResponse:
    """Minimal stand-in for httpx.Response used to unit-test admin helpers."""

    def __init__(self, status_code: int, body: Any = None) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return self._body


def test_iso_from_epoch_millis_converts_int() -> None:
    # Keycloak returns createdTimestamp as epoch milliseconds (a Java Long).
    assert _iso_from_epoch_millis(1782860957283) == "2026-06-30T23:09:17.283000+00:00"


def test_iso_from_epoch_millis_accepts_numeric_string() -> None:
    assert _iso_from_epoch_millis("1782860957283") == "2026-06-30T23:09:17.283000+00:00"


def test_iso_from_epoch_millis_passes_through_iso_string() -> None:
    iso = "2026-07-01T01:49:17+00:00"
    assert _iso_from_epoch_millis(iso) == iso


def test_iso_from_epoch_millis_handles_missing_value() -> None:
    assert _iso_from_epoch_millis(None) is None
    # bool is an int subclass but is never a valid timestamp
    assert _iso_from_epoch_millis(True) is None


def test_org_user_out_accepts_converted_timestamp() -> None:
    # Regression: the int createdTimestamp used to be passed straight into the
    # str-typed joinedAt field, raising a pydantic ValidationError (HTTP 500).
    user = OrgUserOut(
        userId="abc",
        username="analyst@kronos.dev",
        email="analyst@kronos.dev",
        roles=["analyst"],
        joinedAt=_iso_from_epoch_millis(1782860957283),
    )
    assert user.joinedAt == "2026-06-30T23:09:17.283000+00:00"
    assert user.roles == ["analyst"]


def _valid_invite_kwargs(**overrides: object) -> dict:
    base = {
        "email": "new.analyst@kronos.dev",
        "firstName": "New",
        "lastName": "Analyst",
        "password": "Sup3rSecret!Pw",
        "role": "analyst",
    }
    base.update(overrides)
    return base


def test_invite_user_in_accepts_valid_payload() -> None:
    body = InviteUserIn(**_valid_invite_kwargs())
    assert body.email == "new.analyst@kronos.dev"
    assert body.firstName == "New"
    assert body.role == "analyst"


def test_invite_user_in_rejects_malformed_email() -> None:
    with pytest.raises(ValidationError):
        InviteUserIn(**_valid_invite_kwargs(email="not-an-email"))


def test_invite_user_in_rejects_short_password() -> None:
    # Realm passwordPolicy requires length(12); this is well short of it.
    with pytest.raises(ValidationError):
        InviteUserIn(**_valid_invite_kwargs(password="short1!"))


def test_invite_user_in_rejects_password_containing_full_email() -> None:
    with pytest.raises(ValidationError):
        InviteUserIn(**_valid_invite_kwargs(password="new.analyst@kronos.dev123"))


def test_invite_user_in_rejects_password_containing_username_local_part() -> None:
    with pytest.raises(ValidationError):
        InviteUserIn(**_valid_invite_kwargs(password="new.analystXYZ12345"))


def test_invite_user_in_rejects_blank_name() -> None:
    with pytest.raises(ValidationError):
        InviteUserIn(**_valid_invite_kwargs(firstName=""))


def test_to_http_error_maps_bad_request_to_422_with_keycloak_message() -> None:
    # Regression: Keycloak's own password-policy rejection used to surface
    # as a generic 503, hiding the actual reason from the admin.
    exc = StorageError(
        "Keycloak Admin API request failed",
        context={"status": 400, "body": {"errorMessage": "invalidPasswordMinLengthMessage"}},
    )
    http_exc = _to_http_error(exc)
    assert http_exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert http_exc.detail == "invalidPasswordMinLengthMessage"


def test_to_http_error_reads_nested_errors_array() -> None:
    # Some Keycloak validation failures nest the real message one level down.
    exc = StorageError(
        "Keycloak Admin API request failed",
        context={
            "status": 400,
            "body": {"errors": [{"errorMessage": "invalidPasswordGenericMessage"}]},
        },
    )
    http_exc = _to_http_error(exc)
    assert http_exc.detail == "invalidPasswordGenericMessage"


def test_to_http_error_falls_back_to_generic_422_without_keycloak_message() -> None:
    exc = StorageError("Keycloak Admin API request failed", context={"status": 400, "body": None})
    http_exc = _to_http_error(exc)
    assert http_exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "password policy" in http_exc.detail


def test_to_http_error_maps_other_failures_to_503() -> None:
    exc = StorageError("Keycloak Admin API returned server error", context={"status": 500})
    http_exc = _to_http_error(exc)
    assert http_exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_to_http_error_maps_conflict_to_409_without_confirming_other_org() -> None:
    # AUTH-011: the message must not confirm which org the email belongs to.
    exc = StorageError(
        "Email already registered to a different account",
        context={
            "status": 409,
            "body": {"errorMessage": "This email is already registered to a different account."},
        },
    )
    http_exc = _to_http_error(exc)
    assert http_exc.status_code == status.HTTP_409_CONFLICT
    assert "different account" in http_exc.detail


# ---------------------------------------------------------------------------
# AUTH-003: org-membership scoping for realm-role-mapping admin calls
# ---------------------------------------------------------------------------


async def test_is_org_member_true_when_keycloak_returns_200(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = make_tenant_context()

    async def fake_request(*_args: object, **_kwargs: object) -> _FakeResponse:
        return _FakeResponse(200, {"id": "user-1"})

    monkeypatch.setattr("src.external.routes.admin._keycloak_admin_request", fake_request)
    assert await _is_org_member(tenant, "user-1") is True


async def test_is_org_member_false_when_keycloak_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = make_tenant_context()

    async def fake_request(*_args: object, **_kwargs: object) -> _FakeResponse:
        return _FakeResponse(404, None)

    monkeypatch.setattr("src.external.routes.admin._keycloak_admin_request", fake_request)
    assert await _is_org_member(tenant, "not-a-member") is False


async def test_assert_user_in_org_raises_403_when_not_a_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = make_tenant_context()

    async def fake_request(*_args: object, **_kwargs: object) -> _FakeResponse:
        return _FakeResponse(404, None)

    monkeypatch.setattr("src.external.routes.admin._keycloak_admin_request", fake_request)
    with pytest.raises(HTTPException) as exc_info:
        await _assert_user_in_org(tenant, "attacker-controlled-user-id")
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


async def test_assert_user_in_org_passes_when_member(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = make_tenant_context()

    async def fake_request(*_args: object, **_kwargs: object) -> _FakeResponse:
        return _FakeResponse(200, {"id": "user-1"})

    monkeypatch.setattr("src.external.routes.admin._keycloak_admin_request", fake_request)
    await _assert_user_in_org(tenant, "user-1")  # must not raise


async def test_find_user_by_email_returns_none_for_user_in_another_org(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression for AUTH-003/AUTH-011: a realm-wide email match that belongs
    # to a different org must never be reused, role-assigned, or confirmed to
    # the caller as existing.
    tenant = make_tenant_context()
    other_org_user_id = str(uuid.uuid4())

    async def fake_request(_tenant: object, method: str, path: str, *_a: object, **_kw: object) -> _FakeResponse:
        if path.startswith("/users?"):
            return _FakeResponse(200, [{"id": other_org_user_id, "email": "someone@other-org.example"}])
        # org-membership check
        return _FakeResponse(404, None)

    monkeypatch.setattr("src.external.routes.admin._keycloak_admin_request", fake_request)
    result = await _find_user_by_email(tenant, "someone@other-org.example")
    assert result is None


async def test_find_user_by_email_returns_candidate_when_member_of_caller_org(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = make_tenant_context()
    member_user_id = str(uuid.uuid4())

    async def fake_request(_tenant: object, method: str, path: str, *_a: object, **_kw: object) -> _FakeResponse:
        if path.startswith("/users?"):
            return _FakeResponse(200, [{"id": member_user_id, "email": "teammate@caller-org.example"}])
        return _FakeResponse(200, {"id": member_user_id})

    monkeypatch.setattr("src.external.routes.admin._keycloak_admin_request", fake_request)
    result = await _find_user_by_email(tenant, "teammate@caller-org.example")
    assert result is not None
    assert result["id"] == member_user_id
