"""Unit tests for org-admin route helpers."""

from __future__ import annotations

import pytest
from fastapi import status
from pydantic import ValidationError

from src.exceptions import StorageError
from src.external.routes.admin import (
    InviteUserIn,
    OrgUserOut,
    _iso_from_epoch_millis,
    _to_http_error,
)


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
