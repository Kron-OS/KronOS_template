"""Unit tests for org-admin route helpers."""

from __future__ import annotations

from src.external.routes.admin import OrgUserOut, _iso_from_epoch_millis


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
