"""Unit tests for src.external.celery_defender (Gap Audit 2026-08 P1-2 /
roadmap Milestone V2, item b).

The real, full poll-cycle success path (real Postgres cursor persistence,
real Redis stream production, real OAuth2/alerts_v2 round trip via a local
httpx.MockTransport stand-in) is verified end-to-end, for real, in
poc/v2_connector_wiring/defender_poll_beat_task/ (CLAUDE.md SS F) -- not
re-mocked here. These tests cover the module's own fast, pure-logic
"honestly not configured" branches, which `Settings()` reaches BEFORE any
Postgres/Redis/httpx client is ever constructed (confirmed by reading
_run_defender_poll_cycle_async's own body: every real-infra call happens
strictly after both `DefenderPollNotConfiguredError` checks) -- so a
`SimpleNamespace` standing in for `Settings()` (same technique
test_defender_poll_source_wiring.py already uses) is a faithful, not a
hollow, test of this exact code path, no real dependency mocking required.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.external.celery_defender import (
    DefenderPollNotConfiguredError,
    run_defender_poll_cycle,
)


def _fake_settings(
    *,
    defender_tenant_id: str | None = "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    defender_client_id: str | None = "00001111-aaaa-2222-bbbb-3333cccc4444",
    defender_client_secret: str | None = "shh",
    defender_poll_org_id: str | None = None,
) -> SimpleNamespace:
    secret_obj = None
    if defender_client_secret is not None:
        secret_obj = MagicMock()
        secret_obj.get_secret_value.return_value = defender_client_secret
    return SimpleNamespace(
        defender_tenant_id=defender_tenant_id,
        defender_client_id=defender_client_id,
        defender_client_secret=secret_obj,
        defender_poll_org_id=defender_poll_org_id,
        defender_poll_source_id="ms-defender-alerts",
        defender_graph_base_url="https://graph.microsoft.com/v1.0",
    )


class TestRunDefenderPollCycleNotConfigured:
    def test_no_tenant_id_raises_not_configured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(defender_tenant_id=None)):
            with pytest.raises(DefenderPollNotConfiguredError, match="Defender poll source"):
                run_defender_poll_cycle()

    def test_no_client_id_raises_not_configured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(defender_client_id=None)):
            with pytest.raises(DefenderPollNotConfiguredError, match="Defender poll source"):
                run_defender_poll_cycle()

    def test_no_client_secret_raises_not_configured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(defender_client_secret=None)):
            with pytest.raises(DefenderPollNotConfiguredError, match="Defender poll source"):
                run_defender_poll_cycle()

    def test_no_poll_org_id_raises_not_configured(self) -> None:
        """Defender credentials alone are not enough -- P1-2's own design
        decision (see config.py's defender_poll_org_id docstring): there is
        no honest per-alert org attribution signal in the payload itself."""
        with patch("src.config.Settings", return_value=_fake_settings(defender_poll_org_id=None)):
            with pytest.raises(DefenderPollNotConfiguredError, match="defender_poll_org_id"):
                run_defender_poll_cycle()

    def test_malformed_poll_org_id_raises_value_error_not_swallowed(self) -> None:
        """A non-empty but malformed defender_poll_org_id is a real
        deployment misconfiguration, not an honest 'unconfigured' state --
        must fail loudly (ValueError), never be folded into the silent
        DefenderPollNotConfiguredError skip path (CLAUDE.md invariant #8)."""
        with patch(
            "src.config.Settings",
            return_value=_fake_settings(defender_poll_org_id="not-a-real-uuid"),
        ):
            with pytest.raises(ValueError, match="badly formed hexadecimal UUID string"):
                run_defender_poll_cycle()

    def test_valid_poll_org_id_parses_without_raising_not_configured(self) -> None:
        """Confirms the org_id/source_id resolution itself succeeds past
        both honest-skip checks -- the function then goes on to build a
        real AsyncEngine/Redis client against whatever DATABASE_URL/
        REDIS_URL SimpleNamespace attributes it finds next, which this
        fake Settings object deliberately doesn't provide, so the real
        failure surfacing here (AttributeError on a missing database_url)
        is itself proof this test's SimpleNamespace passed both real
        DefenderPollNotConfiguredError gates cleanly."""
        with patch(
            "src.config.Settings",
            return_value=_fake_settings(defender_poll_org_id=str(uuid.uuid4())),
        ):
            with pytest.raises(AttributeError):
                run_defender_poll_cycle()
