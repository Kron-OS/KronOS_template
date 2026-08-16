"""Unit tests for the Defender poll source DI wiring (roadmap Q4,
configure_defender_poll_source_from_settings / get_defender_poll_source in
dependencies.py).

Mirrors test_cef_syslog_sink_wiring.py's own "patch src.config.Settings with
a real, lightweight SimpleNamespace" shape exactly, for the same reason:
constructing a real, fully-valid Settings() would mean inventing fake values
for a dozen unrelated required fields this test has nothing to do with.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from src.external.dependencies import (
    configure_defender_poll_source_from_settings,
    get_defender_poll_org_id,
    get_defender_poll_source,
    get_defender_poll_source_id,
    get_integration_source_registry,
    reset_dependencies,
)
from src.external.integration_sources.defender import DefenderPollSource


class _FakeSecret:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


_DEFAULT_FAKE_SECRET = _FakeSecret("shh")


def _fake_settings(
    *,
    defender_tenant_id: str | None = "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    defender_client_id: str | None = "00001111-aaaa-2222-bbbb-3333cccc4444",
    defender_client_secret: _FakeSecret | None = _DEFAULT_FAKE_SECRET,
    defender_graph_base_url: str = "https://graph.microsoft.com/v1.0",
    defender_poll_org_id: str | None = None,
    defender_poll_source_id: str = "ms-defender-alerts",
) -> SimpleNamespace:
    return SimpleNamespace(
        defender_tenant_id=defender_tenant_id,
        defender_client_id=defender_client_id,
        defender_client_secret=defender_client_secret,
        defender_graph_base_url=defender_graph_base_url,
        defender_poll_org_id=defender_poll_org_id,
        defender_poll_source_id=defender_poll_source_id,
    )


class TestDefenderPollSourceWiring:
    def setup_method(self) -> None:
        reset_dependencies()

    def teardown_method(self) -> None:
        reset_dependencies()

    def test_unconfigured_by_default(self) -> None:
        assert get_defender_poll_source() is None
        assert get_integration_source_registry().get("ms-defender-alerts") is None
        assert get_defender_poll_org_id() is None
        assert get_defender_poll_source_id() == "ms-defender-alerts"

    def test_settings_instantiation_failure_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", side_effect=Exception("missing required env vars")):
            configure_defender_poll_source_from_settings()
        assert get_defender_poll_source() is None

    def test_no_tenant_id_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(defender_tenant_id=None)):
            configure_defender_poll_source_from_settings()
        assert get_defender_poll_source() is None
        assert get_integration_source_registry().get("ms-defender-alerts") is None

    def test_no_client_id_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(defender_client_id=None)):
            configure_defender_poll_source_from_settings()
        assert get_defender_poll_source() is None

    def test_no_client_secret_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(defender_client_secret=None)):
            configure_defender_poll_source_from_settings()
        assert get_defender_poll_source() is None

    def test_real_settings_wire_a_real_source_and_register_it(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_defender_poll_source_from_settings()

        source = get_defender_poll_source()
        assert isinstance(source, DefenderPollSource)
        assert source.source_type == "ms-defender-alerts"
        # Real registration into the shared IntegrationSourceRegistry --
        # not just constructed and left dangling.
        assert get_integration_source_registry().get("ms-defender-alerts") is source

    def test_reset_clears_defender_wiring(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_defender_poll_source_from_settings()
        assert get_defender_poll_source() is not None

        reset_dependencies()
        assert get_defender_poll_source() is None
        assert get_integration_source_registry().get("ms-defender-alerts") is None
        assert get_defender_poll_org_id() is None
        assert get_defender_poll_source_id() == "ms-defender-alerts"

    def test_org_id_captured_even_without_full_credentials(self) -> None:
        # Milestone W14 (GET /api/admin/connectors/status): org/source_id
        # attribution must be readable even when the OAuth2 credential trio
        # is unset -- a real, distinct "org configured, no creds yet"
        # deployment state the status route needs to be honest about.
        org_id = "b7d6a1a0-1111-4444-8888-aaaaaaaaaaaa"
        with patch(
            "src.config.Settings",
            return_value=_fake_settings(
                defender_tenant_id=None,
                defender_poll_org_id=org_id,
                defender_poll_source_id="custom-defender-feed",
            ),
        ):
            configure_defender_poll_source_from_settings()

        assert get_defender_poll_source() is None  # still unconfigured, no creds
        assert get_defender_poll_org_id() == org_id
        assert get_defender_poll_source_id() == "custom-defender-feed"

    def test_org_id_captured_alongside_full_credentials(self) -> None:
        org_id = "b7d6a1a0-1111-4444-8888-aaaaaaaaaaaa"
        with patch("src.config.Settings", return_value=_fake_settings(defender_poll_org_id=org_id)):
            configure_defender_poll_source_from_settings()

        assert get_defender_poll_source() is not None
        assert get_defender_poll_org_id() == org_id
