"""Unit tests for the Microsoft Sentinel DI wiring (roadmap R4,
configure_sentinel_sink_from_settings / get_sentinel_sink /
get_sentinel_detection_mapper in dependencies.py).

Mirrors test_cef_syslog_sink_wiring.py's own "patch src.config.Settings
with a real, lightweight SimpleNamespace" shape exactly, for the same
reason: constructing a real, fully-valid Settings() would mean inventing
fake values for a dozen unrelated required fields this test has nothing to
do with.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from pydantic import SecretStr

from src.adapter.integration_sink.sentinel_sink import SentinelHttpSink
from src.adapter.integration_sink.sink_authenticator import OAuth2ClientCredentialsAuthenticator
from src.application.sentinel_detection_mapper import SentinelDetectionMapper
from src.external.dependencies import (
    configure_sentinel_sink_from_settings,
    get_sentinel_detection_mapper,
    get_sentinel_sink,
    reset_dependencies,
)

_UNSET: Any = object()


def _fake_settings(
    *,
    sentinel_dce_endpoint: str | None = "https://my-dce-5kyl.eastus-1.ingest.monitor.azure.com",
    sentinel_dcr_immutable_id: str | None = "dcr-000a00a000a00000a000000aa000a0aa",
    sentinel_stream_name: str = "Custom-KronOSDetection",
    sentinel_api_version: str = "2023-01-01",
    sentinel_tenant_id: str | None = "aaaabbbb-0000-cccc-1111-dddd2222eeee",
    sentinel_client_id: str | None = "00001111-aaaa-2222-bbbb-3333cccc4444",
    sentinel_client_secret: SecretStr | None = _UNSET,
    sentinel_oauth_scope: str = "https://monitor.azure.com/.default",
    sentinel_verify_tls: bool = True,
) -> SimpleNamespace:
    secret = SecretStr("shh") if sentinel_client_secret is _UNSET else sentinel_client_secret
    return SimpleNamespace(
        sentinel_dce_endpoint=sentinel_dce_endpoint,
        sentinel_dcr_immutable_id=sentinel_dcr_immutable_id,
        sentinel_stream_name=sentinel_stream_name,
        sentinel_api_version=sentinel_api_version,
        sentinel_tenant_id=sentinel_tenant_id,
        sentinel_client_id=sentinel_client_id,
        sentinel_client_secret=secret,
        sentinel_oauth_scope=sentinel_oauth_scope,
        sentinel_verify_tls=sentinel_verify_tls,
    )


class TestSentinelSinkWiring:
    def setup_method(self) -> None:
        reset_dependencies()

    def teardown_method(self) -> None:
        reset_dependencies()

    def test_unconfigured_by_default(self) -> None:
        assert get_sentinel_sink() is None
        assert get_sentinel_detection_mapper() is None

    def test_settings_instantiation_failure_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", side_effect=Exception("missing required env vars")):
            configure_sentinel_sink_from_settings()
        assert get_sentinel_sink() is None
        assert get_sentinel_detection_mapper() is None

    def test_missing_dce_endpoint_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(sentinel_dce_endpoint=None)):
            configure_sentinel_sink_from_settings()
        assert get_sentinel_sink() is None
        assert get_sentinel_detection_mapper() is None

    def test_missing_dcr_immutable_id_leaves_unconfigured(self) -> None:
        with patch(
            "src.config.Settings", return_value=_fake_settings(sentinel_dcr_immutable_id=None)
        ):
            configure_sentinel_sink_from_settings()
        assert get_sentinel_sink() is None

    def test_missing_tenant_id_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(sentinel_tenant_id=None)):
            configure_sentinel_sink_from_settings()
        assert get_sentinel_sink() is None

    def test_missing_client_id_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(sentinel_client_id=None)):
            configure_sentinel_sink_from_settings()
        assert get_sentinel_sink() is None

    def test_missing_client_secret_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(sentinel_client_secret=None)):
            configure_sentinel_sink_from_settings()
        assert get_sentinel_sink() is None

    def test_real_settings_wire_a_real_sink_and_mapper(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_sentinel_sink_from_settings()

        sink = get_sentinel_sink()
        mapper = get_sentinel_detection_mapper()
        assert isinstance(sink, SentinelHttpSink)
        assert isinstance(mapper, SentinelDetectionMapper)

    def test_authenticator_is_real_oauth2_client_credentials(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_sentinel_sink_from_settings()
        sink = get_sentinel_sink()
        assert sink is not None
        authenticator = sink._authenticator  # noqa: SLF001 -- white-box wiring check
        assert isinstance(authenticator, OAuth2ClientCredentialsAuthenticator)

    def test_token_url_uses_real_entra_id_v2_endpoint(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_sentinel_sink_from_settings()
        sink = get_sentinel_sink()
        assert sink is not None
        authenticator = sink._authenticator  # noqa: SLF001
        assert authenticator._token_url == (  # noqa: SLF001
            "https://login.microsoftonline.com/"
            "aaaabbbb-0000-cccc-1111-dddd2222eeee/oauth2/v2.0/token"
        )

    def test_url_reflects_configured_dcr_stream_and_api_version(self) -> None:
        with patch(
            "src.config.Settings",
            return_value=_fake_settings(
                sentinel_stream_name="Custom-Other", sentinel_api_version="2024-02-01"
            ),
        ):
            configure_sentinel_sink_from_settings()
        sink = get_sentinel_sink()
        assert sink is not None
        assert "Custom-Other" in sink._url  # noqa: SLF001
        assert "api-version=2024-02-01" in sink._url  # noqa: SLF001

    def test_reset_clears_sentinel_wiring(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_sentinel_sink_from_settings()
        assert get_sentinel_sink() is not None

        reset_dependencies()
        assert get_sentinel_sink() is None
        assert get_sentinel_detection_mapper() is None
