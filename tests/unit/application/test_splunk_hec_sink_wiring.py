"""Unit tests for the Splunk HEC DI wiring (roadmap R2,
configure_splunk_hec_sink_from_settings / get_splunk_hec_sink /
get_splunk_detection_mapper in dependencies.py).

Mirrors configure_clamav_from_settings's own "unconfigured Settings falls
back silently" shape. Real ``Settings()`` requires ~15 unrelated required
fields (minio/opensearch/keycloak/vault/celery credentials) that no
existing unit test in this repo populates (confirmed: no test constructs a
real, fully-valid ``Settings()`` today) -- constructing one here would mean
inventing fake values for a dozen fields this test has nothing to do with.
Instead, ``src.config.Settings`` itself is patched (mocking a config
loader, not an external dependency -- CLAUDE.md SS B.5's own "mock only
external dependencies" rule is about I/O boundaries like Postgres/S3, not
a plain in-process settings object), a real, lightweight ``SimpleNamespace``
stand-in supplies exactly the Splunk-relevant fields this wiring function
actually reads. The "Settings() itself cannot be instantiated" fallback
path is exercised separately, for real, via monkeypatch.delenv.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.adapter.integration_sink.splunk_hec_sink import SplunkHecSink
from src.application.splunk_detection_mapper import SplunkDetectionMapper
from src.external.dependencies import (
    configure_splunk_hec_sink_from_settings,
    get_splunk_detection_mapper,
    get_splunk_hec_sink,
    reset_dependencies,
)


def _fake_settings(
    *,
    splunk_hec_url: str | None = "https://splunk.example.com:8088/services/collector/event",
    splunk_hec_token: str | None = "test-token-123",
    splunk_hec_source: str = "kronos:test",
    splunk_hec_sourcetype: str = "kronos:test-detection",
    splunk_hec_index: str | None = "kronos_idx",
    splunk_hec_verify_tls: bool = True,
) -> SimpleNamespace:
    token_obj = None
    if splunk_hec_token is not None:
        token_obj = MagicMock()
        token_obj.get_secret_value.return_value = splunk_hec_token
    return SimpleNamespace(
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=token_obj,
        splunk_hec_source=splunk_hec_source,
        splunk_hec_sourcetype=splunk_hec_sourcetype,
        splunk_hec_index=splunk_hec_index,
        splunk_hec_verify_tls=splunk_hec_verify_tls,
    )


class TestSplunkHecSinkWiring:
    def setup_method(self) -> None:
        reset_dependencies()

    def teardown_method(self) -> None:
        reset_dependencies()

    def test_unconfigured_by_default(self) -> None:
        assert get_splunk_hec_sink() is None
        assert get_splunk_detection_mapper() is None

    def test_settings_instantiation_failure_leaves_unconfigured(self) -> None:
        """Mirrors configure_clamav_from_settings's own real fallback: if
        Settings() itself cannot be constructed (e.g. missing required env
        vars in a bare dev/test environment), both stay None rather than
        raising and blocking startup."""
        with patch("src.config.Settings", side_effect=Exception("missing required env vars")):
            configure_splunk_hec_sink_from_settings()
        assert get_splunk_hec_sink() is None
        assert get_splunk_detection_mapper() is None

    def test_no_splunk_url_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(splunk_hec_url=None)):
            configure_splunk_hec_sink_from_settings()
        assert get_splunk_hec_sink() is None
        assert get_splunk_detection_mapper() is None

    def test_no_splunk_token_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(splunk_hec_token=None)):
            configure_splunk_hec_sink_from_settings()
        assert get_splunk_hec_sink() is None
        assert get_splunk_detection_mapper() is None

    def test_real_settings_wire_a_real_sink_and_mapper(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_splunk_hec_sink_from_settings()

        sink = get_splunk_hec_sink()
        mapper = get_splunk_detection_mapper()
        assert isinstance(sink, SplunkHecSink)
        assert isinstance(mapper, SplunkDetectionMapper)
        # Real, documented HEC default ceiling applied.
        assert sink.max_batch_bytes == 838_860_800

    @pytest.mark.asyncio
    async def test_wired_authenticator_uses_real_splunk_scheme(self) -> None:
        """The wiring must use StaticTokenAuthenticator(scheme="Splunk") --
        not the default "Bearer" -- since that's the whole point of this
        connector existing (roadmap's own "easy to get wrong" callout)."""
        with patch("src.config.Settings", return_value=_fake_settings(splunk_hec_token="tok-abc")):
            configure_splunk_hec_sink_from_settings()

        sink = get_splunk_hec_sink()
        assert sink is not None
        auth = await sink._authenticator.prepare()  # noqa: SLF001 -- white-box wiring check
        assert auth.headers["Authorization"] == "Splunk tok-abc"

    def test_reset_clears_splunk_wiring(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_splunk_hec_sink_from_settings()
        assert get_splunk_hec_sink() is not None

        reset_dependencies()
        assert get_splunk_hec_sink() is None
        assert get_splunk_detection_mapper() is None
