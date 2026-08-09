"""Unit tests for the CEF-over-syslog DI wiring (roadmap R3,
configure_cef_syslog_sink_from_settings / get_cef_syslog_sink /
get_cef_detection_mapper in dependencies.py).

Mirrors test_splunk_hec_sink_wiring.py's own "patch src.config.Settings
with a real, lightweight SimpleNamespace" shape exactly, for the same
reason: constructing a real, fully-valid Settings() would mean inventing
fake values for a dozen unrelated required fields this test has nothing to
do with.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from src.adapter.integration_sink.syslog_sink import SyslogIntegrationSink, SyslogTransportProtocol
from src.application.cef_detection_mapper import CefDetectionMapper
from src.external.dependencies import (
    configure_cef_syslog_sink_from_settings,
    get_cef_detection_mapper,
    get_cef_syslog_sink,
    reset_dependencies,
)


def _fake_settings(
    *,
    cef_syslog_host: str | None = "siem.example.com",
    cef_syslog_port: int = 514,
    cef_syslog_protocol: str = "tcp",
    cef_device_vendor: str = "KronOS",
    cef_device_product: str = "DetectionSink",
    cef_device_version: str = "1.0",
) -> SimpleNamespace:
    return SimpleNamespace(
        cef_syslog_host=cef_syslog_host,
        cef_syslog_port=cef_syslog_port,
        cef_syslog_protocol=cef_syslog_protocol,
        cef_device_vendor=cef_device_vendor,
        cef_device_product=cef_device_product,
        cef_device_version=cef_device_version,
    )


class TestCefSyslogSinkWiring:
    def setup_method(self) -> None:
        reset_dependencies()

    def teardown_method(self) -> None:
        reset_dependencies()

    def test_unconfigured_by_default(self) -> None:
        assert get_cef_syslog_sink() is None
        assert get_cef_detection_mapper() is None

    def test_settings_instantiation_failure_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", side_effect=Exception("missing required env vars")):
            configure_cef_syslog_sink_from_settings()
        assert get_cef_syslog_sink() is None
        assert get_cef_detection_mapper() is None

    def test_no_host_leaves_unconfigured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(cef_syslog_host=None)):
            configure_cef_syslog_sink_from_settings()
        assert get_cef_syslog_sink() is None
        assert get_cef_detection_mapper() is None

    def test_real_settings_wire_a_real_sink_and_mapper(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_cef_syslog_sink_from_settings()

        sink = get_cef_syslog_sink()
        mapper = get_cef_detection_mapper()
        assert isinstance(sink, SyslogIntegrationSink)
        assert isinstance(mapper, CefDetectionMapper)
        # SyslogIntegrationSink's own real "one syslog message = one line,
        # no batching concept" contract, unaffected by CEF wiring.
        assert sink.max_batch_events == 1

    def test_tcp_is_the_default_protocol(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_cef_syslog_sink_from_settings()
        sink = get_cef_syslog_sink()
        assert sink is not None
        assert (
            sink._protocol is SyslogTransportProtocol.TCP
        )  # noqa: SLF001 -- white-box wiring check

    def test_udp_selected_when_configured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(cef_syslog_protocol="udp")):
            configure_cef_syslog_sink_from_settings()
        sink = get_cef_syslog_sink()
        assert sink is not None
        assert (
            sink._protocol is SyslogTransportProtocol.UDP
        )  # noqa: SLF001 -- white-box wiring check

    def test_protocol_matching_is_case_insensitive(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings(cef_syslog_protocol="UDP")):
            configure_cef_syslog_sink_from_settings()
        sink = get_cef_syslog_sink()
        assert sink is not None
        assert (
            sink._protocol is SyslogTransportProtocol.UDP
        )  # noqa: SLF001 -- white-box wiring check

    def test_device_vendor_product_version_propagated_to_mapper(self) -> None:
        with patch(
            "src.config.Settings",
            return_value=_fake_settings(
                cef_device_vendor="Acme", cef_device_product="Widget", cef_device_version="9.9"
            ),
        ):
            configure_cef_syslog_sink_from_settings()
        mapper = get_cef_detection_mapper()
        assert mapper is not None
        assert mapper._device_vendor == "Acme"  # noqa: SLF001 -- white-box wiring check
        assert mapper._device_product == "Widget"  # noqa: SLF001
        assert mapper._device_version == "9.9"  # noqa: SLF001

    def test_reset_clears_cef_wiring(self) -> None:
        with patch("src.config.Settings", return_value=_fake_settings()):
            configure_cef_syslog_sink_from_settings()
        assert get_cef_syslog_sink() is not None

        reset_dependencies()
        assert get_cef_syslog_sink() is None
        assert get_cef_detection_mapper() is None
