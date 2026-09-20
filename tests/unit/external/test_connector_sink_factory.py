"""Unit tests for build_sink_and_mapper_from_config (connector marketplace,
`/admin/connectors`, Phase 5/7): the per-org replacement for the removed
configure_splunk_hec_sink_from_settings()/configure_cef_syslog_sink_from_settings()/
configure_sentinel_sink_from_settings() global-Settings wiring functions.
"""

from __future__ import annotations

import pytest

from src.adapter.integration_sink.sentinel_sink import SentinelHttpSink
from src.adapter.integration_sink.splunk_hec_sink import SplunkHecSink
from src.adapter.integration_sink.syslog_sink import SyslogIntegrationSink, SyslogTransportProtocol
from src.application.cef_detection_mapper import CefDetectionMapper
from src.application.sentinel_detection_mapper import SentinelDetectionMapper
from src.application.splunk_detection_mapper import SplunkDetectionMapper
from src.external.dependencies import build_sink_and_mapper_from_config


class TestSplunkHec:
    def test_builds_real_sink_and_mapper_from_config(self) -> None:
        sink, mapper = build_sink_and_mapper_from_config(
            "splunk-hec",
            {
                "splunk_hec_url": "https://splunk.example.com:8088/services/collector/event",
                "splunk_hec_token": "test-token",
                "splunk_hec_source": "kronos:test",
                "splunk_hec_sourcetype": "kronos:test-detection",
                "splunk_hec_index": "kronos_idx",
            },
        )
        assert isinstance(sink, SplunkHecSink)
        assert isinstance(mapper, SplunkDetectionMapper)

    def test_optional_fields_fall_back_to_defaults(self) -> None:
        sink, mapper = build_sink_and_mapper_from_config(
            "splunk-hec",
            {"splunk_hec_url": "https://splunk.example.com:8088/services/collector/event", "splunk_hec_token": "t"},
        )
        assert isinstance(sink, SplunkHecSink)
        assert isinstance(mapper, SplunkDetectionMapper)


class TestCefSyslog:
    def test_builds_real_sink_and_mapper_from_config(self) -> None:
        sink, mapper = build_sink_and_mapper_from_config(
            "cef-syslog",
            {
                "cef_syslog_host": "siem.example.com",
                "cef_syslog_port": "514",
                "cef_syslog_protocol": "tcp",
                "cef_device_vendor": "TestCo",
                "cef_device_product": "TestProduct",
                "cef_device_version": "2.0",
            },
        )
        assert isinstance(sink, SyslogIntegrationSink)
        assert isinstance(mapper, CefDetectionMapper)

    def test_defaults_to_udp_when_protocol_unset(self) -> None:
        sink, _mapper = build_sink_and_mapper_from_config(
            "cef-syslog", {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"}
        )
        assert isinstance(sink, SyslogIntegrationSink)
        assert sink._protocol == SyslogTransportProtocol.UDP  # type: ignore[attr-defined]

    def test_tcp_protocol_selected_when_configured(self) -> None:
        sink, _mapper = build_sink_and_mapper_from_config(
            "cef-syslog",
            {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514", "cef_syslog_protocol": "tcp"},
        )
        assert sink._protocol == SyslogTransportProtocol.TCP  # type: ignore[attr-defined]


class TestSentinel:
    def test_builds_real_sink_and_mapper_from_config(self) -> None:
        sink, mapper = build_sink_and_mapper_from_config(
            "sentinel",
            {
                "sentinel_dce_endpoint": "https://my-dce.eastus-1.ingest.monitor.azure.com",
                "sentinel_dcr_immutable_id": "dcr-abc123",
                "sentinel_stream_name": "Custom-KronOSDetection_CL",
                "sentinel_tenant_id": "tenant-1",
                "sentinel_client_id": "client-1",
                "sentinel_client_secret": "secret-1",
            },
        )
        assert isinstance(sink, SentinelHttpSink)
        assert isinstance(mapper, SentinelDetectionMapper)


class TestUnknownSourceType:
    def test_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="no factory"):
            build_sink_and_mapper_from_config("not-a-real-sink", {})
