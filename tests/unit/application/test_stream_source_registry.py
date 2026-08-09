"""Unit tests for StreamSourceNormalizer / ZeekConnLogNormalizer (roadmap M3/D4)."""

from __future__ import annotations

import json

import pytest

from src.application.stream_source_registry import (
    StreamSourceNormalizerRegistry,
    WazuhAlertNormalizer,
    ZeekConnLogNormalizer,
    get_default_stream_normalizer_registry,
)
from src.exceptions import ParsingError

# The exact real alert body captured from a real wazuh-integratord ->
# custom-kronos -> KronOS push during poc/integration_source_wazuh/'s own
# real run (see that dir's output.txt) -- not a hand-crafted guess.
_REAL_CAPTURED_SSHD_ALERT = json.dumps(
    {
        "timestamp": "2026-08-09T04:07:46.692+0000",
        "rule": {
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "id": "5710",
            "mitre": {
                "id": ["T1110.001", "T1021.004"],
                "tactic": ["Credential Access", "Lateral Movement"],
                "technique": ["Password Guessing", "SSH"],
            },
            "firedtimes": 2,
            "mail": False,
            "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
            "gdpr": ["IV_35.7.d", "IV_32.2"],
            "gpg13": ["7.1"],
            "hipaa": ["164.312.b"],
            "nist_800_53": ["AU.14", "AC.7", "AU.6"],
            "pci_dss": ["10.2.4", "10.2.5", "10.6.1"],
            "tsc": ["CC6.1", "CC6.8", "CC7.2", "CC7.3"],
        },
        "agent": {"id": "000", "name": "4b29f98ecc3d"},
        "manager": {"name": "4b29f98ecc3d"},
        "id": "1786248466.704409",
        "full_log": (
            "Aug  9 06:07:46 4b29f98ecc3d sshd[9911]: Failed password for "
            "invalid user postgres from 198.51.100.7 port 44321 ssh2"
        ),
        "predecoder": {
            "program_name": "sshd",
            "timestamp": "Aug  9 06:07:46",
            "hostname": "4b29f98ecc3d",
        },
        "decoder": {"parent": "sshd", "name": "sshd"},
        "data": {"srcip": "198.51.100.7", "srcuser": "postgres"},
        "location": "/var/log/auth.log",
    }
).encode()

# A real, structural (non-syslog-decoded) alert -- SCA summary, also
# captured verbatim from the same real manager -- to prove the normalizer
# handles alerts with no full_log/data.srcuser/data.srcip at all.
_REAL_CAPTURED_SCA_SUMMARY_ALERT = json.dumps(
    {
        "timestamp": "2026-08-09T03:59:46.368+0000",
        "rule": {
            "level": 5,
            "description": (
                "SCA summary: CIS Benchmark for Amazon Linux 2023 Benchmark "
                "v1.0.0.: Score less than 80% (53)"
            ),
            "id": "19003",
            "firedtimes": 1,
            "mail": False,
            "groups": ["sca"],
            "gdpr": ["IV_35.7.d"],
            "pci_dss": ["2.2"],
            "nist_800_53": ["CM.1"],
            "tsc": ["CC7.1", "CC7.2"],
        },
        "agent": {"id": "000", "name": "4b29f98ecc3d"},
        "manager": {"name": "4b29f98ecc3d"},
        "id": "1786247986.700619",
        "decoder": {"name": "sca"},
        "location": "sca",
    }
).encode()

# A realistic Zeek default-JSON conn.log line, field names/shapes per Zeek's
# own conn.log schema (ts/id.orig_h/id.orig_p/id.resp_h/id.resp_p/proto/
# service/duration/orig_bytes/resp_bytes/conn_state/history/orig_pkts/
# resp_pkts/local_orig/local_resp/missed_bytes/uid).
_REAL_SHAPED_CONN_LOG = json.dumps(
    {
        "ts": 1735689600.123456,
        "uid": "CHhAvVGS1DHFjwGM9",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 52344,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 1.5,
        "orig_bytes": 512,
        "resp_bytes": 4096,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "ShADadFf",
        "orig_pkts": 6,
        "resp_pkts": 5,
    }
).encode()


class TestZeekConnLogNormalizer:
    def test_source_id_and_version(self) -> None:
        normalizer = ZeekConnLogNormalizer()
        assert normalizer.source_id == "zeek-conn-log"
        assert normalizer.normalizer_version == "1.0.0"

    def test_normalizes_a_real_shaped_conn_log_event(self) -> None:
        normalizer = ZeekConnLogNormalizer()

        event = normalizer.normalize(_REAL_SHAPED_CONN_LOG)

        assert event.event_kind == "event"
        assert event.event_category == ["network"]
        assert event.event_type == ["connection"]
        assert event.extra["source.ip"] == "10.0.0.5"
        assert event.extra["source.port"] == 52344
        assert event.extra["destination.ip"] == "93.184.216.34"
        assert event.extra["destination.port"] == 443
        assert event.extra["network.transport"] == "tcp"
        assert event.extra["network.protocol"] == "ssl"
        assert event.extra["source.bytes"] == 512
        assert event.extra["destination.bytes"] == 4096
        assert event.message == "10.0.0.5:52344 -> 93.184.216.34:443 (tcp)"

    def test_duration_converted_from_seconds_to_nanoseconds(self) -> None:
        """ECS event.duration is nanoseconds (long); Zeek's own duration is
        seconds (float) -- a bare rename would silently misrepresent it by
        9 orders of magnitude, exactly the kind of unit bug Section F exists
        to catch."""
        normalizer = ZeekConnLogNormalizer()

        event = normalizer.normalize(_REAL_SHAPED_CONN_LOG)

        assert event.extra["event.duration"] == 1_500_000_000

    def test_preserves_zeek_native_fields_under_extra_namespace(self) -> None:
        normalizer = ZeekConnLogNormalizer()

        event = normalizer.normalize(_REAL_SHAPED_CONN_LOG)

        assert event.extra["zeek.conn.uid"] == "CHhAvVGS1DHFjwGM9"
        assert event.extra["zeek.conn.conn_state"] == "SF"
        assert event.extra["zeek.conn.history"] == "ShADadFf"
        assert event.extra["zeek.conn.orig_pkts"] == 6
        assert event.extra["zeek.conn.resp_pkts"] == 5

    def test_tolerates_nested_id_shape(self) -> None:
        """Some downstream JSON re-shapers (e.g. Filebeat) un-flatten Zeek's
        dotted id.orig_h keys into a nested {"id": {"orig_h": ...}} object --
        tolerate both shapes defensively."""
        normalizer = ZeekConnLogNormalizer()
        nested = json.dumps(
            {
                "ts": 1735689600.0,
                "id": {"orig_h": "10.0.0.9", "orig_p": 1234, "resp_h": "1.2.3.4", "resp_p": 80},
                "proto": "tcp",
            }
        ).encode()

        event = normalizer.normalize(nested)

        assert event.extra["source.ip"] == "10.0.0.9"
        assert event.extra["destination.port"] == 80

    def test_missing_ts_raises_parsing_error(self) -> None:
        normalizer = ZeekConnLogNormalizer()
        payload = json.dumps({"proto": "tcp"}).encode()

        with pytest.raises(ParsingError, match="missing/invalid required 'ts'"):
            normalizer.normalize(payload)

    def test_invalid_json_raises_parsing_error(self) -> None:
        normalizer = ZeekConnLogNormalizer()

        with pytest.raises(ParsingError, match="not valid JSON"):
            normalizer.normalize(b"{not-json")

    def test_json_array_raises_parsing_error(self) -> None:
        normalizer = ZeekConnLogNormalizer()

        with pytest.raises(ParsingError, match="did not decode to a JSON object"):
            normalizer.normalize(b"[1, 2, 3]")

    def test_optional_fields_absent_are_simply_omitted(self) -> None:
        normalizer = ZeekConnLogNormalizer()
        minimal = json.dumps({"ts": 1735689600.0}).encode()

        event = normalizer.normalize(minimal)

        assert "source.ip" not in event.extra
        assert "network.transport" not in event.extra
        assert event.message is None


class TestStreamSourceNormalizerRegistry:
    def test_register_then_for_source(self) -> None:
        registry = StreamSourceNormalizerRegistry()
        normalizer = ZeekConnLogNormalizer()

        registry.register(normalizer)

        assert registry.for_source("zeek-conn-log") is normalizer

    def test_unregistered_source_returns_none(self) -> None:
        registry = StreamSourceNormalizerRegistry()

        assert registry.for_source("unknown-source") is None


class TestWazuhAlertNormalizer:
    def test_source_id_and_version(self) -> None:
        normalizer = WazuhAlertNormalizer()
        assert normalizer.source_id == "wazuh"
        assert normalizer.normalizer_version == "1.0.0"

    def test_normalizes_a_real_captured_sshd_alert(self) -> None:
        normalizer = WazuhAlertNormalizer()

        event = normalizer.normalize(_REAL_CAPTURED_SSHD_ALERT)

        assert event.event_kind == "alert"
        assert event.event_category == ["intrusion_detection", "authentication"]
        assert event.event_type == ["denied"]
        assert event.event_outcome == "failure"
        assert event.message == (
            "Aug  9 06:07:46 4b29f98ecc3d sshd[9911]: Failed password for "
            "invalid user postgres from 198.51.100.7 port 44321 ssh2"
        )
        assert event.host_name == "4b29f98ecc3d"
        assert event.user_name == "postgres"
        assert event.extra["source.ip"] == "198.51.100.7"
        assert event.extra["wazuh.rule.id"] == "5710"
        assert event.extra["wazuh.rule.level"] == 5
        assert event.extra["wazuh.rule.groups"] == [
            "syslog",
            "sshd",
            "authentication_failed",
            "invalid_login",
        ]
        assert event.extra["wazuh.rule.firedtimes"] == 2
        assert event.extra["wazuh.agent.id"] == "000"
        assert event.extra["wazuh.manager.name"] == "4b29f98ecc3d"
        assert event.extra["wazuh.decoder.name"] == "sshd"
        assert event.extra["wazuh.location"] == "/var/log/auth.log"

    def test_timestamp_parsed_with_numeric_utc_offset(self) -> None:
        normalizer = WazuhAlertNormalizer()

        event = normalizer.normalize(_REAL_CAPTURED_SSHD_ALERT)

        assert event.timestamp.isoformat() == "2026-08-09T04:07:46.692000+00:00"

    def test_structural_sca_alert_has_no_user_or_source_ip(self) -> None:
        """A real SCA-summary alert has no full_log/data.srcuser/data.srcip
        at all -- must not fabricate any of them, and must still produce a
        real, non-empty message (falling back to rule.description)."""
        normalizer = WazuhAlertNormalizer()

        event = normalizer.normalize(_REAL_CAPTURED_SCA_SUMMARY_ALERT)

        assert event.event_kind == "alert"
        assert event.event_category == ["intrusion_detection"]
        assert event.event_type == ["info"]
        assert event.event_outcome is None
        assert event.user_name is None
        assert "source.ip" not in event.extra
        assert event.message == (
            "SCA summary: CIS Benchmark for Amazon Linux 2023 Benchmark "
            "v1.0.0.: Score less than 80% (53)"
        )

    def test_authentication_success_group_maps_to_allowed(self) -> None:
        normalizer = WazuhAlertNormalizer()
        payload = json.dumps(
            {
                "timestamp": "2026-08-09T00:00:00.000+0000",
                "rule": {"level": 3, "id": "5715", "groups": ["authentication_success"]},
            }
        ).encode()

        event = normalizer.normalize(payload)

        assert event.event_category == ["intrusion_detection", "authentication"]
        assert event.event_type == ["allowed"]
        assert event.event_outcome == "success"

    def test_missing_timestamp_raises_parsing_error(self) -> None:
        normalizer = WazuhAlertNormalizer()
        payload = json.dumps({"rule": {"level": 5}}).encode()

        with pytest.raises(ParsingError, match="missing/invalid required 'timestamp'"):
            normalizer.normalize(payload)

    def test_invalid_json_raises_parsing_error(self) -> None:
        normalizer = WazuhAlertNormalizer()

        with pytest.raises(ParsingError, match="not valid JSON"):
            normalizer.normalize(b"{not-json")

    def test_json_array_raises_parsing_error(self) -> None:
        normalizer = WazuhAlertNormalizer()

        with pytest.raises(ParsingError, match="did not decode to a JSON object"):
            normalizer.normalize(b"[1, 2, 3]")


class TestGetDefaultStreamNormalizerRegistry:
    def test_zeek_conn_log_registered_by_default(self) -> None:
        registry = get_default_stream_normalizer_registry()

        normalizer = registry.for_source("zeek-conn-log")

        assert normalizer is not None
        assert isinstance(normalizer, ZeekConnLogNormalizer)

    def test_wazuh_registered_by_default(self) -> None:
        registry = get_default_stream_normalizer_registry()

        normalizer = registry.for_source("wazuh")

        assert normalizer is not None
        assert isinstance(normalizer, WazuhAlertNormalizer)
