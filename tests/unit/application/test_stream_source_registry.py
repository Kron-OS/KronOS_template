"""Unit tests for StreamSourceNormalizer / ZeekConnLogNormalizer (roadmap M3/D4)."""

from __future__ import annotations

import json

import pytest

from src.application.stream_source_registry import (
    StreamSourceNormalizerRegistry,
    ZeekConnLogNormalizer,
    get_default_stream_normalizer_registry,
)
from src.exceptions import ParsingError

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


class TestGetDefaultStreamNormalizerRegistry:
    def test_zeek_conn_log_registered_by_default(self) -> None:
        registry = get_default_stream_normalizer_registry()

        normalizer = registry.for_source("zeek-conn-log")

        assert normalizer is not None
        assert isinstance(normalizer, ZeekConnLogNormalizer)
