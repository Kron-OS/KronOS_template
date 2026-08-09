"""Unit tests for SuricataEvePushSource/ZeekJsonPushSource (roadmap Q3).

The Suricata NDJSON fixture used below (``tests/fixtures/samples/real/
suricata/eve.json``) is the same real, provenance-tracked sample
``tests/unit/parsers/test_suricata.py`` already uses for ``SuricataEveParser``
(see that directory's own ``NOTICE.md``) -- reused here rather than
hand-crafted, since it is real captured/documented Suricata output and this
connector's whole job is correctly splitting/validating exactly this real
NDJSON shape as fluent-bit forwards it. The multi-line "one flush, two
records" body below mirrors the real wire shape independently captured from
a real ``fluent/fluent-bit:3.1`` container in
``poc/integration_source_suricata_zeek/output.txt`` (NDJSON body, one JSON
object per originally-tailed line).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.application.stream_source_registry import (
    ZeekConnLogNormalizer,
    get_default_stream_normalizer_registry,
)
from src.domain.integration_source import IntegrationDeliveryMode
from src.exceptions import ParsingError
from src.external.integration_sources.suricata_zeek import (
    SuricataEvePushSource,
    SuricataEveStreamNormalizer,
    ZeekJsonPushSource,
    register_suricata_zeek_normalizers,
)

REAL_SURICATA_FIXTURE = (
    Path(__file__).parents[2] / "fixtures" / "samples" / "real" / "suricata" / "eve.json"
)

_REAL_ZEEK_SHAPED_CONN_LOG = json.dumps(
    {
        "ts": 1735689600.123456,
        "uid": "CxWIhL3rGCezA5MKq",
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
        "history": "ShADadFf",
        "orig_pkts": 6,
        "resp_pkts": 5,
    }
).encode()


class TestSuricataEvePushSource:
    def test_identity_properties(self) -> None:
        source = SuricataEvePushSource()
        assert source.source_type == "suricata-eve"
        assert source.source_version == "1.0.0"
        assert source.delivery_mode == IntegrationDeliveryMode.PUSH

    @pytest.mark.asyncio
    async def test_real_eve_json_fixture_splits_into_six_events(self) -> None:
        """Real 6-line NDJSON fixture (fileinfo/alert/fileinfo/http/anomaly/
        flow) -- proves real multi-record NDJSON bodies (fluent-bit's own
        real batching behavior when several lines land in one flush window)
        split correctly, not just a single-event body."""
        source = SuricataEvePushSource()
        body = REAL_SURICATA_FIXTURE.read_bytes()

        events = await source.parse_push_event(body)

        assert len(events) == 6
        decoded = [json.loads(e) for e in events]
        assert [d["event_type"] for d in decoded] == [
            "fileinfo",
            "alert",
            "fileinfo",
            "http",
            "anomaly",
            "flow",
        ]

    @pytest.mark.asyncio
    async def test_single_real_alert_line_is_one_event(self) -> None:
        source = SuricataEvePushSource()
        alert_line = REAL_SURICATA_FIXTURE.read_bytes().splitlines()[1]

        events = await source.parse_push_event(alert_line)

        assert events == [alert_line]

    @pytest.mark.asyncio
    async def test_fluent_bit_added_date_field_is_tolerated(self) -> None:
        """Real, observed fluent-bit 3.1 behavior (poc/integration_source_suricata_zeek/
        output.txt): the http output's json_lines format prepends its own
        ``date`` field (json_date_key's default name) to every forwarded
        record. This extra, harmless field must not break validation."""
        source = SuricataEvePushSource()
        body = (
            b'{"date":1786267123.761089,"timestamp":"2026-08-09T09:20:00.123456+0000",'
            b'"flow_id":1234567890123456,"event_type":"alert","src_ip":"203.0.113.5",'
            b'"src_port":51234,"dest_ip":"198.51.100.10","dest_port":443,"proto":"TCP",'
            b'"alert":{"signature":"test"}}'
        )

        events = await source.parse_push_event(body)

        assert events == [body]

    @pytest.mark.asyncio
    async def test_stats_event_with_no_flow_id_is_accepted(self) -> None:
        """Real EVE 'stats'/'engine' lines have event_type but no flow_id/
        5-tuple at all -- unlike SuricataEveParser.supports()'s own
        file-detection heuristic (which requires flow_id to disambiguate
        *file format*), this connector must not reject a real, valid,
        flow_id-less EVE line."""
        source = SuricataEvePushSource()
        body = json.dumps({"timestamp": "2026-08-09T00:00:00+0000", "event_type": "stats"}).encode()

        events = await source.parse_push_event(body)

        assert events == [body]

    @pytest.mark.asyncio
    async def test_non_json_line_raises_parsing_error(self) -> None:
        source = SuricataEvePushSource()

        with pytest.raises(ParsingError):
            await source.parse_push_event(b"not json at all")

    @pytest.mark.asyncio
    async def test_missing_event_type_raises_parsing_error(self) -> None:
        source = SuricataEvePushSource()
        body = json.dumps({"timestamp": "2026-08-09T00:00:00+0000"}).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)

    @pytest.mark.asyncio
    async def test_json_array_line_raises_parsing_error(self) -> None:
        source = SuricataEvePushSource()
        body = json.dumps([{"event_type": "alert"}]).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)

    @pytest.mark.asyncio
    async def test_all_blank_lines_raises_parsing_error(self) -> None:
        source = SuricataEvePushSource()

        with pytest.raises(ParsingError):
            await source.parse_push_event(b"\n\n   \n")

    @pytest.mark.asyncio
    async def test_one_bad_line_among_good_ones_rejects_whole_batch(self) -> None:
        """Fail loudly (CLAUDE.md invariant #8): a partially-malformed
        fluent-bit flush must not silently drop the bad line and accept the
        rest -- that would hide a real upstream problem (e.g. a truncated
        write mid-flush)."""
        source = SuricataEvePushSource()
        good = json.dumps({"timestamp": "2026-08-09T00:00:00+0000", "event_type": "stats"}).encode()
        body = good + b"\nnot json\n"

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)


class TestZeekJsonPushSource:
    def test_identity_properties(self) -> None:
        source = ZeekJsonPushSource()
        assert source.source_type == "zeek-conn-log"
        assert source.source_version == "1.0.0"
        assert source.delivery_mode == IntegrationDeliveryMode.PUSH

    @pytest.mark.asyncio
    async def test_real_shaped_conn_log_line_is_one_event(self) -> None:
        source = ZeekJsonPushSource()

        events = await source.parse_push_event(_REAL_ZEEK_SHAPED_CONN_LOG)

        assert events == [_REAL_ZEEK_SHAPED_CONN_LOG]

    @pytest.mark.asyncio
    async def test_multiple_lines_in_one_flush_split_correctly(self) -> None:
        source = ZeekJsonPushSource()
        second = json.dumps({"ts": 1735689601.0, "id.orig_h": "10.0.0.6"}).encode()
        body = _REAL_ZEEK_SHAPED_CONN_LOG + b"\n" + second

        events = await source.parse_push_event(body)

        assert events == [_REAL_ZEEK_SHAPED_CONN_LOG, second]

    @pytest.mark.asyncio
    async def test_non_json_line_raises_parsing_error(self) -> None:
        source = ZeekJsonPushSource()

        with pytest.raises(ParsingError):
            await source.parse_push_event(b"not json at all")

    @pytest.mark.asyncio
    async def test_missing_ts_field_raises_parsing_error(self) -> None:
        source = ZeekJsonPushSource()
        body = json.dumps({"uid": "C1", "id.orig_h": "10.0.0.5"}).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)

    @pytest.mark.asyncio
    async def test_json_array_line_raises_parsing_error(self) -> None:
        source = ZeekJsonPushSource()
        body = json.dumps([{"ts": 1.0}]).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)


class TestSuricataEveStreamNormalizer:
    """Reuses ``SuricataEveParser``'s own already-proven ECS mapping (its
    static ``_build_message``/``_build_extra`` helpers and its
    ``_ECS_BY_EVENT_TYPE`` table, imported directly) -- these tests assert
    the normalizer's own new plumbing (JSON decode, required-field
    validation, ``NormalizedStreamEvent`` construction) is correct, against
    the exact same real fixture ``tests/unit/parsers/test_suricata.py``
    already proves ``SuricataEveParser.parse()`` maps correctly, so any
    divergence between the two paths would show up as a real regression.
    """

    def test_source_id_and_version(self) -> None:
        normalizer = SuricataEveStreamNormalizer()
        assert normalizer.source_id == "suricata-eve"
        assert normalizer.normalizer_version == "1.0.0"

    def test_normalizes_the_real_captured_alert_line(self) -> None:
        normalizer = SuricataEveStreamNormalizer()
        alert_line = REAL_SURICATA_FIXTURE.read_bytes().splitlines()[1]

        event = normalizer.normalize(alert_line)

        assert event.event_kind == "alert"
        assert event.event_category == ["intrusion_detection", "network"]
        assert event.event_type == ["info"]
        assert "LeftHook Stealer" in event.message
        assert event.extra["source.ip"] == "142.11.240.191"
        assert event.extra["destination.ip"] == "192.168.100.237"
        assert event.extra["alert.category"] == "A Network Trojan was detected"
        assert event.extra["rule.id"] == "2045001"
        assert event.extra["suricata.flow_id"] == 1676750115612680

    def test_normalizes_every_real_line_in_the_fixture_without_error(self) -> None:
        """All six real event_types in the fixture (fileinfo/alert/fileinfo/
        http/anomaly/flow) must normalize without raising -- proves the
        reused ``_ECS_BY_EVENT_TYPE``/``_build_extra`` mapping's real
        per-type branches, not just the alert branch, are reachable through
        this normalizer."""
        normalizer = SuricataEveStreamNormalizer()

        for line in REAL_SURICATA_FIXTURE.read_bytes().splitlines():
            event = normalizer.normalize(line)
            assert event.timestamp is not None
            assert event.message

    def test_flow_event_type_maps_to_connection_end(self) -> None:
        normalizer = SuricataEveStreamNormalizer()
        flow_line = REAL_SURICATA_FIXTURE.read_bytes().splitlines()[-1]

        event = normalizer.normalize(flow_line)

        assert event.event_kind == "event"
        assert event.event_category == ["network"]
        assert event.event_type == ["connection", "end"]

    def test_non_json_payload_raises_parsing_error(self) -> None:
        normalizer = SuricataEveStreamNormalizer()

        with pytest.raises(ParsingError):
            normalizer.normalize(b"not json at all")

    def test_json_array_payload_raises_parsing_error(self) -> None:
        normalizer = SuricataEveStreamNormalizer()

        with pytest.raises(ParsingError):
            normalizer.normalize(json.dumps([1, 2]).encode())

    def test_missing_timestamp_raises_parsing_error(self) -> None:
        normalizer = SuricataEveStreamNormalizer()
        body = json.dumps({"event_type": "alert"}).encode()

        with pytest.raises(ParsingError):
            normalizer.normalize(body)


class TestRegisterSuricataZeekNormalizers:
    def test_adds_suricata_without_disturbing_zeek_or_wazuh(self) -> None:
        registry = get_default_stream_normalizer_registry()

        register_suricata_zeek_normalizers(registry)

        suricata_normalizer = registry.for_source("suricata-eve")
        zeek_normalizer = registry.for_source("zeek-conn-log")
        assert isinstance(suricata_normalizer, SuricataEveStreamNormalizer)
        assert isinstance(zeek_normalizer, ZeekConnLogNormalizer)
        assert registry.for_source("wazuh") is not None
