"""SuricataEveParser tests against a real Suricata EVE JSON sample.

tests/fixtures/samples/real/suricata/eve.json holds real, captured Suricata
output (see NOTICE.md in that directory for full provenance — one line from
OISF/suricata-verify's own golden test fixture, five lines copied from
Suricata's official userguide's flow_id-correlated real-pcap example). This
mirrors tests/unit/parsers/test_real_world_samples.py's exact pattern:
ParserRegistry.get_parser() for detection, then the winning parser's
parse(), against real bytes — the way execute_parse() does in
src/application/parsing_orchestration.py.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from src.application.parser_registry import ParserRegistry
from src.domain.timeline import TimelineRecord
from src.external.parsers.cloudtrail import CloudTrailParser
from src.external.parsers.nginx import NginxParser
from src.external.parsers.suricata import SuricataEveParser
from tests.fixtures.factories import make_evidence, make_tenant_context

REAL_SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples" / "real"
FIXTURE = REAL_SAMPLES / "suricata" / "eve.json"

# Matches the 8 KB detection window execute_parse()/_detect_parser() reads
# in src/application/parsing_orchestration.py — real detection never sees
# more than this.
_HEADER_BYTES = 8192


def _make_registry() -> ParserRegistry:
    """Register all three FAST JSON/text parsers together, proving
    SuricataEveParser cannot shadow or be shadowed by CloudTrailParser/
    NginxParser regardless of which real sample is routed through it."""
    registry = ParserRegistry()
    registry.register(CloudTrailParser())
    registry.register(NginxParser())
    registry.register(SuricataEveParser())
    return registry


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


def _read_header(path: Path) -> bytes:
    return path.read_bytes()[:_HEADER_BYTES]


class TestRealSuricataEveLog:
    def test_registry_detects_suricata_parser(self) -> None:
        registry = _make_registry()
        header = _read_header(FIXTURE)
        parser = registry.get_parser(FIXTURE.name, "application/json", header)
        assert isinstance(parser, SuricataEveParser)

    def test_cloudtrail_sample_still_routes_to_cloudtrail_not_suricata(self) -> None:
        # Cross-routing guard: a real CloudTrail NDJSON file (no "flow_id")
        # must still win CloudTrailParser, proving the two supports() checks
        # don't collide now that all three FAST JSON parsers are registered.
        registry = _make_registry()
        cloudtrail_fixture = REAL_SAMPLES / "aws_cloudtrail.jsonl"
        header = _read_header(cloudtrail_fixture)
        parser = registry.get_parser(cloudtrail_fixture.name, "application/json", header)
        assert isinstance(parser, CloudTrailParser)

    def test_nginx_sample_still_routes_to_nginx_not_suricata(self) -> None:
        registry = _make_registry()
        nginx_fixture = REAL_SAMPLES / "apache_access.log"
        header = _read_header(nginx_fixture)
        parser = registry.get_parser(nginx_fixture.name, "text/plain", header)
        assert isinstance(parser, NginxParser)

    @pytest.mark.asyncio
    async def test_parses_every_real_eve_line(self) -> None:
        data = FIXTURE.read_bytes()
        total_lines = len([ln for ln in data.decode().splitlines() if ln.strip()])
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(SuricataEveParser().parse(_bytes_stream(data), evidence, tenant))
        assert total_lines == 6
        assert len(records) == total_lines

    @pytest.mark.asyncio
    async def test_real_alert_record_maps_signature_and_5_tuple(self) -> None:
        # Line 2 of the real fixture: a real ET ATTACK_RESPONSE alert,
        # flow_id 1676750115612680, from Suricata's own userguide's
        # real-pcap-correlated example set.
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            SuricataEveParser().parse(_bytes_stream(FIXTURE.read_bytes()), evidence, tenant)
        )
        alert = next(r for r in records if r.event_kind == "alert")
        assert alert.extra["alert.signature"] == (
            "ET ATTACK_RESPONSE Win32/LeftHook Stealer Browser Extension Config Inbound"
        )
        assert alert.extra["alert.category"] == "A Network Trojan was detected"
        assert alert.extra["rule.id"] == "2045001"
        assert alert.extra["source.ip"] == "142.11.240.191"
        assert alert.extra["destination.ip"] == "192.168.100.237"
        assert alert.extra["network.transport"] == "tcp"
        assert alert.extra["suricata.flow_id"] == 1676750115612680
        assert "intrusion_detection" in alert.event_category
        assert alert.timestamp.year == 2023

    @pytest.mark.asyncio
    async def test_real_fileinfo_record_from_suricata_verify_golden_fixture(self) -> None:
        # Line 1: the OISF/suricata-verify golden test fixture itself
        # (real Suricata run against a real pcap, EICAR-over-HTTP download).
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            SuricataEveParser().parse(_bytes_stream(FIXTURE.read_bytes()), evidence, tenant)
        )
        first = records[0]
        assert first.event_category == ["file", "network"]
        assert first.extra["file.name"] == "eicar.com"
        assert first.extra["file.size"] == 68
        assert first.extra["http.hostname"] == "www.eicar.org"
        assert first.kronos.parser == "suricata-eve"
        assert first.kronos.record_index == 0

    @pytest.mark.asyncio
    async def test_real_flow_record_maps_byte_and_packet_counters(self) -> None:
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            SuricataEveParser().parse(_bytes_stream(FIXTURE.read_bytes()), evidence, tenant)
        )
        # event.type ["connection", "end"] is unique to the "flow" event_type
        # -- the "alert" record also carries an embedded "flow" sub-object
        # (a different, smaller summary of the same TCP session up to the
        # alert's packet), so filtering on "flow.bytes_toserver" presence
        # alone would match the wrong record.
        flow = next(r for r in records if r.event_type == ["connection", "end"])
        assert flow.extra["flow.bytes_toserver"] == 3536402
        assert flow.extra["flow.bytes_toclient"] == 94102
        assert flow.extra["flow.pkts_toserver"] == 3869

    @pytest.mark.asyncio
    async def test_record_index_is_sequential_and_provenance_is_populated(self) -> None:
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            SuricataEveParser().parse(_bytes_stream(FIXTURE.read_bytes()), evidence, tenant)
        )
        assert [r.kronos.record_index for r in records] == list(range(len(records)))
        for r in records:
            assert r.kronos.evidence_id == evidence.evidence_id
            assert r.kronos.parser == "suricata-eve"
            assert r.kronos.parser_version == "1.0.0"
