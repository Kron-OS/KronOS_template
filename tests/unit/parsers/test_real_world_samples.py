"""Parser tests against real-world sample files (not hand-crafted fixtures).

tests/fixtures/samples/real/ holds small real artifacts pulled from the
Plaso project's own test corpus (Apache-2.0 — see NOTICE.md in that
directory for provenance/license). Every synthetic fixture elsewhere in
this repo was hand-written to match the parser it tests, which is
circular: it can't catch a parser that's simply too strict for what
real-world tools actually produce. These tests run the exact production
pipeline — ParserRegistry.get_parser() for detection, then the winning
parser's parse() — against real bytes, the way execute_parse() does in
src/application/parsing_orchestration.py.

Three real bugs were found and fixed this way (see git history for
src/external/parsers/nginx.py, cloudtrail.py, plaso.py):

  1. NginxParser's combined-log-format regex required every field
     (referrer, user-agent) and rejected nginx's optional "$host:$port "
     vhost-prefixed lines — real logs mix Common Log Format (no
     referrer/UA) and vhost-prefixed lines in the same file. Silently
     dropped 9 of 15 lines in the real sample.
  2. CloudTrailParser.supports() required a literal "Records" key, which
     AWS's own CloudTrail Lake/S3-export NDJSON shape doesn't have (each
     line is a flat envelope with the real event nested as a JSON string
     under "CloudTrailEvent"). Rejected the file outright.
  3. PlasoParser only recognized MAM-compressed prefetch containers, not
     the also-common uncompressed SCCA-format prefetch files. Rejected a
     real Windows 10 .pf file outright.
  4. CloudTrailParser mapped AWS's own "sourceIPAddress" field straight to
     ECS's strictly ip-typed "source.ip" -- real, unremarkable for most
     rows, but AWS-service-initiated events (e.g. this file's own
     "SharedSnapshotVolumeCreated" row) document that field as the calling
     service's own hostname ("ec2.amazonaws.com"), not an IP. A real
     OpenSearch bulk-index call against this exact file failed outright
     (mapper_parsing_exception) the first time this fixture was ever
     driven through the real ingest pipeline end-to-end (Gap Audit
     Milestone AAAA) rather than just parsed in isolation -- this repo's
     own unit tests only ever exercised parse(), never the OpenSearch
     write path, so the bug had been latent since CloudTrailParser shipped.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from src.application.parser_registry import ParserRegistry
from src.domain.timeline import TimelineRecord
from src.external.parsers.cloudtrail import CloudTrailParser
from src.external.parsers.nginx import NginxParser
from src.external.parsers.plaso import PlasoParser
from tests.fixtures.factories import make_evidence, make_tenant_context

REAL_SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples" / "real"

# Matches the 8 KB detection window execute_parse()/_detect_parser() reads
# in src/application/parsing_orchestration.py — real detection never sees
# more than this.
_HEADER_BYTES = 8192


def _make_registry() -> ParserRegistry:
    """Mirror get_parser_registry()'s FAST-parser registration order
    (src/external/dependencies.py) — CloudTrail, then Nginx, then EVTX.
    EVTX/Plaso are registered conditionally there (optional deps); this
    covers the always-on FAST parsers plus PlasoParser explicitly per test.
    """
    registry = ParserRegistry()
    registry.register(CloudTrailParser())
    registry.register(NginxParser())
    return registry


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


def _read_header(path: Path) -> bytes:
    return path.read_bytes()[:_HEADER_BYTES]


# ---------------------------------------------------------------------------
# Nginx / apache combined access log
# ---------------------------------------------------------------------------


class TestRealNginxAccessLog:
    FIXTURE = REAL_SAMPLES / "apache_access.log"

    def test_registry_detects_nginx_parser(self) -> None:
        registry = _make_registry()
        header = _read_header(self.FIXTURE)
        parser = registry.get_parser(self.FIXTURE.name, "text/plain", header)
        assert isinstance(parser, NginxParser)

    @pytest.mark.asyncio
    async def test_parses_every_line_including_common_log_format_and_vhost_prefix(
        self,
    ) -> None:
        data = self.FIXTURE.read_bytes()
        total_lines = len(data.decode().strip().splitlines())
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(NginxParser().parse(_bytes_stream(data), evidence, tenant))
        # 15 real-world lines: full combined format, Common Log Format
        # (no referrer/UA), "$host:$port " vhost-prefixed, and one line
        # with an unterminated quote (still partially recoverable).
        assert total_lines == 15
        assert len(records) == 15

    @pytest.mark.asyncio
    async def test_common_log_format_line_has_no_referrer_or_user_agent(self) -> None:
        # Line 1 in the fixture is Common Log Format: no trailing
        # "referrer" "user-agent" pair at all.
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            NginxParser().parse(_bytes_stream(self.FIXTURE.read_bytes()), evidence, tenant)
        )
        first = records[0]
        assert first.extra.get("http.response.status_code") == 200
        assert "http.request.referrer" not in first.extra
        assert "user_agent.original" not in first.extra

    @pytest.mark.asyncio
    async def test_vhost_prefixed_line_still_extracts_correct_source_ip(self) -> None:
        # Lines 9-12 are prefixed with "$host:$port " (e.g.
        # "plaso.log2timeline.net:443 10.1.1.2 - - [...]"). The vhost
        # token must not be mistaken for the remote address.
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            NginxParser().parse(_bytes_stream(self.FIXTURE.read_bytes()), evidence, tenant)
        )
        vhost_prefixed = [r for r in records if (r.event_original or "").startswith("plaso")]
        # 4 lines (9-12) carry a "$host:$port " vhost prefix.
        assert len(vhost_prefixed) == 4
        for record in vhost_prefixed:
            source_ip = record.extra.get("source.ip")
            assert source_ip in {"10.1.1.2", "192.168.0.2"}
            assert ":" not in source_ip


# ---------------------------------------------------------------------------
# AWS CloudTrail (Lake/S3-export NDJSON shape)
# ---------------------------------------------------------------------------


class TestRealCloudTrailLog:
    FIXTURE = REAL_SAMPLES / "aws_cloudtrail.jsonl"

    def test_registry_detects_cloudtrail_parser(self) -> None:
        registry = _make_registry()
        header = _read_header(self.FIXTURE)
        parser = registry.get_parser(self.FIXTURE.name, "application/json", header)
        assert isinstance(parser, CloudTrailParser)

    @pytest.mark.asyncio
    async def test_parses_every_ndjson_row(self) -> None:
        data = self.FIXTURE.read_bytes()
        total_lines = len([ln for ln in data.decode().splitlines() if ln.strip()])
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(CloudTrailParser().parse(_bytes_stream(data), evidence, tenant))
        assert len(records) == total_lines

    @pytest.mark.asyncio
    async def test_unwraps_nested_cloudtrail_event_fields(self) -> None:
        # Each row's real event data lives inside a JSON-encoded string
        # under "CloudTrailEvent" (lowercase-camelCase fields), not the
        # row's own PascalCase envelope fields (EventId, EventName, ...).
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            CloudTrailParser().parse(_bytes_stream(self.FIXTURE.read_bytes()), evidence, tenant)
        )
        first = records[0]
        assert first.extra.get("cloud.service.name") == "ec2.amazonaws.com"
        assert first.timestamp.year == 2022
        assert "DescribeInstances" in (first.message or "")

    @pytest.mark.asyncio
    async def test_service_linked_row_gets_source_address_not_a_bad_source_ip(self) -> None:
        # Real bug #4 above: this fixture's own "SharedSnapshotVolumeCreated"
        # row has sourceIPAddress="ec2.amazonaws.com" (AWS's own documented
        # behaviour for service-initiated events, not malformed data) --
        # asserting on the actual real row rather than a synthetic one,
        # matching this module's own real-bytes-only convention.
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            CloudTrailParser().parse(_bytes_stream(self.FIXTURE.read_bytes()), evidence, tenant)
        )
        service_linked = next(
            r for r in records if r.extra.get("event.action") == "SharedSnapshotVolumeCreated"
        )
        assert service_linked.extra.get("source.address") == "ec2.amazonaws.com"
        assert service_linked.extra.get("source.ip") is None

        # A row with a real IP still gets both fields populated, and
        # source.ip is never a bare hostname string that would fail
        # OpenSearch's strictly ip-typed mapping.
        ip_addressed = next(
            r for r in records if r.extra.get("event.action") == "DescribeInstances"
        )
        assert ip_addressed.extra.get("source.ip") == "1.2.3.4"
        assert ip_addressed.extra.get("source.address") == "1.2.3.4"


# ---------------------------------------------------------------------------
# Windows Prefetch (uncompressed SCCA format — not MAM-compressed)
# ---------------------------------------------------------------------------


class TestRealPrefetchDetection:
    FIXTURE = REAL_SAMPLES / "CMD.EXE-087B4001.pf"

    def test_plaso_parser_detects_uncompressed_scca_prefetch(self) -> None:
        # PlasoParser.parse() shells out to a Firecracker/subprocess-based
        # Plaso worker (excluded from unit coverage — see pyproject.toml's
        # coverage omit list, same as the existing PlasoParser tests), so
        # only detection is exercised here.
        header = _read_header(self.FIXTURE)
        assert header[4:8] == b"SCCA"  # ground truth: not MAM-compressed
        assert PlasoParser().supports(self.FIXTURE.name, "application/octet-stream", header)


# ---------------------------------------------------------------------------
# Windows EVTX (System event log)
# ---------------------------------------------------------------------------

evtx = pytest.importorskip("evtx")  # skip the rest of this module if evtx isn't installed

from src.external.parsers.evtx import FastEvtxParser  # noqa: E402


class TestRealEvtxLog:
    FIXTURE = REAL_SAMPLES / "system.evtx"

    def test_registry_detects_evtx_parser(self) -> None:
        registry = _make_registry()
        registry.register(FastEvtxParser())
        header = _read_header(self.FIXTURE)
        parser = registry.get_parser(self.FIXTURE.name, "application/octet-stream", header)
        assert isinstance(parser, FastEvtxParser)

    @pytest.mark.asyncio
    async def test_parses_real_system_event_log(self) -> None:
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            FastEvtxParser().parse(_bytes_stream(self.FIXTURE.read_bytes()), evidence, tenant)
        )
        assert len(records) > 0
        assert all(r.kronos.parser == "evtx-rs" for r in records)
