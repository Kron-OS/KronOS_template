"""Unit tests for NginxParser."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from src.domain.timeline import TimelineRecord
from src.external.parsers.nginx import NginxParser
from tests.fixtures.factories import make_evidence, make_tenant_context

SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples"

parser = NginxParser()

_COMBINED_HEADER = (
    b'192.168.1.1 - frank [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024'
)
_JSON_HEADER = b'{"Records": []}'
_UNKNOWN_HEADER = b"totally random garbage that matches nothing"


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    records = []
    async for r in it:
        records.append(r)
    return records


class TestNginxParserSupports:
    def test_supports_log_file_with_combined_format(self) -> None:
        assert parser.supports("access.log", "text/plain", _COMBINED_HEADER) is True

    def test_supports_txt_extension(self) -> None:
        assert parser.supports("web.txt", "text/plain", _COMBINED_HEADER) is True

    def test_does_not_support_json_extension(self) -> None:
        assert parser.supports("data.json", "application/json", _COMBINED_HEADER) is False

    def test_does_not_support_unrecognised_log_format(self) -> None:
        assert parser.supports("access.log", "text/plain", _UNKNOWN_HEADER) is False

    def test_does_not_support_evtx(self) -> None:
        assert parser.supports("system.evtx", "application/octet-stream", b"ElfFile\x00") is False


class TestNginxParserParse:
    @pytest.mark.asyncio
    async def test_parses_five_records(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert len(records) == 5

    @pytest.mark.asyncio
    async def test_record_timestamp_timezone_aware(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert records[0].timestamp.tzinfo is not None

    @pytest.mark.asyncio
    async def test_record_has_source_ip(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert records[0].extra.get("source.ip") == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_record_has_http_status_code_as_int(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert records[0].extra.get("http.response.status_code") == 200
        assert isinstance(records[0].extra["http.response.status_code"], int)

    @pytest.mark.asyncio
    async def test_malformed_lines_skipped(self) -> None:
        data = b"not a log line at all\n" + (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        # The malformed line is skipped; only the 5 valid lines are parsed.
        assert len(records) == 5

    @pytest.mark.asyncio
    async def test_record_has_kronos_provenance(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert records[0].kronos.evidence_id == evidence.evidence_id
        assert records[0].kronos.parser == "nginx"

    @pytest.mark.asyncio
    async def test_record_index_sequential(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert [r.kronos.record_index for r in records] == list(range(5))

    @pytest.mark.asyncio
    async def test_category_is_web(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert "web" in records[0].event_category

    @pytest.mark.asyncio
    async def test_user_name_set_for_authenticated_user(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        # First line has user "frank".
        assert records[0].user_name == "frank"

    @pytest.mark.asyncio
    async def test_user_name_none_for_anonymous(self) -> None:
        fixture = (SAMPLES / "nginx.log").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        # Second line has "-" as remote_user → None.
        assert records[1].user_name is None
