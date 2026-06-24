"""Unit tests for CloudTrailParser."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from src.domain.timeline import TimelineRecord
from src.external.parsers.cloudtrail import CloudTrailParser
from tests.fixtures.factories import make_evidence, make_tenant_context

SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples"

_CLOUDTRAIL_HEADER = b'{"Records": [{"eventTime": "2024-01-15T10:30:00Z"'
_NO_RECORDS_HEADER = b'{"data": []}'
_EVTX_HEADER = b"ElfFile\x00" + b"\x00" * 50

parser = CloudTrailParser()


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    records = []
    async for r in it:
        records.append(r)
    return records


class TestCloudTrailParserSupports:
    def test_supports_json_with_records_key(self) -> None:
        assert parser.supports("trail.json", "application/json", _CLOUDTRAIL_HEADER) is True

    def test_supports_jsonl_extension(self) -> None:
        assert parser.supports("trail.jsonl", "application/json", _CLOUDTRAIL_HEADER) is True

    def test_does_not_support_json_without_records_key(self) -> None:
        assert parser.supports("data.json", "application/json", _NO_RECORDS_HEADER) is False

    def test_does_not_support_evtx_extension(self) -> None:
        assert parser.supports("log.evtx", "application/octet-stream", b'"Records"') is False

    def test_does_not_support_log_extension(self) -> None:
        assert parser.supports("access.log", "text/plain", _CLOUDTRAIL_HEADER) is False


class TestCloudTrailParserParse:
    @pytest.mark.asyncio
    async def test_parses_two_records(self) -> None:
        fixture = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_record_timestamp_parsed_correctly(self) -> None:
        fixture = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        ts = records[0].timestamp
        assert ts.year == 2024
        assert ts.month == 1
        assert ts.day == 15

    @pytest.mark.asyncio
    async def test_record_has_kronos_provenance(self) -> None:
        fixture = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert records[0].kronos.evidence_id == evidence.evidence_id
        assert records[0].kronos.parser == "cloudtrail"

    @pytest.mark.asyncio
    async def test_record_index_sequential(self) -> None:
        fixture = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert [r.kronos.record_index for r in records] == [0, 1]

    @pytest.mark.asyncio
    async def test_empty_records_array_yields_nothing(self) -> None:
        data = b'{"Records": []}'
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert records == []

    @pytest.mark.asyncio
    async def test_record_has_event_action_in_extra(self) -> None:
        fixture = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert records[0].extra.get("event.action") == "DescribeInstances"

    @pytest.mark.asyncio
    async def test_ndjson_format_parsed(self) -> None:
        line1 = json.dumps(
            {
                "Records": [
                    {
                        "eventTime": "2024-02-01T00:00:00Z",
                        "eventName": "X",
                        "eventSource": "s3.amazonaws.com",
                        "userIdentity": {"userName": "u", "accountId": "1"},
                    }
                ]
            }
        )
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(line1.encode()), evidence, tenant))
        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_category_is_cloud(self) -> None:
        fixture = (SAMPLES / "cloudtrail.json").read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(fixture), evidence, tenant))
        assert "cloud" in records[0].event_category
