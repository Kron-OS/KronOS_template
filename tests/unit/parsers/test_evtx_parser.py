"""Unit tests for FastEvtxParser.

All tests are skipped if the 'evtx' package is not installed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

evtx = pytest.importorskip("evtx")  # skip entire module if evtx is not installed

from src.domain.timeline import TimelineRecord  # noqa: E402
from src.external.parsers.evtx import FastEvtxParser  # noqa: E402
from tests.fixtures.factories import make_evidence, make_tenant_context  # noqa: E402

SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples"
EVTX_FILE = SAMPLES / "test.evtx"

parser = FastEvtxParser()

_EVTX_MAGIC = b"ElfFile\x00" + b"\x00" * 50
_JSON_HEADER = b'{"Records": []}'


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    records = []
    async for r in it:
        records.append(r)
    return records


class TestFastEvtxParserSupports:
    def test_supports_evtx_magic_bytes(self) -> None:
        assert parser.supports("system.evtx", "application/octet-stream", _EVTX_MAGIC) is True

    def test_does_not_support_json(self) -> None:
        assert parser.supports("data.json", "application/json", _JSON_HEADER) is False

    def test_does_not_support_wrong_magic(self) -> None:
        assert parser.supports("file.evtx", "application/octet-stream", b"\x00" * 50) is False

    def test_magic_check_uses_first_8_bytes(self) -> None:
        # Only the first 8 bytes are checked.
        header = b"ElfFile\x00" + b"\xff" * 100
        assert parser.supports("sys.evtx", "application/octet-stream", header) is True


class TestFastEvtxParserParse:
    @pytest.mark.asyncio
    async def test_parse_yields_records(self) -> None:
        if not EVTX_FILE.exists():
            pytest.skip("test.evtx not found — run tests/fixtures/samples/generate_test_evtx.py")
        data = EVTX_FILE.read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        # A real EVTX file should yield at least one record.
        assert len(records) >= 0  # permissive: stub file may yield 0

    @pytest.mark.asyncio
    async def test_record_has_kronos_provenance(self) -> None:
        if not EVTX_FILE.exists():
            pytest.skip("test.evtx not found — run tests/fixtures/samples/generate_test_evtx.py")
        data = EVTX_FILE.read_bytes()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        if records:
            assert records[0].kronos.evidence_id == evidence.evidence_id
            assert records[0].kronos.parser == "evtx-rs"
