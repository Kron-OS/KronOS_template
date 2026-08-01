"""ZipArchiveParser tests: real KAPE-shaped zip + synthetic adversarial zips.

tests/fixtures/samples/real/kape/kape_triage.zip is a real ZIP built from the
same real forensic artifacts used elsewhere in this suite (see that
directory's NOTICE.md for full provenance and the honest note on why no
actual Windows system was involved), laid out under the real KAPE target
destination folder convention (``C/Windows/...``). This drives the exact
production path: ParserRegistry.get_parser() resolves ZipArchiveParser,
whose parse() recursively re-dispatches each member through the same
registry -- exactly what execute_parse() does in production.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.application.parser_registry import ParserRegistry
from src.domain.artifact import StructuredArtifact
from src.domain.timeline import TimelineRecord
from src.exceptions import ParsingError, YaraRuleCompilationError
from src.external.parsers import archive as archive_module
from src.external.parsers.archive import ZipArchiveParser
from src.external.parsers.chrome_history import ChromeHistoryParser
from src.external.parsers.cloudtrail import CloudTrailParser
from src.external.parsers.nginx import NginxParser
from src.external.sandbox.yara_x_runner import YaraRuleMatch, YaraScanResult, YaraStringMatch
from tests.fixtures.factories import make_evidence, make_tenant_context

REAL_SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples" / "real"
KAPE_ZIP = REAL_SAMPLES / "kape" / "kape_triage.zip"
KAPE_E01 = REAL_SAMPLES / "kape" / "kape_triage.E01"

_HEADER_BYTES = 8192


def _make_registry_with_zip() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(ZipArchiveParser(registry))
    registry.register(CloudTrailParser())
    registry.register(NginxParser())
    registry.register(ChromeHistoryParser())
    return registry


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


def _build_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Real KAPE zip: detection + recursive re-dispatch
# ---------------------------------------------------------------------------


class TestRealKapeZip:
    def test_registry_detects_zip_archive_parser(self) -> None:
        registry = _make_registry_with_zip()
        header = KAPE_ZIP.read_bytes()[:_HEADER_BYTES]
        parser = registry.get_parser(KAPE_ZIP.name, "application/zip", header)
        assert isinstance(parser, ZipArchiveParser)

    @pytest.mark.asyncio
    async def test_recursively_dispatches_every_member_to_its_real_parser(self) -> None:
        # Real members: EVTX (evtx-rs, needs the optional `evtx` package --
        # skip that assertion path if unavailable, same gating
        # test_real_world_samples.py uses), Chrome History, an IIS-style
        # access log (nginx parser, format-agnostic despite the name), and a
        # Prefetch file (Plaso -- not installed in this unit-test venv, so
        # it is expected to be skipped with a log, not fail the whole zip).
        registry = _make_registry_with_zip()
        evidence = make_evidence()
        evidence = evidence.model_copy(
            update={"sha256": __import__("hashlib").sha256(KAPE_ZIP.read_bytes()).hexdigest()}
        )
        tenant = make_tenant_context()
        parser = registry.get_parser(
            KAPE_ZIP.name, "application/zip", KAPE_ZIP.read_bytes()[:_HEADER_BYTES]
        )
        assert parser is not None
        records = await _drain(parser.parse(_bytes_stream(KAPE_ZIP.read_bytes()), evidence, tenant))

        by_parser: dict[str, list[TimelineRecord]] = {}
        for r in records:
            by_parser.setdefault(r.kronos.parser, []).append(r)

        assert by_parser["chrome-history"], "Chrome History member must be re-dispatched"
        assert {r.kronos.source_path for r in by_parser["chrome-history"]} == {
            "C/Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History"
        }
        assert by_parser["nginx"], "the IIS-style access log member must be re-dispatched"
        assert {r.kronos.source_path for r in by_parser["nginx"]} == {
            "C/inetpub/logs/LogFiles/W3SVC1/u_ex260723.log"
        }
        # Every record, regardless of which inner parser produced it, must
        # link back to the outer container's own sha256.
        assert all(r.kronos.container_sha256 == evidence.sha256 for r in records)

    @pytest.mark.asyncio
    async def test_evtx_member_gets_real_source_path_when_evtx_installed(self) -> None:
        pytest.importorskip("evtx")
        from src.external.parsers.evtx import FastEvtxParser  # noqa: PLC0415

        registry = _make_registry_with_zip()
        registry.register(FastEvtxParser())
        evidence = make_evidence()
        evidence = evidence.model_copy(
            update={"sha256": __import__("hashlib").sha256(KAPE_ZIP.read_bytes()).hexdigest()}
        )
        tenant = make_tenant_context()
        parser = registry.get_parser(
            KAPE_ZIP.name, "application/zip", KAPE_ZIP.read_bytes()[:_HEADER_BYTES]
        )
        assert parser is not None
        records = await _drain(parser.parse(_bytes_stream(KAPE_ZIP.read_bytes()), evidence, tenant))
        evtx_records = [r for r in records if r.kronos.parser == "evtx-rs"]
        assert len(evtx_records) > 0
        assert {r.kronos.source_path for r in evtx_records} == {
            "C/Windows/System32/winevt/Logs/System.evtx"
        }


# ---------------------------------------------------------------------------
# Adversarial / guard behaviour (synthetic zips -- no real fixture needed)
# ---------------------------------------------------------------------------


class TestZipArchiveGuards:
    @pytest.mark.asyncio
    async def test_rejects_zip_slip_member_path(self) -> None:
        # A member path escaping the extraction root must be skipped, not
        # followed -- verified by asserting no record is ever produced from
        # it (there is no parser that could resolve to "escape.txt" content
        # anyway, but the point is _is_unsafe_member_path filters it before
        # even attempting detection).
        registry = ParserRegistry()
        registry.register(ZipArchiveParser(registry))
        registry.register(NginxParser())
        data = _build_zip(
            {
                "../../etc/passwd": b"root:x:0:0::/root:/bin/bash\n",
                "safe/access.log": (
                    b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100\n'
                ),
            }
        )
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("evil.zip", "application/zip", data[:_HEADER_BYTES])
        assert isinstance(parser, ZipArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert all(r.kronos.source_path != "../../etc/passwd" for r in records)
        # The safe, non-traversal member is still processed normally.
        assert any(r.kronos.source_path == "safe/access.log" for r in records)

    @pytest.mark.asyncio
    async def test_rejects_container_nesting_beyond_max_depth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive_module, "MAX_CONTAINER_DEPTH", 2)
        registry = ParserRegistry()
        registry.register(ZipArchiveParser(registry))

        # Build 3 levels of zip-in-zip -- one more than the patched max depth.
        innermost = _build_zip({"leaf.txt": b"hello"})
        level2 = _build_zip({"nested.zip": innermost})
        level1 = _build_zip({"nested.zip": level2})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("l1.zip", "application/zip", level1[:_HEADER_BYTES])
        assert isinstance(parser, ZipArchiveParser)
        with pytest.raises(ParsingError, match="maximum depth"):
            await _drain(parser.parse(_bytes_stream(level1), evidence, tenant))

    @pytest.mark.asyncio
    async def test_rejects_container_exceeding_max_member_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive_module, "MAX_MEMBER_COUNT", 3)
        registry = ParserRegistry()
        registry.register(ZipArchiveParser(registry))
        data = _build_zip({f"file{i}.txt": b"x" for i in range(5)})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("many.zip", "application/zip", data[:_HEADER_BYTES])
        assert isinstance(parser, ZipArchiveParser)
        with pytest.raises(ParsingError, match="member count"):
            await _drain(parser.parse(_bytes_stream(data), evidence, tenant))

    @pytest.mark.asyncio
    async def test_rejects_container_exceeding_total_byte_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive_module, "MAX_TOTAL_UNCOMPRESSED_BYTES", 10)
        registry = ParserRegistry()
        registry.register(ZipArchiveParser(registry))
        data = _build_zip({"big.txt": b"x" * 100})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("big.zip", "application/zip", data[:_HEADER_BYTES])
        assert isinstance(parser, ZipArchiveParser)
        with pytest.raises(ParsingError, match="total extracted bytes"):
            await _drain(parser.parse(_bytes_stream(data), evidence, tenant))

    @pytest.mark.asyncio
    async def test_skips_oversized_single_member_without_failing_whole_container(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(archive_module, "MAX_PER_FILE_UNCOMPRESSED_BYTES", 200)
        registry = ParserRegistry()
        registry.register(ZipArchiveParser(registry))
        registry.register(NginxParser())
        data = _build_zip(
            {
                "huge.bin": b"x" * 1000,
                "access.log": (
                    b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100\n'
                ),
            }
        )
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("mixed.zip", "application/zip", data[:_HEADER_BYTES])
        assert isinstance(parser, ZipArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert any(r.kronos.source_path == "access.log" for r in records)
        assert all(r.kronos.source_path != "huge.bin" for r in records)

    @pytest.mark.asyncio
    async def test_bad_zip_raises_parsing_error(self) -> None:
        registry = ParserRegistry()
        registry.register(ZipArchiveParser(registry))
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = ZipArchiveParser(registry)
        with pytest.raises(ParsingError, match="valid ZIP"):
            await _drain(parser.parse(_bytes_stream(b"PK\x03\x04not a real zip"), evidence, tenant))

    @pytest.mark.asyncio
    async def test_unmatched_member_is_skipped_not_fatal(self) -> None:
        # A member no registered parser recognises (here: nothing is
        # registered at all besides the zip parser itself) must be silently
        # skipped, not raise -- one unparseable file inside a large KAPE zip
        # must not sink the whole evidence to ERROR.
        registry = ParserRegistry()
        registry.register(ZipArchiveParser(registry))
        data = _build_zip({"mystery.bin": b"\x00\x01\x02\x03"})
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("m.zip", "application/zip", data[:_HEADER_BYTES])
        assert isinstance(parser, ZipArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert records == []


# ---------------------------------------------------------------------------
# EWF (E01) detection -- routed to Plaso, see src/external/parsers/plaso.py
# ---------------------------------------------------------------------------


class TestRealE01Detection:
    FIXTURE = KAPE_E01

    def test_plaso_parser_detects_ewf_magic(self) -> None:
        from src.external.parsers.plaso import PlasoParser  # noqa: PLC0415

        header = self.FIXTURE.read_bytes()[:_HEADER_BYTES]
        assert header.startswith(b"EVF\x09\x0d\x0a\xff\x00")  # ground truth
        assert PlasoParser().supports(self.FIXTURE.name, "application/octet-stream", header)


# ---------------------------------------------------------------------------
# YARA scanning via extract_artifacts() (roadmap E3) -- lighter mirror of
# test_tar_archive.py's TestTarYaraArtifactExtraction (ZipArchiveParser and
# TarArchiveParser share the identical extract_artifacts()/_scan_members_for_
# yara implementation shape by construction -- full coverage lives on the
# tar side, this confirms the zip side behaves identically, not a second
# full copy of every case).
# ---------------------------------------------------------------------------


class _StubRuleProvider:
    def __init__(self, rule_source: str | None) -> None:
        self._rule_source = rule_source

    async def get_rule_source(self) -> str | None:
        return self._rule_source


class TestZipYaraArtifactExtraction:
    @pytest.mark.asyncio
    async def test_no_runner_configured_yields_nothing(self) -> None:
        parser = ZipArchiveParser(ParserRegistry(), yara_runner=None, yara_rule_provider=None)
        data = _build_zip({"a.txt": b"hello"})
        evidence = make_evidence()
        tenant = make_tenant_context()

        artifacts = [
            a async for a in parser.extract_artifacts(_bytes_stream(data), evidence, tenant)
        ]

        assert artifacts == []

    @pytest.mark.asyncio
    async def test_real_match_yields_structured_artifact_with_correct_provenance(self) -> None:
        runner = AsyncMock()
        runner.run.return_value = YaraScanResult(
            matched_rules=(
                YaraRuleMatch(
                    identifier="evil_rule",
                    namespace="default",
                    tags=(),
                    matched_strings=(YaraStringMatch(pattern_identifier="$a", offset=2, length=5),),
                ),
            )
        )
        parser = ZipArchiveParser(
            ParserRegistry(),
            yara_runner=runner,
            yara_rule_provider=_StubRuleProvider("rule x {...}"),
        )
        data = _build_zip({"payload.bin": b"xxevilxx"})
        evidence = make_evidence()
        tenant = make_tenant_context()

        artifacts: list[StructuredArtifact] = [
            a async for a in parser.extract_artifacts(_bytes_stream(data), evidence, tenant)
        ]

        assert len(artifacts) == 1
        assert artifacts[0].kind == "yara.match"
        assert artifacts[0].kronos.source_path == "payload.bin"
        assert artifacts[0].kronos.org_alias == evidence.metadata.org_alias

    @pytest.mark.asyncio
    async def test_compile_error_does_not_raise(self) -> None:
        runner = AsyncMock()
        runner.run.side_effect = YaraRuleCompilationError("bad syntax")
        parser = ZipArchiveParser(
            ParserRegistry(),
            yara_runner=runner,
            yara_rule_provider=_StubRuleProvider("not valid {{{"),
        )
        data = _build_zip({"a.txt": b"one"})
        evidence = make_evidence()
        tenant = make_tenant_context()

        artifacts = [
            a async for a in parser.extract_artifacts(_bytes_stream(data), evidence, tenant)
        ]

        assert artifacts == []
