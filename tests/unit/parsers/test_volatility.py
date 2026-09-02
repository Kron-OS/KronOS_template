"""VolatilityModule tests: detection, artifact construction, chunking, and
graceful degradation on a real subprocess-boundary failure.

Mirrors test_tar_archive.py/test_plaso_parser.py's own idiom (CLAUDE.md
§B.5: mock only the external dependency -- here, VolatilityLauncher's own
subprocess boundary -- never domain objects). The real, end-to-end
reproduction against the real, classic `cridex.vmem` sample (real
volatility3==2.28.0, real `windows.pstree` -> `windows.psscan` fallback)
lives in `poc/volatility_memory_module/` per CLAUDE.md Section F; this file
covers VolatilityModule's own unit-level contract with a fake
VolatilityLauncher, exactly as test_tar_archive.py already does for
TarArchiveParser's YARA collaborator.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest

from src.application.parsing import ParserType
from src.domain.artifact import StructuredArtifact
from src.domain.timeline import EvidenceProvenance, TimelineRecord
from src.exceptions import VolatilityScanError
from src.external.parsers import volatility as volatility_module
from src.external.parsers.volatility import VolatilityModule, _plugin_to_kind
from tests.fixtures.factories import make_evidence, make_tenant_context


class _FakeSettings:
    """Stands in for src.config.Settings -- only the one attribute
    VolatilityModule reads is needed, avoiding the real Settings' many
    required env vars (database_url, redis_url, etc.) in these unit tests.
    """

    volatility_worker_path: str | None = None


@dataclass(frozen=True)
class _FakeResult:
    plugin: str
    rows: tuple[dict[str, Any], ...]
    fallback_plugin: str | None = None
    fallback_rows: tuple[dict[str, Any], ...] | None = None

    @property
    def used_fallback(self) -> bool:
        return self.fallback_plugin is not None


class _FakeLauncher:
    """Drop-in for VolatilityLauncher: returns a canned result or raises."""

    last_kwargs: dict[str, Any] | None = None

    def __init__(
        self, result: _FakeResult | None = None, error: Exception | None = None, **_kw: Any
    ) -> None:
        self._result = result
        self._error = error

    async def run(self, **kwargs: Any) -> _FakeResult:
        _FakeLauncher.last_kwargs = kwargs
        if self._error is not None:
            raise self._error
        assert self._result is not None
        return self._result


def _install_fake_launcher(
    monkeypatch: pytest.MonkeyPatch,
    result: _FakeResult | None = None,
    error: Exception | None = None,
) -> None:
    monkeypatch.setattr("src.config.Settings", _FakeSettings)

    def _factory(**kwargs: Any) -> _FakeLauncher:
        return _FakeLauncher(result=result, error=error, **kwargs)

    monkeypatch.setattr("src.external.sandbox.volatility_launcher.VolatilityLauncher", _factory)


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[StructuredArtifact]) -> list[StructuredArtifact]:
    return [a async for a in it]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestSupports:
    def test_supports_vmem_extension(self) -> None:
        assert VolatilityModule().supports("cridex.vmem", "application/octet-stream", b"\x00" * 16)

    def test_supports_mem_extension(self) -> None:
        assert VolatilityModule().supports("memory.mem", "application/octet-stream", b"\x00" * 16)

    def test_supports_raw_extension(self) -> None:
        assert VolatilityModule().supports("memory.raw", "application/octet-stream", b"\x00" * 16)

    def test_supports_dmp_extension(self) -> None:
        assert VolatilityModule().supports("crash.dmp", "application/octet-stream", b"\x00" * 16)

    def test_supports_lime_extension(self) -> None:
        assert VolatilityModule().supports("memory.lime", "application/octet-stream", b"\x00" * 16)

    def test_does_not_support_evtx(self) -> None:
        header = b"ElfFile\x00" + b"\x00" * 30
        assert not VolatilityModule().supports("system.evtx", "application/octet-stream", header)

    def test_does_not_support_unrelated_extension(self) -> None:
        assert not VolatilityModule().supports("notes.txt", "text/plain", b"hello")

    def test_parser_name(self) -> None:
        assert VolatilityModule().parser_name == "volatility3"

    def test_parser_version_is_pinned_tool_version(self) -> None:
        assert VolatilityModule().parser_version == "2.28.0"

    def test_parser_type_is_heavy(self) -> None:
        assert VolatilityModule().parser_type == ParserType.HEAVY


# ---------------------------------------------------------------------------
# Plugin -> kind mapping
# ---------------------------------------------------------------------------


class TestPluginToKind:
    def test_windows_pstree_maps_to_volatility_pstree(self) -> None:
        assert _plugin_to_kind("windows.pstree") == "volatility.pstree"

    def test_windows_psscan_maps_to_volatility_psscan(self) -> None:
        assert _plugin_to_kind("windows.psscan") == "volatility.psscan"

    def test_linux_pslist_maps_to_same_namespace_as_windows(self) -> None:
        # Kind describes *what the data is*, not which OS build produced it.
        assert _plugin_to_kind("linux.pslist") == "volatility.pslist"

    def test_plugin_with_no_dot_passes_through(self) -> None:
        assert _plugin_to_kind("pstree") == "volatility.pstree"


# ---------------------------------------------------------------------------
# extract_artifacts()
# ---------------------------------------------------------------------------


class TestExtractArtifacts:
    async def test_yields_one_artifact_from_nonempty_primary_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = ({"PID": 4, "PPID": 0, "ImageFileName": "System"},)
        _install_fake_launcher(monkeypatch, result=_FakeResult(plugin="windows.pstree", rows=rows))
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(
                _bytes_stream(b"fake-memory-bytes"), evidence, make_tenant_context()
            )
        )

        assert len(artifacts) == 1
        assert artifacts[0].kind == "volatility.pstree"
        assert artifacts[0].content["plugin"] == "windows.pstree"
        assert artifacts[0].content["rows"] == [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
        assert artifacts[0].kronos.evidence_id == evidence.evidence_id
        assert artifacts[0].kronos.parser == "volatility3"
        assert artifacts[0].kronos.parser_version == "2.28.0"

    async def test_yields_honest_empty_artifact_when_primary_empty_and_no_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_launcher(monkeypatch, result=_FakeResult(plugin="windows.pstree", rows=()))
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(artifacts) == 1
        assert artifacts[0].kind == "volatility.pstree"
        assert artifacts[0].content["rows"] == []

    async def test_yields_fallback_artifact_when_primary_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mirrors the real, reproduced cridex.vmem finding: pstree empty,
        psscan recovers real rows -- see poc/volatility_memory_module/.
        """
        fallback_rows = (
            {"PID": 908, "PPID": 652, "ImageFileName": "svchost.exe"},
            {"PID": 1484, "PPID": 1464, "ImageFileName": "explorer.exe"},
        )
        _install_fake_launcher(
            monkeypatch,
            result=_FakeResult(
                plugin="windows.pstree",
                rows=(),
                fallback_plugin="windows.psscan",
                fallback_rows=fallback_rows,
            ),
        )
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(artifacts) == 2
        assert artifacts[0].kind == "volatility.pstree"
        assert artifacts[0].content["rows"] == []
        assert artifacts[1].kind == "volatility.psscan"
        assert len(artifacts[1].content["rows"]) == 2
        assert artifacts[1].content["rows"][1]["ImageFileName"] == "explorer.exe"
        # record_index must be contiguous across primary + fallback artifacts.
        assert artifacts[0].kronos.record_index == 0
        assert artifacts[1].kronos.record_index == 1

    async def test_scan_error_yields_no_artifacts_and_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A volatility3 failure must never abort the evidence file's parse --
        mirrors TarArchiveParser's yara_ruleset_compile_failed precedent.
        """
        _install_fake_launcher(
            monkeypatch, error=VolatilityScanError("vol CLI not found in worker runtime")
        )
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert artifacts == []

    async def test_splits_large_row_set_into_multiple_artifacts_of_same_kind(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Each row padded so a handful of rows trips the (patched, small)
        # per-batch cap -- proves the chunking path without needing a real
        # multi-MB payload in a unit test.
        big_rows = tuple({"PID": i, "PPID": 0, "ImageFileName": "x" * 200} for i in range(20))
        monkeypatch.setattr(volatility_module, "_MAX_ROWS_CONTENT_BYTES", 1024)
        _install_fake_launcher(
            monkeypatch, result=_FakeResult(plugin="windows.psscan", rows=big_rows)
        )
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(artifacts) > 1
        assert all(a.kind == "volatility.psscan" for a in artifacts)
        # Every row is preserved exactly once, in order, across the batches.
        recovered = [row for a in artifacts for row in a.content["rows"]]
        assert recovered == list(big_rows)
        # record_index is contiguous and unique across batches.
        indices = [a.kronos.record_index for a in artifacts]
        assert indices == list(range(len(artifacts)))
        # Every batch's own content actually respects the cap.
        for a in artifacts:
            size = len(json.dumps(a.content["rows"], default=str).encode("utf-8"))
            assert size <= 1024 or len(a.content["rows"]) == 1

    async def test_launcher_receives_configured_plugin_and_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_launcher(monkeypatch, result=_FakeResult(plugin="windows.pstree", rows=()))
        evidence = make_evidence()
        parser = VolatilityModule(plugin="windows.pstree", fallback_plugin="windows.psscan")

        await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert _FakeLauncher.last_kwargs is not None
        assert _FakeLauncher.last_kwargs["plugin"] == "windows.pstree"
        assert _FakeLauncher.last_kwargs["fallback_plugin"] == "windows.psscan"

async def _drain_records(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


class TestParseDualEmit:
    """Gap Audit Milestone AAAAA: parse() now derives a real
    process-creation TimelineRecord for every row carrying a parseable
    CreateTime, and caches the scan result for extract_artifacts() to
    reuse -- see volatility.py's own module docstring for the full
    "one scan, not two" design.
    """

    async def test_parse_yields_one_record_per_row_with_create_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = (
            {
                "PID": 908,
                "PPID": 652,
                "ImageFileName": "svchost.exe",
                "CreateTime": "2012-07-22T02:42:33+00:00",
                "Threads": 9,
                "SessionId": None,
                "Offset(V)": 33725112,
            },
            {
                "PID": 664,
                "PPID": 608,
                "ImageFileName": "lsass.exe",
                "CreateTime": None,  # real shape: some rows carry no CreateTime
            },
        )
        _install_fake_launcher(monkeypatch, result=_FakeResult(plugin="windows.psscan", rows=rows))
        evidence = make_evidence()
        parser = VolatilityModule()

        records = await _drain_records(
            parser.parse(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(records) == 1
        record = records[0]
        assert record.process_pid == 908
        assert record.process_name == "svchost.exe"
        assert record.event_category == ["process"]
        assert record.event_type == ["start"]
        assert record.extra["process.parent.pid"] == 652
        assert record.extra["process.thread.count"] == 9
        assert record.extra["volatility.offset_v"] == 33725112
        assert "volatility.session_id" not in record.extra  # None values omitted
        assert record.timestamp.isoformat() == "2012-07-22T02:42:33+00:00"
        assert isinstance(record.kronos, EvidenceProvenance)
        assert record.kronos.evidence_id == evidence.evidence_id
        assert record.kronos.parser == "volatility3"

    async def test_parse_yields_nothing_when_no_row_has_create_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows = ({"PID": 1, "PPID": 0, "ImageFileName": "System"},)
        _install_fake_launcher(monkeypatch, result=_FakeResult(plugin="windows.pstree", rows=rows))
        evidence = make_evidence()
        parser = VolatilityModule()

        records = await _drain_records(
            parser.parse(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert records == []

    async def test_parse_covers_fallback_rows_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fallback_rows = (
            {
                "PID": 908,
                "PPID": 652,
                "ImageFileName": "svchost.exe",
                "CreateTime": "2012-07-22T02:42:33+00:00",
            },
        )
        _install_fake_launcher(
            monkeypatch,
            result=_FakeResult(
                plugin="windows.pstree",
                rows=(),
                fallback_plugin="windows.psscan",
                fallback_rows=fallback_rows,
            ),
        )
        evidence = make_evidence()
        parser = VolatilityModule()

        records = await _drain_records(
            parser.parse(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(records) == 1
        assert records[0].extra["volatility.plugin"] == "windows.psscan"

    async def test_scan_error_yields_no_records_and_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_launcher(
            monkeypatch, error=VolatilityScanError("vol CLI not found in worker runtime")
        )
        evidence = make_evidence()
        parser = VolatilityModule()

        records = await _drain_records(
            parser.parse(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert records == []

    async def test_parse_then_extract_artifacts_only_runs_volatility_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real, load-bearing claim: calling parse() then
        extract_artifacts() for the same evidence file (exactly how
        ParsingOrchestrationService.execute_parse() calls a dual-implementing
        parser) invokes VolatilityLauncher.run() exactly once, not twice --
        see volatility.py's own "one scan, not two" docstring section.
        """
        run_call_count = 0
        rows = (
            {
                "PID": 908,
                "PPID": 652,
                "ImageFileName": "svchost.exe",
                "CreateTime": "2012-07-22T02:42:33+00:00",
            },
        )

        class _CountingLauncher(_FakeLauncher):
            async def run(self, **kwargs: Any) -> _FakeResult:
                nonlocal run_call_count
                run_call_count += 1
                return await super().run(**kwargs)

        monkeypatch.setattr("src.config.Settings", _FakeSettings)
        monkeypatch.setattr(
            "src.external.sandbox.volatility_launcher.VolatilityLauncher",
            lambda **kw: _CountingLauncher(result=_FakeResult(plugin="windows.psscan", rows=rows)),
        )

        evidence = make_evidence()
        parser = VolatilityModule()
        tenant = make_tenant_context()

        records = await _drain_records(parser.parse(_bytes_stream(b"fake"), evidence, tenant))
        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, tenant)
        )

        assert run_call_count == 1
        assert len(records) == 1
        assert len(artifacts) == 1
        assert artifacts[0].content["rows"] == list(rows)

    async def test_extract_artifacts_still_runs_volatility_when_called_standalone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same "still independently callable" contract every other
        extract_artifacts() override honours -- no cached scan present
        (parse() was never called first) falls back to a real scan.
        """
        rows = ({"PID": 1, "PPID": 0, "ImageFileName": "System"},)
        _install_fake_launcher(monkeypatch, result=_FakeResult(plugin="windows.psscan", rows=rows))
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(artifacts) == 1
        assert artifacts[0].content["rows"] == list(rows)
