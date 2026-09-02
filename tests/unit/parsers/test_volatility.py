"""VolatilityModule tests: detection, artifact construction, chunking, and
graceful degradation on a real subprocess-boundary failure.

Mirrors test_tar_archive.py/test_plaso_parser.py's own idiom (CLAUDE.md
§B.5: mock only the external dependency -- here, VolatilityLauncher's own
subprocess boundary -- never domain objects). The real, end-to-end
reproduction against the real, classic `cridex.vmem` sample (and a real
1.6GB user-uploaded image) lives in `poc/volatility_multiplugin/` per
CLAUDE.md Section F; this file covers VolatilityModule's own unit-level
contract with a fake VolatilityLauncher, exactly as test_tar_archive.py
already does for TarArchiveParser's YARA collaborator.

Milestone CCCCC: rewritten for the multi-plugin result shape
(`VolatilityMultiPluginResult`/`VolatilityPluginOutcome` replace the old
single-plugin primary/fallback pair) -- uses the real dataclasses directly
as test fixtures rather than hand-rolled fakes, since they're plain,
side-effect-free data containers (avoids drift between a fake shape and the
real one).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest

from src.application.parsing import ParserType
from src.domain.artifact import StructuredArtifact
from src.domain.timeline import EvidenceProvenance, TimelineRecord
from src.exceptions import VolatilityScanError
from src.external.parsers import volatility as volatility_module
from src.external.parsers.volatility import VolatilityModule, _plugin_to_kind
from src.external.sandbox.volatility_launcher import (
    VolatilityMultiPluginResult,
    VolatilityPluginOutcome,
)
from tests.fixtures.factories import make_evidence, make_tenant_context


class _FakeSettings:
    """Stands in for src.config.Settings -- only the one attribute
    VolatilityModule reads is needed, avoiding the real Settings' many
    required env vars (database_url, redis_url, etc.) in these unit tests.
    """

    volatility_worker_path: str | None = None


def _outcome(
    plugin: str,
    rows: tuple[dict[str, Any], ...] = (),
    *,
    status: str = "ok",
    error: str | None = None,
) -> VolatilityPluginOutcome:
    return VolatilityPluginOutcome(plugin=plugin, status=status, rows=rows, error=error)


class _FakeLauncher:
    """Drop-in for VolatilityLauncher: returns a canned result or raises."""

    last_kwargs: dict[str, Any] | None = None

    def __init__(
        self,
        result: VolatilityMultiPluginResult | None = None,
        error: Exception | None = None,
        **_kw: Any,
    ) -> None:
        self._result = result
        self._error = error

    async def run(self, **kwargs: Any) -> VolatilityMultiPluginResult:
        _FakeLauncher.last_kwargs = kwargs
        if self._error is not None:
            raise self._error
        assert self._result is not None
        return self._result


def _install_fake_launcher(
    monkeypatch: pytest.MonkeyPatch,
    result: VolatilityMultiPluginResult | None = None,
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


async def _drain_records(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


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
        assert _plugin_to_kind("windows.pstree.PsTree") == "volatility.pstree"

    def test_windows_psscan_maps_to_volatility_psscan(self) -> None:
        assert _plugin_to_kind("windows.psscan.PsScan") == "volatility.psscan"

    def test_windows_dlllist_maps_to_volatility_dlllist(self) -> None:
        assert _plugin_to_kind("windows.dlllist.DllList") == "volatility.dlllist"

    def test_windows_cmdline_maps_to_volatility_cmdline(self) -> None:
        assert _plugin_to_kind("windows.cmdline.CmdLine") == "volatility.cmdline"

    def test_windows_filescan_maps_to_volatility_filescan(self) -> None:
        assert _plugin_to_kind("windows.filescan.FileScan") == "volatility.filescan"

    def test_windows_registry_hivelist_keeps_registry_segment(self) -> None:
        # Real, multi-segment plugin path -- must strip only the OS prefix
        # and the trailing class name, not the "registry" module segment.
        assert (
            _plugin_to_kind("windows.registry.hivelist.HiveList") == "volatility.registry.hivelist"
        )

    def test_malfind_uses_the_explicit_override_not_the_derived_path(self) -> None:
        # Real finding this session: malfind's canonical import path moved to
        # windows.malware.malfind.Malfind in the pinned volatility3==2.28.0 --
        # naive derivation would give "volatility.malware.malfind", a worse,
        # less stable kind name than the intended "volatility.malfind".
        assert _plugin_to_kind("windows.malware.malfind.Malfind") == "volatility.malfind"

    def test_linux_pslist_maps_to_same_namespace_as_windows(self) -> None:
        # Kind describes *what the data is*, not which OS build produced it.
        assert _plugin_to_kind("linux.pslist.PsList") == "volatility.pslist"


# ---------------------------------------------------------------------------
# extract_artifacts()
# ---------------------------------------------------------------------------


class TestExtractArtifacts:
    async def test_yields_one_artifact_per_ok_plugin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = VolatilityMultiPluginResult(
            outcomes=(
                _outcome(
                    "windows.pstree.PsTree", ({"PID": 4, "PPID": 0, "ImageFileName": "System"},)
                ),
                _outcome(
                    "windows.psscan.PsScan",
                    ({"PID": 908, "PPID": 652, "ImageFileName": "svchost.exe"},),
                ),
            )
        )
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(
                _bytes_stream(b"fake-memory-bytes"), evidence, make_tenant_context()
            )
        )

        assert len(artifacts) == 2
        assert artifacts[0].kind == "volatility.pstree"
        assert artifacts[0].content["plugin"] == "windows.pstree.PsTree"
        assert artifacts[0].content["rows"] == [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
        assert artifacts[0].kronos.evidence_id == evidence.evidence_id
        assert artifacts[0].kronos.parser == "volatility3"
        assert artifacts[0].kronos.parser_version == "2.28.0"
        assert artifacts[1].kind == "volatility.psscan"
        # record_index is contiguous across every plugin's own artifact(s).
        assert artifacts[0].kronos.record_index == 0
        assert artifacts[1].kronos.record_index == 1

    async def test_yields_honest_empty_artifact_for_a_plugin_that_ran_clean_and_found_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = VolatilityMultiPluginResult(outcomes=(_outcome("windows.pstree.PsTree", ()),))
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(artifacts) == 1
        assert artifacts[0].kind == "volatility.pstree"
        assert artifacts[0].content["rows"] == []

    async def test_a_genuinely_failed_plugin_yields_no_artifact_at_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real per-plugin failure (e.g. automagic construction failed for
        this specific plugin) is honestly different from "ran cleanly and
        found nothing" -- no fabricated empty artifact, while sibling
        plugins that DID succeed still get their own real artifacts."""
        result = VolatilityMultiPluginResult(
            outcomes=(
                _outcome("windows.pstree.PsTree", ({"PID": 4},)),
                _outcome(
                    "windows.malware.malfind.Malfind",
                    (),
                    status="scan_error",
                    error="Unsatisfied requirement plugins.Malfind.kernel.layer_name",
                ),
            )
        )
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(artifacts) == 1
        assert artifacts[0].kind == "volatility.pstree"

    async def test_scan_error_yields_no_artifacts_and_does_not_raise(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A whole-run volatility3 failure (every plugin failed, or the
        worker couldn't even launch) must never abort the evidence file's
        parse -- mirrors TarArchiveParser's yara_ruleset_compile_failed
        precedent.
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
        result = VolatilityMultiPluginResult(
            outcomes=(_outcome("windows.psscan.PsScan", big_rows),)
        )
        _install_fake_launcher(monkeypatch, result=result)
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

    async def test_launcher_receives_the_configured_plugin_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = VolatilityMultiPluginResult(outcomes=(_outcome("windows.pstree.PsTree", ()),))
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule(plugins=("windows.pstree.PsTree", "windows.dlllist.DllList"))

        await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert _FakeLauncher.last_kwargs is not None
        assert _FakeLauncher.last_kwargs["plugins"] == (
            "windows.pstree.PsTree",
            "windows.dlllist.DllList",
        )


class TestParseDualEmit:
    """Gap Audit Milestone AAAAA (extended CCCCC): parse() derives a real
    process-creation TimelineRecord for every pstree/psscan row carrying a
    parseable CreateTime, and caches the scan result for extract_artifacts()
    to reuse -- see volatility.py's own module docstring for the full
    "one scan, not N" design.
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
        result = VolatilityMultiPluginResult(outcomes=(_outcome("windows.psscan.PsScan", rows),))
        _install_fake_launcher(monkeypatch, result=result)
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
        result = VolatilityMultiPluginResult(
            outcomes=(
                _outcome(
                    "windows.pstree.PsTree", ({"PID": 1, "PPID": 0, "ImageFileName": "System"},)
                ),
            )
        )
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule()

        records = await _drain_records(
            parser.parse(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert records == []

    async def test_parse_prefers_pstree_but_falls_back_to_psscan_when_pstree_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real, verified cridex.vmem shape: pstree legitimately empty,
        psscan is the only real source -- must not double-count a process
        that both plugins would otherwise agree on (see _timeline_rows's
        own docstring)."""
        psscan_rows = (
            {
                "PID": 908,
                "PPID": 652,
                "ImageFileName": "svchost.exe",
                "CreateTime": "2012-07-22T02:42:33+00:00",
            },
        )
        result = VolatilityMultiPluginResult(
            outcomes=(
                _outcome("windows.pstree.PsTree", ()),
                _outcome("windows.psscan.PsScan", psscan_rows),
            )
        )
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule()

        records = await _drain_records(
            parser.parse(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(records) == 1
        assert records[0].extra["volatility.plugin"] == "windows.psscan.PsScan"

    async def test_parse_does_not_double_emit_when_both_pstree_and_psscan_have_the_same_process(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real, common case once pstree succeeds: psscan is a superset
        pool-tag scan that would recover the SAME process again -- pstree
        being preferred (and psscan's own contribution skipped entirely)
        is what prevents a duplicate process-creation TimelineRecord."""
        pstree_rows = (
            {
                "PID": 908,
                "PPID": 652,
                "ImageFileName": "svchost.exe",
                "CreateTime": "2012-07-22T02:42:33+00:00",
            },
        )
        psscan_rows = pstree_rows + (
            {
                "PID": 2080,
                "PPID": 3060,
                "ImageFileName": "firefox.exe",
                "CreateTime": "2019-08-19T14:41:08+00:00",
            },
        )
        result = VolatilityMultiPluginResult(
            outcomes=(
                _outcome("windows.pstree.PsTree", pstree_rows),
                _outcome("windows.psscan.PsScan", psscan_rows),
            )
        )
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule()

        records = await _drain_records(
            parser.parse(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(records) == 1
        assert records[0].process_name == "svchost.exe"

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
        see volatility.py's own "one scan, not N" docstring section.
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
        result = VolatilityMultiPluginResult(outcomes=(_outcome("windows.psscan.PsScan", rows),))

        class _CountingLauncher(_FakeLauncher):
            async def run(self, **kwargs: Any) -> VolatilityMultiPluginResult:
                nonlocal run_call_count
                run_call_count += 1
                return await super().run(**kwargs)

        monkeypatch.setattr("src.config.Settings", _FakeSettings)
        monkeypatch.setattr(
            "src.external.sandbox.volatility_launcher.VolatilityLauncher",
            lambda **kw: _CountingLauncher(result=result),
        )

        evidence = make_evidence()
        parser = VolatilityModule()
        tenant = make_tenant_context()

        records = await _drain_records(parser.parse(_bytes_stream(b"fake"), evidence, tenant))
        artifacts = await _drain(parser.extract_artifacts(_bytes_stream(b"fake"), evidence, tenant))

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
        result = VolatilityMultiPluginResult(outcomes=(_outcome("windows.psscan.PsScan", rows),))
        _install_fake_launcher(monkeypatch, result=result)
        evidence = make_evidence()
        parser = VolatilityModule()

        artifacts = await _drain(
            parser.extract_artifacts(_bytes_stream(b"fake"), evidence, make_tenant_context())
        )

        assert len(artifacts) == 1
        assert artifacts[0].content["rows"] == list(rows)
