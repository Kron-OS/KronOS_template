"""Unit tests for VolatilityLauncher's subprocess/JSON-io contract.

Mirrors test_yara_x_runner.py's own idiom (CLAUDE.md §B.5: mock only the
external dependency -- here, the worker subprocess -- never the domain
objects): most tests swap in a small fake worker script that emits a
hand-crafted JSON payload, so the launcher's own parsing/error-mapping logic
is exercised against a real subprocess boundary without needing volatility3
installed. `test_real_worker_*` additionally drives the *real*
docker/volatility/kronos-volatility-worker.py script with the real, pinned
`volatility3==2.28.0` package against the real, classic `cridex.vmem` sample
-- see poc/volatility_memory_module/README.md for the from-first-principles
verification of this exact plugin/fallback behaviour. Those tests are gated
on both the real worker script existing (always true in this repo) and a
real downloaded sample being present locally (never committed -- see that
PoC's README for the download instructions) -- mirrors this repo's existing
`pytest.importorskip("evtx")` pattern for an optional real-artifact
dependency.
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

from src.exceptions import VolatilityScanError
from src.external.sandbox.volatility_launcher import VolatilityLauncher

pytestmark = pytest.mark.asyncio

_REAL_WORKER_PATH = (
    Path(__file__).parent.parent.parent / "docker" / "volatility" / "kronos-volatility-worker.py"
)

# Never committed (real cridex.vmem is ~512 MiB uncompressed -- see the PoC's
# own README for why) -- set this to a local scratch path to exercise the
# real-sample tests below; skipped, not failed, when unset/missing.
_REAL_SAMPLE_PATH = os.environ.get("KRONOS_CRIDEX_VMEM_PATH", "")
_REAL_VOL_AVAILABLE = _REAL_SAMPLE_PATH and Path(_REAL_SAMPLE_PATH).exists()


def _write_worker(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake_volatility_worker.py"
    script.write_text(textwrap.dedent(body))
    return script


async def test_run_returns_rows_from_ok_payload(tmp_path: Path) -> None:
    payload = {
        "status": "ok",
        "error": None,
        "plugin": "windows.pstree",
        "rows": [{"PID": 4, "PPID": 0, "ImageFileName": "System"}],
        "fallback_plugin": None,
        "fallback_rows": None,
    }
    script = _write_worker(
        tmp_path,
        f"""
        import json
        print(json.dumps({payload!r}))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    result = await launcher.run("/tmp/fake.vmem", plugin="windows.pstree")

    assert result.plugin == "windows.pstree"
    assert len(result.rows) == 1
    assert result.rows[0]["PID"] == 4
    assert result.used_fallback is False
    assert result.fallback_plugin is None


async def test_run_reports_fallback_when_primary_empty(tmp_path: Path) -> None:
    payload = {
        "status": "ok",
        "error": None,
        "plugin": "windows.pstree",
        "rows": [],
        "fallback_plugin": "windows.psscan",
        "fallback_rows": [{"PID": 908, "PPID": 652, "ImageFileName": "svchost.exe"}],
    }
    script = _write_worker(
        tmp_path,
        f"""
        import json
        print(json.dumps({payload!r}))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    result = await launcher.run("/tmp/fake.vmem")

    assert result.rows == ()
    assert result.used_fallback is True
    assert result.fallback_plugin == "windows.psscan"
    assert result.fallback_rows is not None
    assert result.fallback_rows[0]["ImageFileName"] == "svchost.exe"


async def test_run_raises_scan_error_on_scan_error_status(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({
            "status": "scan_error",
            "error": "volatility3 'vol' CLI not found in worker runtime",
            "plugin": "windows.pstree",
            "rows": [],
            "fallback_plugin": None,
            "fallback_rows": None,
        }))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(VolatilityScanError, match="vol' CLI not found"):
        await launcher.run("/tmp/fake.vmem")


async def test_run_raises_scan_error_on_timeout_status(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({
            "status": "timeout",
            "error": "windows.pstree exceeded 300s",
            "plugin": "windows.pstree",
            "rows": [],
            "fallback_plugin": None,
            "fallback_rows": None,
        }))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable, timeout_seconds=1)

    with pytest.raises(VolatilityScanError, match="exceeded 300s"):
        await launcher.run("/tmp/fake.vmem")


async def test_run_raises_on_outer_wallclock_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The launcher's own subprocess.run(timeout=...) is the outer kill-switch
    above the worker's in-worker --timeout-seconds, mirroring
    YaraXSandboxRunner's identical outer-timeout test.
    """
    monkeypatch.setattr(
        "src.external.sandbox.volatility_launcher._SUBPROCESS_TIMEOUT_MARGIN_SECONDS", 1
    )
    script = _write_worker(
        tmp_path,
        """
        import time
        time.sleep(30)
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable, timeout_seconds=0)

    with pytest.raises(VolatilityScanError, match="wall-clock timeout"):
        await launcher.run("/tmp/fake.vmem")


async def test_run_raises_on_nonzero_exit(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import sys
        sys.stderr.write("boom\\n")
        sys.exit(1)
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(VolatilityScanError, match="exited with code 1"):
        await launcher.run("/tmp/fake.vmem")


async def test_run_raises_on_unparseable_output(tmp_path: Path) -> None:
    script = _write_worker(tmp_path, 'print("this is not json")')
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(VolatilityScanError, match="unparseable output"):
        await launcher.run("/tmp/fake.vmem")


async def test_run_raises_on_empty_output(tmp_path: Path) -> None:
    script = _write_worker(tmp_path, "")
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(VolatilityScanError, match="no output"):
        await launcher.run("/tmp/fake.vmem")


async def test_missing_python_binary_raises_scan_error(tmp_path: Path) -> None:
    script = _write_worker(tmp_path, "")
    launcher = VolatilityLauncher(
        worker_path=script, python_bin=str(tmp_path / "no-such-interpreter")
    )

    with pytest.raises(VolatilityScanError, match="worker not found"):
        await launcher.run("/tmp/fake.vmem")


async def test_run_raises_on_unrecognized_status(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({"status": "something_else", "plugin": "x", "rows": []}))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(VolatilityScanError, match="unrecognized status"):
        await launcher.run("/tmp/fake.vmem")


async def test_stderr_is_logged_on_success(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        import sys
        sys.stderr.write("No metadata file found alongside VMEM file\\n")
        print(json.dumps({
            "status": "ok", "error": None, "plugin": "windows.pstree",
            "rows": [], "fallback_plugin": None, "fallback_rows": None,
        }))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with caplog.at_level("INFO"):
        await launcher.run("/tmp/fake.vmem")

    stderr_logs = [r for r in caplog.records if r.message == "volatility_worker_stderr"]
    assert len(stderr_logs) == 1
    assert "No metadata file" in stderr_logs[0].stderr


# --- Real worker + real volatility3 (pinned volatility3==2.28.0) -----------


@pytest.mark.skipif(not _REAL_WORKER_PATH.exists(), reason="real worker script missing")
@pytest.mark.skipif(
    not _REAL_VOL_AVAILABLE,
    reason="KRONOS_CRIDEX_VMEM_PATH not set or file missing; see poc/volatility_memory_module/",
)
async def test_real_worker_falls_back_to_psscan_on_real_cridex_sample() -> None:
    """End-to-end against the real, classic cridex.vmem sample.

    Real, reproduced finding (poc/volatility_memory_module/README.md):
    windows.pstree's own linked-list walk returns zero rows for this real
    sample + volatility3==2.28.0, while windows.psscan (same real file)
    recovers the real, well-documented process census.
    """
    launcher = VolatilityLauncher(
        worker_path=_REAL_WORKER_PATH, python_bin=sys.executable, timeout_seconds=120
    )

    result = await launcher.run(_REAL_SAMPLE_PATH)

    assert result.plugin == "windows.pstree"
    assert result.rows == ()
    assert result.used_fallback is True
    assert result.fallback_plugin == "windows.psscan"
    assert result.fallback_rows is not None
    names = {row["ImageFileName"] for row in result.fallback_rows}
    assert "explorer.exe" in names
    assert "services.exe" in names
