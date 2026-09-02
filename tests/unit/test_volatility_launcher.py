"""Unit tests for VolatilityLauncher's subprocess/JSON-io contract.

Mirrors test_yara_x_runner.py's own idiom (CLAUDE.md §B.5: mock only the
external dependency -- here, the worker subprocess -- never the domain
objects): most tests swap in a small fake worker script that emits a
hand-crafted JSON payload, so the launcher's own parsing/error-mapping logic
is exercised against a real subprocess boundary without needing volatility3
installed. `test_real_worker_*` additionally drives the *real*
docker/volatility/kronos-volatility-worker.py script with the real, pinned
`volatility3==2.28.0` package against the real, classic `cridex.vmem` sample
-- see poc/volatility_multiplugin/README.md (Milestone CCCCC) for the
from-first-principles verification of the multi-plugin shared-context
architecture this launcher now drives. Those tests are gated on both the
real worker script existing (always true in this repo), a real downloaded
sample being present locally (never committed), and a real volatility3
install on the interpreter the test itself runs the worker with -- mirrors
this repo's existing `pytest.importorskip("evtx")` pattern for an optional
real-artifact/real-dependency combination.

Milestone CCCCC: rewritten for the multi-plugin result shape
(`VolatilityMultiPluginResult`/`VolatilityPluginOutcome` replace the old
single-plugin `VolatilityPluginResult` with its primary/fallback pair).
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

# Never committed (real cridex.vmem is ~512 MiB uncompressed -- see
# poc/volatility_multiplugin/README.md for why) -- set this to a local
# scratch path to exercise the real-sample test below; skipped, not failed,
# when unset/missing. KRONOS_VOLATILITY_PYTHON_BIN must point at an
# interpreter with volatility3==2.28.0 actually installed (this repo's own
# pytest venv deliberately does not carry it -- the real worker's runtime is
# the celery-worker-plaso container image, docker/Dockerfile.plaso-worker,
# not this test process).
_REAL_SAMPLE_PATH = os.environ.get("KRONOS_CRIDEX_VMEM_PATH", "")
_REAL_VOL_AVAILABLE = bool(_REAL_SAMPLE_PATH) and Path(_REAL_SAMPLE_PATH).exists()
_REAL_VOL_PYTHON_BIN = os.environ.get("KRONOS_VOLATILITY_PYTHON_BIN", "")


def _write_worker(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake_volatility_worker.py"
    script.write_text(textwrap.dedent(body))
    return script


async def test_run_returns_rows_from_ok_payload(tmp_path: Path) -> None:
    payload = {
        "status": "ok",
        "error": None,
        "plugins": {
            "windows.pstree.PsTree": {
                "status": "ok",
                "rows": [{"PID": 4, "PPID": 0, "ImageFileName": "System"}],
                "error": None,
            }
        },
    }
    script = _write_worker(
        tmp_path,
        f"""
        import json
        print(json.dumps({payload!r}))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    result = await launcher.run("/tmp/fake.vmem", plugins=["windows.pstree.PsTree"])

    outcome = result.for_plugin("windows.pstree.PsTree")
    assert outcome is not None
    assert outcome.ok is True
    assert len(outcome.rows) == 1
    assert outcome.rows[0]["PID"] == 4


async def test_run_returns_independent_outcome_per_plugin(tmp_path: Path) -> None:
    """A mixed run (some plugins ok, one genuinely failed) must not raise --
    each plugin's own outcome carries its own status, per this module's own
    "one bad thing doesn't sink the evidence" generalization from the old
    primary/fallback pair to N plugins."""
    payload = {
        "status": "ok",
        "error": None,
        "plugins": {
            "windows.pstree.PsTree": {"status": "ok", "rows": [{"PID": 4}], "error": None},
            "windows.psscan.PsScan": {
                "status": "ok",
                "rows": [{"PID": 908, "ImageFileName": "svchost.exe"}],
                "error": None,
            },
            "windows.malware.malfind.Malfind": {
                "status": "scan_error",
                "rows": [],
                "error": "Unsatisfied requirement plugins.Malfind.kernel.layer_name",
            },
        },
    }
    script = _write_worker(
        tmp_path,
        f"""
        import json
        print(json.dumps({payload!r}))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    result = await launcher.run(
        "/tmp/fake.vmem",
        plugins=[
            "windows.pstree.PsTree",
            "windows.psscan.PsScan",
            "windows.malware.malfind.Malfind",
        ],
    )

    pstree = result.for_plugin("windows.pstree.PsTree")
    psscan = result.for_plugin("windows.psscan.PsScan")
    malfind = result.for_plugin("windows.malware.malfind.Malfind")
    assert pstree is not None and pstree.ok
    assert psscan is not None and psscan.ok
    assert psscan.rows[0]["ImageFileName"] == "svchost.exe"
    assert malfind is not None and not malfind.ok
    assert malfind.status == "scan_error"
    assert "Unsatisfied requirement" in (malfind.error or "")


async def test_run_raises_when_every_plugin_fails(tmp_path: Path) -> None:
    """Real, reproduced case: automagic construction itself fails for a
    genuinely unsupported image (the ch2.dmp finding) -- every plugin
    sharing that context fails identically. This IS a whole-run failure,
    not a partial result the caller could build artifacts from."""
    payload = {
        "status": "scan_error",
        "error": "no plugin produced a usable result",
        "plugins": {
            "windows.pstree.PsTree": {
                "status": "scan_error",
                "rows": [],
                "error": "Unsatisfied requirement plugins.PsTree.kernel.layer_name",
            },
            "windows.psscan.PsScan": {
                "status": "scan_error",
                "rows": [],
                "error": "Unsatisfied requirement plugins.PsScan.kernel.layer_name",
            },
        },
    }
    script = _write_worker(
        tmp_path,
        f"""
        import json
        print(json.dumps({payload!r}))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(VolatilityScanError, match="no plugin produced a usable result"):
        await launcher.run(
            "/tmp/fake.vmem", plugins=["windows.pstree.PsTree", "windows.psscan.PsScan"]
        )


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


async def test_run_raises_on_unrecognized_shape(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({"status": "something_else", "plugin": "x", "rows": []}))
        """,
    )
    launcher = VolatilityLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(VolatilityScanError, match="unrecognized shape"):
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
            "status": "ok", "error": None,
            "plugins": {"windows.pstree.PsTree": {"status": "ok", "rows": [], "error": None}},
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
    not (_REAL_VOL_AVAILABLE and _REAL_VOL_PYTHON_BIN),
    reason="KRONOS_CRIDEX_VMEM_PATH/KRONOS_VOLATILITY_PYTHON_BIN not set; "
    "see poc/volatility_multiplugin/",
)
async def test_real_worker_runs_full_plugin_set_on_real_cridex_sample() -> None:
    """End-to-end against the real, classic cridex.vmem sample, real
    volatility3==2.28.0, the real (rewritten) multi-plugin worker script.

    Real, reproduced finding (poc/volatility_multiplugin/output.txt):
    windows.pstree's own linked-list walk returns zero rows for this real
    sample + volatility3==2.28.0, while windows.psscan (same real file,
    same shared automagic context) recovers the real, well-documented
    process census. The five newer plugins also legitimately return zero
    rows for this specific XP-era sample (a real, already-documented
    per-process-introspection limitation for cridex.vmem, not a bug).
    """
    launcher = VolatilityLauncher(
        worker_path=_REAL_WORKER_PATH, python_bin=_REAL_VOL_PYTHON_BIN, timeout_seconds=120
    )

    result = await launcher.run(_REAL_SAMPLE_PATH)

    pstree = result.for_plugin("windows.pstree.PsTree")
    psscan = result.for_plugin("windows.psscan.PsScan")
    assert pstree is not None and pstree.ok and pstree.rows == ()
    assert psscan is not None and psscan.ok
    names = {row["ImageFileName"] for row in psscan.rows}
    assert "explorer.exe" in names
    assert "services.exe" in names
