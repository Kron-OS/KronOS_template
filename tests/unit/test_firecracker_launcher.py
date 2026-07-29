"""Unit tests for FirecrackerLauncher's subprocess stdout/stderr handling."""

from __future__ import annotations

import sys
import textwrap
import uuid
from pathlib import Path

import pytest

from src.external.sandbox.firecracker import FirecrackerLauncher

pytestmark = pytest.mark.asyncio


def _write_worker(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake_worker.py"
    script.write_text(textwrap.dedent(body))
    return script


async def _collect(launcher: FirecrackerLauncher) -> list:
    records = await launcher.run(
        evidence_path="/tmp/does-not-matter",
        evidence_id=str(uuid.uuid4()),
        case_id=str(uuid.uuid4()),
        org_id=str(uuid.uuid4()),
        org_alias="acme",
        sha256="deadbeef",
    )
    return [r async for r in records]


async def test_run_yields_records_from_stdout_jsonl(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({"message": "hello", "data_type": "test"}))
        """,
    )
    launcher = FirecrackerLauncher(worker_path=script, python_bin=sys.executable)

    records = await _collect(launcher)

    assert len(records) == 1
    assert records[0].message == "hello"


async def test_maps_realistic_psort_prefetch_event(tmp_path: Path) -> None:
    """A psort json_line event (the worker's real output shape) must map onto a
    TimelineRecord: datetime -> @timestamp, message -> message, and every other
    field preserved under extra. This locks the heavy-path pre-OpenSearch
    mapping contract between kronos-plaso-worker.py and FirecrackerLauncher.
    """
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({
            "datetime": "2013-03-10T14:00:00+00:00",
            "message": "Prefetch [CMD.EXE] executed, run count 2",
            "timestamp_desc": "Last Time Executed",
            "data_type": "windows:prefetch:execution",
            "parser": "prefetch",
            "run_count": 2,
        }))
        """,
    )
    launcher = FirecrackerLauncher(worker_path=script, python_bin=sys.executable)

    records = await _collect(launcher)

    assert len(records) == 1
    rec = records[0]
    assert rec.timestamp.year == 2013 and rec.timestamp.month == 3
    assert rec.message == "Prefetch [CMD.EXE] executed, run count 2"
    # Non-time/message fields are preserved for querying.
    assert rec.extra["data_type"] == "windows:prefetch:execution"
    assert rec.extra["run_count"] == 2
    assert rec.kronos.parser == "plaso"


async def test_run_raises_on_nonzero_exit(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import sys
        sys.stderr.write("boom\\n")
        sys.exit(1)
        """,
    )
    launcher = FirecrackerLauncher(worker_path=script, python_bin=sys.executable)

    with pytest.raises(RuntimeError, match="exited with code 1"):
        await _collect(launcher)


async def test_stderr_is_logged_even_on_clean_exit(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Regression: the worker always exits 0, even when it silently falls back to
    the plaso:placeholder stub — its own diagnostic ("Plaso not installed...",
    "No events from Plaso...") lands on stderr either way. Previously
    FirecrackerLauncher only read stderr on a *non-zero* exit, so a clean-exit
    stub-fallback run left no trace anywhere of why extraction produced
    nothing (Track B1: the plaso:placeholder events were unexplainable from
    server logs alone). This must now surface on the success path too.
    """
    script = _write_worker(
        tmp_path,
        """
        import json
        import sys
        sys.stderr.write("No events from Plaso; emitting placeholder\\n")
        print(json.dumps({"message": "placeholder", "data_type": "plaso:placeholder"}))
        """,
    )
    launcher = FirecrackerLauncher(worker_path=script, python_bin=sys.executable)

    with caplog.at_level("INFO"):
        records = await _collect(launcher)

    assert len(records) == 1
    stderr_logs = [r for r in caplog.records if r.message == "firecracker_worker_stderr"]
    assert len(stderr_logs) == 1
    assert "No events from Plaso" in stderr_logs[0].stderr


async def test_missing_python_binary_raises_runtime_error(tmp_path: Path) -> None:
    script = _write_worker(tmp_path, "")
    launcher = FirecrackerLauncher(
        worker_path=script, python_bin=str(tmp_path / "no-such-interpreter")
    )

    with pytest.raises(RuntimeError, match="Plaso worker not found"):
        await launcher.run(
            evidence_path="/tmp/x",
            evidence_id=str(uuid.uuid4()),
            case_id=str(uuid.uuid4()),
            org_id=str(uuid.uuid4()),
            org_alias="acme",
            sha256="deadbeef",
        )
