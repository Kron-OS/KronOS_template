"""Unit tests for YaraXSandboxRunner's subprocess/JSON-io contract.

Mirrors test_firecracker_launcher.py's own idiom (CLAUDE.md §B.5: mock only
the external dependency -- here, the worker subprocess -- never the domain
objects): most tests swap in a small fake worker script that emits a
hand-crafted JSON payload, so the runner's own parsing/error-mapping logic is
exercised against a real subprocess boundary without needing yara_x
installed. `test_real_worker_*` additionally drives the *real*
docker/yara/kronos-yarax-worker.py script with the real, pinned
`yara_x==1.19.0` package (see poc/yarax_sandboxed_runner/ for the from-first-
principles verification of this exact API).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from src.exceptions import YaraRuleCompilationError, YaraScanError
from src.external.sandbox.yara_x_runner import YaraXSandboxRunner

pytestmark = pytest.mark.asyncio

_REAL_WORKER_PATH = (
    Path(__file__).parent.parent.parent / "docker" / "yara" / "kronos-yarax-worker.py"
)


def _write_worker(tmp_path: Path, body: str) -> Path:
    script = tmp_path / "fake_yarax_worker.py"
    script.write_text(textwrap.dedent(body))
    return script


async def test_run_returns_matched_rules_from_ok_payload(tmp_path: Path) -> None:
    payload = {
        "status": "ok",
        "error": None,
        "matched_rules": [
            {
                "identifier": "test_rule",
                "namespace": "default",
                "tags": ["malware"],
                "matched_strings": [
                    {"pattern_identifier": "$a", "offset": 4, "length": 6, "xor_key": None}
                ],
            }
        ],
    }
    script = _write_worker(
        tmp_path,
        f"""
        import json
        print(json.dumps({payload!r}))
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    result = await runner.run(
        rule_source="rule test_rule { condition: true }", target=b"xxxxfoobar"
    )

    assert result.matched is True
    assert len(result.matched_rules) == 1
    rule = result.matched_rules[0]
    assert rule.identifier == "test_rule"
    assert rule.tags == ("malware",)
    assert len(rule.matched_strings) == 1
    match = rule.matched_strings[0]
    assert match.pattern_identifier == "$a"
    assert match.offset == 4
    assert match.length == 6


async def test_run_returns_empty_result_on_no_match(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({"status": "ok", "error": None, "matched_rules": []}))
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    result = await runner.run(rule_source="rule r { condition: false }", target=b"irrelevant")

    assert result.matched is False
    assert result.matched_rules == ()


async def test_run_raises_compilation_error_on_compile_error_status(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({
            "status": "compile_error",
            "error": "error[E001]: syntax error",
            "matched_rules": [],
        }))
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    with pytest.raises(YaraRuleCompilationError, match="syntax error"):
        await runner.run(rule_source="not valid yara {{{", target=b"data")


async def test_run_raises_scan_error_on_timeout_status(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({"status": "timeout", "error": "timeout", "matched_rules": []}))
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable, timeout_seconds=1)

    with pytest.raises(YaraScanError, match="timeout"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")


async def test_run_raises_on_outer_wallclock_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner's own subprocess.run(timeout=...) is the outer kill-switch
    above the worker's in-process yara_x.Scanner.set_timeout() -- exercised
    here with a worker that simply never exits, to confirm the outer layer
    still returns control to the caller as a clean YaraScanError, not a hang.
    The module's timeout margin is patched to keep this test fast.
    """
    monkeypatch.setattr("src.external.sandbox.yara_x_runner._SUBPROCESS_TIMEOUT_MARGIN_SECONDS", 1)
    script = _write_worker(
        tmp_path,
        """
        import time
        time.sleep(30)
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable, timeout_seconds=0)

    with pytest.raises(YaraScanError, match="wall-clock timeout"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")


async def test_run_raises_on_nonzero_exit(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import sys
        sys.stderr.write("boom\\n")
        sys.exit(1)
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    with pytest.raises(YaraScanError, match="exited with code 1"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")


async def test_run_raises_on_unparseable_output(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        print("this is not json")
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    with pytest.raises(YaraScanError, match="unparseable output"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")


async def test_run_raises_on_empty_output(tmp_path: Path) -> None:
    script = _write_worker(tmp_path, "")
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    with pytest.raises(YaraScanError, match="no output"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")


async def test_missing_python_binary_raises_scan_error(tmp_path: Path) -> None:
    script = _write_worker(tmp_path, "")
    runner = YaraXSandboxRunner(
        worker_path=script, python_bin=str(tmp_path / "no-such-interpreter")
    )

    with pytest.raises(YaraScanError, match="worker not found"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")


async def test_stderr_is_logged_on_success(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        import sys
        sys.stderr.write("yara_x not installed in worker runtime: boom\\n")
        print(json.dumps({"status": "ok", "error": None, "matched_rules": []}))
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    with caplog.at_level("INFO"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")

    stderr_logs = [r for r in caplog.records if r.message == "yarax_worker_stderr"]
    assert len(stderr_logs) == 1
    assert "boom" in stderr_logs[0].stderr


async def test_run_raises_on_unrecognized_status(tmp_path: Path) -> None:
    script = _write_worker(
        tmp_path,
        """
        import json
        print(json.dumps({"status": "something_else", "matched_rules": []}))
        """,
    )
    runner = YaraXSandboxRunner(worker_path=script, python_bin=sys.executable)

    with pytest.raises(YaraScanError, match="unrecognized status"):
        await runner.run(rule_source="rule r { condition: true }", target=b"data")


# --- Real worker + real yara_x (pinned yara-x==1.19.0) ----------------------


@pytest.mark.skipif(not _REAL_WORKER_PATH.exists(), reason="real worker script missing")
async def test_real_worker_matches_known_pattern() -> None:
    runner = YaraXSandboxRunner(worker_path=_REAL_WORKER_PATH, python_bin=sys.executable)
    rule_source = 'rule find_foobar { strings: $a = "foobar" condition: $a }'
    target = b"xxxxfoobarxxxxfoobar"

    result = await runner.run(rule_source=rule_source, target=target)

    assert result.matched is True
    assert len(result.matched_rules) == 1
    rule = result.matched_rules[0]
    assert rule.identifier == "find_foobar"
    offsets = sorted(m.offset for m in rule.matched_strings)
    assert offsets == [4, 14]
    assert all(m.length == 6 for m in rule.matched_strings)


@pytest.mark.skipif(not _REAL_WORKER_PATH.exists(), reason="real worker script missing")
async def test_real_worker_reports_no_match_honestly() -> None:
    runner = YaraXSandboxRunner(worker_path=_REAL_WORKER_PATH, python_bin=sys.executable)
    rule_source = 'rule find_foobar { strings: $a = "foobar" condition: $a }'

    result = await runner.run(rule_source=rule_source, target=b"nothing interesting here")

    assert result.matched is False
    assert result.matched_rules == ()


@pytest.mark.skipif(not _REAL_WORKER_PATH.exists(), reason="real worker script missing")
async def test_real_worker_surfaces_compile_error_cleanly() -> None:
    runner = YaraXSandboxRunner(worker_path=_REAL_WORKER_PATH, python_bin=sys.executable)

    with pytest.raises(YaraRuleCompilationError):
        await runner.run(rule_source="this is not valid yara syntax {{{", target=b"data")
