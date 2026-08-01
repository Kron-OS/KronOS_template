#!/usr/bin/env python3
"""KronOS Volatility3 worker: run a real volatility3 plugin against a memory
image and emit one JSON result document to stdout.

Invoked by VolatilityLauncher (src/external/sandbox/volatility_launcher.py);
the launcher feeds an evidence-file path + plugin name(s) + a per-run timeout
via CLI args, and reads exactly one JSON object back from stdout -- the same
"small standalone script, JSON in/out, everything else on stderr" shape as
docker/plaso/kronos-plaso-worker.py and docker/yara/kronos-yarax-worker.py.

Uses volatility3's own *stable public CLI* (the ``vol`` console script,
pinned ``volatility3==2.28.0`` -- see poc/volatility_memory_module/README.md
for the real, captured verification run), not volatility3's internal Python
framework API: the CLI + its ``-r json`` renderer is the documented, stable
contract (mirrors kronos-plaso-worker.py's identical reasoning for using
log2timeline/psort rather than Plaso's internal classes). Runs inside this
subprocess, never inside the caller's (API/Celery worker) process --
CLAUDE.md §G.3.

**Real, reproduced finding this worker's fallback exists for** (verified
against the real, classic `cridex.vmem` Windows XP sample -- see
poc/volatility_memory_module/README.md): ``windows.pstree``/``windows.pslist``
walk the kernel's ``PsActiveProcessHead`` doubly-linked list, and for this
specific real sample + volatility3==2.28.0 combination that walk yields
*zero* processes -- a real, exit-0, no-exception, empty JSON ``[]`` result,
not a wrapper bug (independently confirmed: correct DTB/kernel-virtual-offset
detected via ``windows.info``, no exceptions in ``-vvv`` output, ``--pid``
filtered by a PID confirmed present via the scanner still returns nothing).
``windows.psscan`` (an independent pool-tag scanner, not a linked-list walk)
recovers the real, full, well-documented process census from the exact same
file. Never silently drop recoverable data when the primary (linked-list)
technique and a real alternative (pool-scan) technique disagree: if the
primary plugin's own JSON result is an empty list, this worker automatically
also runs ``--fallback-plugin`` (default ``windows.psscan``) against the same
evidence file and reports both results in one JSON document.

Usage:
    python kronos-volatility-worker.py \
        --evidence-path /mnt/evidence/sample.vmem \
        --plugin windows.pstree \
        --fallback-plugin windows.psscan \
        --timeout-seconds 300
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("kronos-volatility-worker")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KronOS volatility3 sandboxed plugin runner")
    p.add_argument("--evidence-path", required=True)
    p.add_argument("--plugin", default="windows.pstree")
    p.add_argument(
        "--fallback-plugin",
        default="windows.psscan",
        help="Run this plugin too if --plugin's own JSON result is empty. Pass '' to disable.",
    )
    p.add_argument("--timeout-seconds", type=int, default=300)
    return p.parse_args()


def _emit(result: dict) -> None:
    """Write the single JSON result document to stdout."""
    print(json.dumps(result, default=str), flush=True)


def _run_plugin(
    vol_bin: str, evidence_path: str, plugin: str, timeout_seconds: int
) -> tuple[int, list, str]:
    """Run one volatility3 plugin via the real ``vol`` CLI with ``-r json``.

    Returns ``(returncode, rows, stderr)``. ``rows`` is ``[]`` whenever the
    process didn't exit 0 or its stdout wasn't a JSON list -- callers decide
    what that means (a genuine zero-result plugin run vs. a real failure is
    disambiguated by ``returncode``, not by this helper). Lets
    ``subprocess.TimeoutExpired`` propagate to the caller.
    """
    cmd = [vol_bin, "-q", "-r", "json", "-f", evidence_path, plugin]
    logger.info("Running volatility3 plugin: %s", " ".join(cmd))
    completed = subprocess.run(  # noqa: S603  # argv list, shell=False, vol_bin from shutil.which
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    rows: list = []
    if completed.returncode == 0 and completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError:
            logger.warning("volatility3 plugin %s produced non-JSON stdout", plugin)
        else:
            if isinstance(parsed, list):
                rows = parsed
            else:
                logger.warning(
                    "volatility3 plugin %s's JSON output was not a list (got %s)",
                    plugin,
                    type(parsed).__name__,
                )
    return completed.returncode, rows, completed.stderr


def main() -> None:
    args = _parse_args()
    logger.info(
        "Starting volatility3 run: evidence=%s plugin=%s fallback=%s",
        args.evidence_path,
        args.plugin,
        args.fallback_plugin or "(disabled)",
    )

    vol_bin = shutil.which("vol")
    if vol_bin is None:
        # This worker's own runtime is missing the real dependency -- an
        # infrastructure problem (mirrors kronos-yarax-worker.py's identical
        # "yara_x not installed" scan_error path), never a plugin-specific
        # failure.
        logger.error("volatility3 'vol' CLI not found on PATH in this worker's runtime")
        _emit(
            {
                "status": "scan_error",
                "error": "volatility3 'vol' CLI not found in worker runtime",
                "plugin": args.plugin,
                "rows": [],
                "fallback_plugin": None,
                "fallback_rows": None,
            }
        )
        sys.exit(0)

    try:
        returncode, rows, stderr = _run_plugin(
            vol_bin, args.evidence_path, args.plugin, args.timeout_seconds
        )
    except subprocess.TimeoutExpired:
        logger.error(
            "volatility3 plugin %s exceeded its %ss in-worker timeout",
            args.plugin,
            args.timeout_seconds,
        )
        _emit(
            {
                "status": "timeout",
                "error": f"{args.plugin} exceeded {args.timeout_seconds}s",
                "plugin": args.plugin,
                "rows": [],
                "fallback_plugin": None,
                "fallback_rows": None,
            }
        )
        sys.exit(0)

    if stderr.strip():
        # Logged on every run, success or failure -- same Track B1 reasoning
        # FirecrackerLauncher/kronos-yarax-worker.py already established: a
        # clean exit can still carry a meaningful diagnostic (e.g. volatility3's
        # own "No metadata file found alongside VMEM file" warning).
        logger.info("volatility3 stderr (plugin=%s): %s", args.plugin, stderr[:2000])

    if returncode != 0:
        logger.error("volatility3 plugin %s exited %d", args.plugin, returncode)
        _emit(
            {
                "status": "scan_error",
                "error": f"{args.plugin} exited {returncode}: {stderr[:500]}",
                "plugin": args.plugin,
                "rows": [],
                "fallback_plugin": None,
                "fallback_rows": None,
            }
        )
        sys.exit(0)

    fallback_plugin: str | None = None
    fallback_rows: list | None = None
    if not rows and args.fallback_plugin:
        logger.info(
            "Primary plugin %s returned 0 rows; trying fallback %s",
            args.plugin,
            args.fallback_plugin,
        )
        try:
            fb_returncode, fb_rows, fb_stderr = _run_plugin(
                vol_bin, args.evidence_path, args.fallback_plugin, args.timeout_seconds
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "Fallback plugin %s timed out; reporting primary result only", args.fallback_plugin
            )
        else:
            if fb_stderr.strip():
                logger.info(
                    "volatility3 stderr (plugin=%s): %s", args.fallback_plugin, fb_stderr[:2000]
                )
            if fb_returncode == 0:
                fallback_plugin = args.fallback_plugin
                fallback_rows = fb_rows
            else:
                logger.warning(
                    "Fallback plugin %s exited %d; reporting primary result only",
                    args.fallback_plugin,
                    fb_returncode,
                )

    logger.info(
        "volatility3 run complete: plugin=%s rows=%d fallback_plugin=%s fallback_rows=%s",
        args.plugin,
        len(rows),
        fallback_plugin,
        len(fallback_rows) if fallback_rows is not None else "n/a",
    )
    _emit(
        {
            "status": "ok",
            "error": None,
            "plugin": args.plugin,
            "rows": rows,
            "fallback_plugin": fallback_plugin,
            "fallback_rows": fallback_rows,
        }
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
