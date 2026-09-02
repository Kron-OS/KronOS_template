"""VolatilityLauncher: subprocess-isolated multi-plugin volatility3 execution.

**Why this exists (CLAUDE.md §G.3, roadmap E5).** ``volatility3`` is a real,
independently-versioned external tool (pinned ``volatility3==2.28.0``, see
``poc/volatility_memory_module/README.md`` for the real, captured
verification run) with its own dependency surface and its own CLI. Per
CLAUDE.md's own worked example -- "first-party module wrapping a real
external tool (volatility3, ...) -> subprocess, sandboxed at the container
level" -- this never imports ``volatility3`` directly into the caller's
(API/Celery worker) process. It launches a small worker script
(``docker/volatility/kronos-volatility-worker.py``) as a subprocess and
reads back a single JSON result document from stdout, exactly mirroring
``FirecrackerLauncher`` (Plaso) and ``YaraXSandboxRunner`` (YARA-X): a real
file on disk crosses the process boundary (a CLI arg, not stdin -- avoids
any pipe/argv size surprise for a 512 MiB+ memory image), the worker's only
stdout output is that one JSON object, and every diagnostic the worker
produces lands on stderr and is logged either way (success or failure) --
Track B1's fix to ``FirecrackerLauncher`` applied identically here.

**Honest risk-model note** (do not oversell this, mirrors
``YaraXSandboxRunner``'s own identical disclaimer): this buys *subprocess*
isolation only -- the same, real level of isolation this codebase's Plaso
and YARA-X paths already provide, not a Firecracker microVM or gVisor
sandbox of its own.

**Milestone CCCCC rewrite: one call now runs several plugins, not one.**
Real-verified (``poc/volatility_multiplugin/``): the worker script shares a
single resolved automagic context across every requested plugin, so running
N plugins costs roughly "one full automagic resolution + N cheap
constructions," not N full resolutions. ``run()`` now takes a plugin
*sequence* and returns a ``VolatilityMultiPluginResult`` carrying one
``VolatilityPluginOutcome`` per requested plugin -- **a single plugin's own
failure is reported in its own outcome, not raised** (generalizes the old
primary/fallback pair's "one bad thing doesn't sink the evidence" precedent
to N plugins). ``VolatilityScanError`` is only raised when the worker run
fails *outright* (couldn't even launch, produced no parseable output, or
every single requested plugin failed) -- see ``_payload_to_result``.

**``pstree``/``psscan`` no longer need special fallback handling at this
layer.** Both are simply two of the caller's requested plugins now and both
run unconditionally (cheap, shared-context reuse) -- see the worker script's
own docstring for the full account of the two real findings
(``cridex.vmem``'s empty pstree; ``ch2.dmp``'s automagic-construction
failure) that originally motivated a conditional fallback, and why running
both unconditionally still handles both correctly.

**Deliberately not a ``FirecrackerLauncher`` subclass**, for the same reason
``YaraXSandboxRunner`` isn't one: structurally different output shape (a
dict of plugin-rendered rows, not a ``TimelineRecord`` stream) and
``FirecrackerLauncher``'s constructor is tightly coupled to Plaso specifics
this class has no analogue for. Same subprocess/JSON-io/timeout *pattern*,
deliberately a separate class -- mirrors the ``TarArchiveParser``/
``ZipArchiveParser`` precedent this codebase already established.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.exceptions import VolatilityScanError

logger = logging.getLogger(__name__)

_VOLATILITY_WORKER_PATH = (
    Path(__file__).parent.parent.parent.parent
    / "docker"
    / "volatility"
    / "kronos-volatility-worker.py"
)

# Wall-clock ceiling for the subprocess itself, layered above the worker's
# own --timeout-seconds -- same two-independent-timeouts reasoning as
# FirecrackerLauncher/YaraXSandboxRunner: if the in-worker budget guard
# somehow fails to fire, this outer one still guarantees the caller gets
# control back. Widened from the single-plugin era's 30s: the worker now
# runs up to 7 plugins sequentially in one process (malfind/filescan alone
# measured 24s/11s render time each on a modest 1.6GB real image, per
# poc/volatility_multiplugin/output.txt) before this margin even starts
# counting.
_SUBPROCESS_TIMEOUT_MARGIN_SECONDS = 60

# Real eager plugin set (Milestone CCCCC) -- must match
# kronos-volatility-worker.py's own _DEFAULT_PLUGINS exactly (kept here too,
# not imported from the worker script, since the worker runs in a different
# container image with a different Python environment -- see
# VolatilityModule's own docstring for the same "mirror, don't import
# across the sandbox boundary" reasoning already established for the
# fallback-plugin constant).
DEFAULT_PLUGINS: tuple[str, ...] = (
    "windows.pstree.PsTree",
    "windows.psscan.PsScan",
    "windows.dlllist.DllList",
    "windows.cmdline.CmdLine",
    "windows.malware.malfind.Malfind",
    "windows.filescan.FileScan",
    "windows.registry.hivelist.HiveList",
)

# Doubled from the single-plugin era's 300s: 7 plugins now run sequentially
# in one process instead of 1-2 `vol` subprocess invocations. Real-measured
# combined cost on a 1.6GB image was ~40s (poc/volatility_multiplugin/); a
# larger real-world image (multi-GB, common in practice) will take
# proportionally longer for the pool-scanning plugins (malfind/filescan) in
# particular, so this is real headroom, not an arbitrary bump.
_DEFAULT_TIMEOUT_SECONDS = 600


@dataclass(frozen=True)
class VolatilityPluginOutcome:
    """The real, per-plugin outcome of one requested plugin within a
    ``VolatilityMultiPluginResult`` -- never raised on its own; a single
    plugin's failure is reported here, not sunk into the whole run."""

    plugin: str
    status: str
    rows: tuple[dict[str, Any], ...]
    error: str | None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass(frozen=True)
class VolatilityMultiPluginResult:
    """The full, real output of one sandboxed multi-plugin volatility3 run."""

    outcomes: tuple[VolatilityPluginOutcome, ...]

    def for_plugin(self, plugin: str) -> VolatilityPluginOutcome | None:
        for outcome in self.outcomes:
            if outcome.plugin == plugin:
                return outcome
        return None


class VolatilityLauncher:
    """Run several real volatility3 plugins (sharing one resolved automagic
    context) against a real memory image in a sandboxed subprocess.

    Never imports/calls ``volatility3`` in this (the caller's) process --
    see this module's own docstring and CLAUDE.md §G.3.
    """

    def __init__(
        self,
        worker_path: Path | None = None,
        python_bin: str = sys.executable,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._worker_path = worker_path or _VOLATILITY_WORKER_PATH
        self._python_bin = python_bin
        self._timeout = timeout_seconds

    async def run(
        self,
        evidence_path: str,
        plugins: Sequence[str] = DEFAULT_PLUGINS,
    ) -> VolatilityMultiPluginResult:
        """Run *plugins* against *evidence_path*; return the real result.

        Runs the blocking subprocess call in a worker thread
        (``asyncio.to_thread``) so this never blocks the caller's event loop
        -- CLAUDE.md §A.5.

        Raises:
            VolatilityScanError: the sandbox subprocess failed to launch,
                exited non-zero, produced unparseable output, or every
                single requested plugin failed inside the worker (an
                individual plugin's own failure among a mixed-success run
                is reported in its ``VolatilityPluginOutcome`` instead).
        """
        return await asyncio.to_thread(self._run_sync, evidence_path, plugins)

    def _run_sync(self, evidence_path: str, plugins: Sequence[str]) -> VolatilityMultiPluginResult:
        cmd = [
            self._python_bin,
            str(self._worker_path),
            "--evidence-path",
            evidence_path,
            "--plugins",
            ",".join(plugins),
            "--timeout-seconds",
            str(self._timeout),
        ]

        logger.info(
            "volatility_launch", extra={"worker": str(self._worker_path), "plugins": list(plugins)}
        )

        try:
            completed = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout + _SUBPROCESS_TIMEOUT_MARGIN_SECONDS,
                check=False,
            )
        except FileNotFoundError as exc:
            logger.error("volatility_worker_not_found", extra={"path": str(self._worker_path)})
            raise VolatilityScanError(
                f"Volatility worker not found: {self._worker_path}",
                context={"path": str(self._worker_path)},
            ) from exc
        except subprocess.TimeoutExpired as exc:
            logger.error("volatility_worker_wallclock_timeout", extra={"timeout": self._timeout})
            raise VolatilityScanError(
                "Volatility worker exceeded its outer wall-clock timeout",
                context={"timeout_seconds": self._timeout},
            ) from exc

        if completed.stderr and completed.stderr.strip():
            # Logged on every run, success or failure -- same Track B1 fix
            # FirecrackerLauncher/YaraXSandboxRunner already apply.
            logger.info("volatility_worker_stderr", extra={"stderr": completed.stderr[:2000]})

        if completed.returncode != 0:
            logger.error(
                "volatility_worker_failed",
                extra={"returncode": completed.returncode, "stderr": completed.stderr[:500]},
            )
            raise VolatilityScanError(
                f"Volatility worker exited with code {completed.returncode}: "
                f"{completed.stderr[:200]}",
                context={"returncode": completed.returncode},
            )

        stdout = completed.stdout.strip()
        if not stdout:
            raise VolatilityScanError("Volatility worker produced no output on stdout")

        try:
            payload = json.loads(stdout.splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise VolatilityScanError(
                f"Volatility worker produced unparseable output: {stdout[:200]}"
            ) from exc

        return self._payload_to_result(payload)

    @staticmethod
    def _payload_to_result(payload: dict[str, Any]) -> VolatilityMultiPluginResult:
        status = payload.get("status")
        plugins_payload = payload.get("plugins")
        if not isinstance(plugins_payload, dict):
            raise VolatilityScanError(
                payload.get("error")
                or f"Volatility worker returned an unrecognized shape: {payload!r}"
            )

        outcomes = tuple(
            VolatilityPluginOutcome(
                plugin=name,
                status=entry.get("status", "scan_error"),
                rows=tuple(entry.get("rows", [])),
                error=entry.get("error"),
            )
            for name, entry in plugins_payload.items()
        )

        if status == "scan_error" and not any(o.ok for o in outcomes):
            # Every requested plugin genuinely failed (or none were even
            # attempted) -- this is a real, whole-run failure, not a partial
            # result the caller could still usefully build artifacts from.
            raise VolatilityScanError(
                payload.get("error") or "Volatility worker: no plugin produced a usable result",
                context={"status": status},
            )

        logger.info(
            "volatility_run_complete",
            extra={
                "plugins": {o.plugin: {"status": o.status, "rows": len(o.rows)} for o in outcomes},
            },
        )
        return VolatilityMultiPluginResult(outcomes=outcomes)
