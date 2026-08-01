"""VolatilityLauncher: subprocess-isolated volatility3 plugin execution.

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

**Fallback behaviour is real, not a guess.** Verified against the real,
classic ``cridex.vmem`` Windows XP sample (poc/volatility_memory_module/):
``windows.pstree``/``windows.pslist`` (linked-list walk) returned a real,
reproducible zero-row result for this sample + pinned version, while
``windows.psscan`` (pool-tag scan, same real file) recovered the real,
full process census. The worker script automatically re-runs a configured
fallback plugin when the primary plugin's own JSON result is empty and
reports both -- see the worker script's own module docstring for the full
account. This class is a thin, honest pass-through of that contract; it
does not itself decide when to fall back.

**Deliberately not a ``FirecrackerLauncher`` subclass**, for the same reason
``YaraXSandboxRunner`` isn't one: structurally different output shape (a
list of plugin-rendered rows, not a ``TimelineRecord`` stream) and
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

# Wall-clock ceiling for the subprocess itself, layered above the worker's own
# --timeout-seconds passed to each `vol` invocation -- same two-independent-
# timeouts reasoning as FirecrackerLauncher/YaraXSandboxRunner: if the
# in-worker timeout somehow fails to fire, this outer one still guarantees
# the caller gets control back. The worker can run the primary AND a
# fallback plugin sequentially, so the margin is generous (a single
# `vol -f <512MB image> windows.psscan` run measured well under 5s against
# the real cridex.vmem sample -- see poc/volatility_memory_module/README.md
# -- but a larger real-world image or a heavier plugin can take much longer).
_SUBPROCESS_TIMEOUT_MARGIN_SECONDS = 30

_DEFAULT_PLUGIN = "windows.pstree"
_DEFAULT_FALLBACK_PLUGIN = "windows.psscan"
_DEFAULT_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class VolatilityPluginResult:
    """The full, real output of one sandboxed volatility3 run (possibly with a fallback)."""

    plugin: str
    rows: tuple[dict[str, Any], ...]
    fallback_plugin: str | None = None
    fallback_rows: tuple[dict[str, Any], ...] | None = None

    @property
    def used_fallback(self) -> bool:
        """True if the primary plugin came back empty and a fallback ran."""
        return self.fallback_plugin is not None


class VolatilityLauncher:
    """Run one volatility3 plugin (with an automatic empty-result fallback)
    against a real memory image in a sandboxed subprocess.

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
        plugin: str = _DEFAULT_PLUGIN,
        fallback_plugin: str | None = _DEFAULT_FALLBACK_PLUGIN,
    ) -> VolatilityPluginResult:
        """Run *plugin* against *evidence_path*; return the real result.

        Runs the blocking subprocess call in a worker thread
        (``asyncio.to_thread``) so this never blocks the caller's event loop
        -- CLAUDE.md §A.5.

        Raises:
            VolatilityScanError: the sandbox subprocess failed to launch,
                exited non-zero, produced unparseable output, or the plugin
                run itself timed out or errored inside the worker.
        """
        return await asyncio.to_thread(self._run_sync, evidence_path, plugin, fallback_plugin)

    def _run_sync(
        self, evidence_path: str, plugin: str, fallback_plugin: str | None
    ) -> VolatilityPluginResult:
        cmd = [
            self._python_bin,
            str(self._worker_path),
            "--evidence-path",
            evidence_path,
            "--plugin",
            plugin,
            "--fallback-plugin",
            fallback_plugin or "",
            "--timeout-seconds",
            str(self._timeout),
        ]

        logger.info("volatility_launch", extra={"worker": str(self._worker_path), "plugin": plugin})

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
    def _payload_to_result(payload: dict[str, Any]) -> VolatilityPluginResult:
        status = payload.get("status")
        if status in ("scan_error", "timeout"):
            raise VolatilityScanError(
                payload.get("error") or f"Volatility worker reported status={status}",
                context={"status": status},
            )
        if status != "ok":
            raise VolatilityScanError(
                f"Volatility worker returned an unrecognized status: {status!r}"
            )

        fallback_rows = payload.get("fallback_rows")
        logger.info(
            "volatility_run_complete",
            extra={
                "plugin": payload.get("plugin"),
                "rows": len(payload.get("rows", [])),
                "fallback_plugin": payload.get("fallback_plugin"),
            },
        )
        return VolatilityPluginResult(
            plugin=payload["plugin"],
            rows=tuple(payload.get("rows", [])),
            fallback_plugin=payload.get("fallback_plugin"),
            fallback_rows=tuple(fallback_rows) if fallback_rows is not None else None,
        )
