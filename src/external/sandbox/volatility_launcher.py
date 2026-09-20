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
import tempfile
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

# Real, curated Linux eager set (reviews/Volatility_Linux_Plugin_Research.md,
# real-sample-verified in poc/volatility_linux_module/ against a
# self-generated Ubuntu 22.04/5.15.0-191-generic LiME capture -- 8 of 9
# plugins here produced real, plausible rows; `hidden_modules` is real but
# sensitive to which tool generated the target org's ISF symbol table
# (dwarf2json vs. btf2json) and may legitimately come back as a per-run
# scan_error on some real images -- expected, not a bug, same "one bad
# plugin doesn't sink the run" precedent every other multi-plugin outcome
# here already has). Same "must match kronos-volatility-worker.py exactly"
# mirroring discipline as DEFAULT_PLUGINS above.
#
# `linux.pslist.PsList` added real-verified this session
# (poc/volatility_linux_boottime/, reviews/Volatility_Linux_Plugin_Research.md):
# unlike pstree/psscan, its "CREATION TIME" column is a real absolute
# wall-clock datetime volatility3 computes internally
# (task.get_create_time() = boottime + task_start_time) -- the real source
# ``VolatilityModule._timeline_rows()`` now dual-emits Linux
# ``TimelineRecord``s from. Same ISF-tool sensitivity as `hidden_modules`
# above, verified both ways against the identical kernel build/memory
# capture: a dwarf2json-built ISF resolves `tk_core`/`timekeeper` correctly
# (all rows got a real, monotonically-plausible CREATION TIME); the
# btf2json-built ISF this codebase's own self-generated sample uses does
# not (every row's CREATION TIME comes back null, same as pstree/psscan
# always have) -- handled honestly, not a crash: a null CREATION TIME is
# just "not a timeline-shaped row," so a btf2json-ISF org continues to get
# zero Linux TimelineRecords (no regression) while a dwarf2json-ISF org
# (most distro kernels with a debug/dbgsym package available) now gets
# real ones.
LINUX_DEFAULT_PLUGINS: tuple[str, ...] = (
    "linux.pstree.PsTree",
    "linux.psscan.PsScan",
    "linux.pslist.PsList",
    "linux.psaux.PsAux",
    "linux.bash.Bash",
    "linux.malware.malfind.Malfind",
    "linux.library_list.LibraryList",
    "linux.lsof.Lsof",
    "linux.lsmod.Lsmod",
    "linux.malware.hidden_modules.Hidden_modules",
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


@dataclass(frozen=True)
class DumpedFile:
    """One real file extracted by an on-demand windows.dumpfiles run
    (Milestone EEEEE, poc/volatility_dumpfiles/) -- ``path`` is a real
    temp-file path on THIS (launcher/caller) process's filesystem, written
    by the worker subprocess before it exited; the caller must read and
    delete it (mirrors how VolatilityModule already writes/deletes the
    evidence file itself around the launcher call)."""

    filename: str
    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class VolatilityDumpFilesResult:
    """Real result of one on-demand windows.dumpfiles extraction.

    ``output_dir`` is the real scratch directory ``dumped_files[*].path``
    live in -- the caller (VolatilityModule's on-demand extraction path)
    owns cleanup: read each file's bytes, upload to
    DerivedArtifactStorage, then ``shutil.rmtree(output_dir)``. Present
    even when ``ok`` is False/``dumped_files`` is empty, so the caller can
    always clean up the (possibly-empty) scratch directory this call
    created.
    """

    ok: bool
    error: str | None
    dumped_files: tuple[DumpedFile, ...]
    output_dir: str


@dataclass(frozen=True)
class VolatilityRegistryKeyResult:
    """Real result of one on-demand, scoped windows.registry.printkey call."""

    ok: bool
    error: str | None
    rows: tuple[dict[str, Any], ...]


# Real, top-level (not windows.*/linux.*-namespaced) plugin -- requires only
# a `primary` TranslationLayerRequirement, auto-resolved by the LayerStacker
# automagic without needing OS-specific symbol resolution, so it can run
# BEFORE deciding whether the rest of a scan should request DEFAULT_PLUGINS
# or LINUX_DEFAULT_PLUGINS. Real-verified against both families
# (poc/volatility_linux_module/): a Windows image's banner is a PDB
# reference (`ntkrnlpa.pdb|<hex-guid>|<age>`); a Linux image's banner is the
# literal `/proc/version`-style string, always starting with
# "Linux version ". No macOS eager set exists yet in this codebase, so a mac
# banner (also detectable via this same plugin) currently falls through to
# "unknown" -- see _detect_os_family_from_banners' own docstring.
_BANNER_PLUGIN = "banners.Banners"


def _detect_os_family_from_banners(rows: tuple[dict[str, Any], ...]) -> str:
    """Classify a real ``banners.Banners`` result into ``"windows"``,
    ``"linux"``, or ``"unknown"`` (no bannner found, or a family this
    codebase has no eager plugin set for yet, e.g. macOS).

    Real, verified string shapes (poc/volatility_linux_module/README.md):
    Linux banners always start with ``"Linux version "`` (the literal
    ``/proc/version`` content each kernel embeds); Windows banners are a
    ``<pdb-name>|<hex-guid>|<age>`` PDB reference with no such prefix.
    """
    for row in rows:
        banner = row.get("Banner")
        if isinstance(banner, str) and banner.startswith("Linux version "):
            return "linux"
    for row in rows:
        banner = row.get("Banner")
        if isinstance(banner, str) and banner.endswith(("|1", "|2")) and ".pdb|" in banner:
            return "windows"
    return "unknown"


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
        remote_isf_url: str | None = None,
    ) -> None:
        self._worker_path = worker_path or _VOLATILITY_WORKER_PATH
        self._python_bin = python_bin
        self._timeout = timeout_seconds
        # Real, verified fix (poc/volatility_remote_isf/): without this, the
        # worker's own volatility3.framework.constants.REMOTE_ISF_URL is
        # never set (this worker uses the framework API directly, not
        # volatility3's CLI, which is the only other thing that ever sets
        # it) -- every image whose exact kernel/PDB build has no locally
        # pre-installed ISF then fails every symbol-dependent plugin with
        # UnsatisfiedException, indistinguishable from a genuinely
        # unsupported image. Only threaded into the multi-plugin run/OS
        # detection below (_run_sync) -- the on-demand Windows dumpfiles/
        # registry-printkey paths target an already-identified kernel and
        # have no Linux equivalent today.
        self._remote_isf_url = remote_isf_url

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

    async def run_dumpfile(self, evidence_path: str, physaddr: int) -> VolatilityDumpFilesResult:
        """On-demand, single-target windows.dumpfiles extraction (Milestone
        EEEEE, real mechanism verified in poc/volatility_dumpfiles/):
        *physaddr* must be a real windows.filescan row's own ``Offset``
        (a physical address, NOT a virtual one -- the PoC's decisive
        finding). Returns real file bytes written to real temp paths on
        this process's own filesystem -- the caller (VolatilityModule's
        on-demand path) is responsible for reading and deleting them after
        uploading to DerivedArtifactStorage.
        """
        return await asyncio.to_thread(self._run_dumpfile_sync, evidence_path, physaddr)

    def _run_dumpfile_sync(self, evidence_path: str, physaddr: int) -> VolatilityDumpFilesResult:
        output_dir = tempfile.mkdtemp(prefix="kronos-volatility-dumpfiles-")
        cmd = [
            self._python_bin,
            str(self._worker_path),
            "--evidence-path",
            evidence_path,
            "--dumpfiles-physaddr",
            str(physaddr),
            "--dumpfiles-output-dir",
            output_dir,
            "--timeout-seconds",
            str(self._timeout),
        ]
        try:
            payload = self._run_worker(cmd)
        except VolatilityScanError as exc:
            return VolatilityDumpFilesResult(
                ok=False, error=str(exc), dumped_files=(), output_dir=output_dir
            )
        if payload.get("status") != "ok":
            return VolatilityDumpFilesResult(
                ok=False,
                error=payload.get("error") or "Unknown dumpfiles error",
                dumped_files=(),
                output_dir=output_dir,
            )
        dumped = tuple(
            DumpedFile(
                filename=entry["filename"],
                path=entry["path"],
                sha256=entry["sha256"],
                size_bytes=entry["size_bytes"],
            )
            for entry in payload.get("dumped_files", [])
        )
        return VolatilityDumpFilesResult(
            ok=True, error=None, dumped_files=dumped, output_dir=output_dir
        )

    async def run_registry_key(
        self, evidence_path: str, hive_offset: int, key: str | None = None
    ) -> VolatilityRegistryKeyResult:
        """On-demand, scoped windows.registry.printkey call (Milestone
        EEEEE, real mechanism verified in poc/volatility_registry_printkey/):
        *hive_offset* must be a real windows.registry.hivelist row's own
        ``Offset``. Always fresh-Context per call (worker-side) -- never
        reused across repeated calls (real, verified reason: a shared
        Context reused for a second printkey call against the same hive
        raises LayerException).
        """
        return await asyncio.to_thread(self._run_registry_key_sync, evidence_path, hive_offset, key)

    def _run_registry_key_sync(
        self, evidence_path: str, hive_offset: int, key: str | None
    ) -> VolatilityRegistryKeyResult:
        cmd = [
            self._python_bin,
            str(self._worker_path),
            "--evidence-path",
            evidence_path,
            "--registry-hive-offset",
            str(hive_offset),
            "--timeout-seconds",
            str(self._timeout),
        ]
        if key:
            cmd.extend(["--registry-key", key])
        try:
            payload = self._run_worker(cmd)
        except VolatilityScanError as exc:
            return VolatilityRegistryKeyResult(ok=False, error=str(exc), rows=())
        if payload.get("status") != "ok":
            return VolatilityRegistryKeyResult(
                ok=False, error=payload.get("error") or "Unknown registry error", rows=()
            )
        return VolatilityRegistryKeyResult(ok=True, error=None, rows=tuple(payload.get("rows", [])))

    async def detect_os_family(self, evidence_path: str) -> str:
        """Run the real, OS-agnostic ``banners.Banners`` plugin against
        *evidence_path* and classify the result into ``"windows"``,
        ``"linux"``, or ``"unknown"`` -- the real signal ``VolatilityModule``
        uses to pick ``DEFAULT_PLUGINS`` vs. ``LINUX_DEFAULT_PLUGINS`` for
        the real multi-plugin scan that follows. A separate, cheap worker
        launch (one plugin only) rather than folding into the main run: the
        plugin list to request is exactly the question this answers, so it
        must complete first. Never raises -- a worker-level failure here
        (couldn't even launch, bad output) is reported as ``"unknown"``,
        same fail-open-to-Windows-default posture as before this method
        existed, not a new failure mode for callers to handle.
        """
        return await asyncio.to_thread(self._detect_os_family_sync, evidence_path)

    def _detect_os_family_sync(self, evidence_path: str) -> str:
        try:
            result = self._run_sync(evidence_path, (_BANNER_PLUGIN,))
        except VolatilityScanError:
            return "unknown"
        outcome = result.for_plugin(_BANNER_PLUGIN)
        if outcome is None or not outcome.ok:
            return "unknown"
        return _detect_os_family_from_banners(outcome.rows)

    def _run_worker(self, cmd: list[str]) -> dict[str, Any]:
        """Shared subprocess-launch + JSON-parse logic for the two on-demand
        modes -- same real launch/timeout/stderr-logging discipline as
        ``_run_sync``, factored out since both on-demand calls need it
        without the multi-plugin-specific ``--plugins`` argument."""
        logger.info(
            "volatility_launch_on_demand", extra={"worker": str(self._worker_path), "cmd": cmd}
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
            raise VolatilityScanError(
                f"Volatility worker not found: {self._worker_path}",
                context={"path": str(self._worker_path)},
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise VolatilityScanError(
                "Volatility worker exceeded its outer wall-clock timeout",
                context={"timeout_seconds": self._timeout},
            ) from exc

        if completed.stderr and completed.stderr.strip():
            logger.info("volatility_worker_stderr", extra={"stderr": completed.stderr[:2000]})

        if completed.returncode != 0:
            raise VolatilityScanError(
                f"Volatility worker exited with code {completed.returncode}: "
                f"{completed.stderr[:200]}",
                context={"returncode": completed.returncode},
            )

        stdout = completed.stdout.strip()
        if not stdout:
            raise VolatilityScanError("Volatility worker produced no output on stdout")

        try:
            result: dict[str, Any] = json.loads(stdout.splitlines()[-1])
            return result
        except json.JSONDecodeError as exc:
            raise VolatilityScanError(
                f"Volatility worker produced unparseable output: {stdout[:200]}"
            ) from exc

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
        if self._remote_isf_url:
            cmd.extend(["--remote-isf-url", self._remote_isf_url])

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

        if status == "scan_error" and not outcomes:
            # Real, live-diagnosed bug fix (case
            # 43097ab0-aae3-4968-915b-8f0229ac3865): this used to also
            # raise whenever every *attempted* plugin failed (`not any(o.ok
            # for o in outcomes)`), discarding each plugin's own real error
            # string (e.g. volatility3's genuine "UnsatisfiedException: "/
            # "No suitable kernels found during pdbscan" when it can't
            # identify an image's kernel) and leaving VolatilityModule with
            # nothing to build a diagnostic artifact from -- the exact
            # silent-failure path CaseDetailPage.tsx's own empty-state text
            # falsely promised had an explanation in the Audit tab. Only an
            # empty ``plugins`` payload (no plugin even attempted -- a
            # worker-level failure, not a per-plugin one) is still a real
            # whole-run error with nothing informative to return instead.
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
