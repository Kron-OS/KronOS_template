"""YaraXSandboxRunner: subprocess-isolated YARA-X rule compilation + scanning.

**Why this exists (CLAUDE.md §G.3, roadmap E2).** libyara/`yara-python`
compiles untrusted rule text *in-process*, and libyara has a real
memory-safety CVE history -- doing that inside an API/Celery worker process
is one bug away from RCE. YARA-X (the `yara_x` PyPI package, a real Rust
extension, pinned ``yara-x==1.19.0`` in ``pyproject.toml``) is memory-safe
Rust, which removes the memory-corruption class of bug -- but rule
compilation is still, by design, arbitrary attacker-influenced input driving
a real compiler, so this class still never imports/calls `yara_x` in the
caller's process. It launches a small worker script
(``docker/yara/kronos-yarax-worker.py``) as a subprocess and reads back a
single JSON result document from stdout, exactly mirroring
``FirecrackerLauncher``'s architecture for Plaso: real files on disk cross
the process boundary (a CLI arg per path, not stdin -- avoids any pipe/argv
size surprises for a large target blob or a long rule file), the worker's
*only* stdout output is that one JSON object, and every diagnostic the
worker produces lands on stderr and is logged either way (success or
failure), mirroring the Track B1 fix already applied to
``FirecrackerLauncher``.

**Honest risk-model note** (do not oversell this): this buys *subprocess*
isolation -- a compromised/misbehaving worker process is not a compromised
API/Celery process, and rule compilation crashing the worker just ends that
one subprocess. It is *not* a Firecracker microVM or gVisor sandbox; like
``FirecrackerLauncher`` itself (see its own docstring), "sandboxed at the
container level" today means the existing Chainguard/Wolfi container the
API/Celery process already runs in, not a fresh container/microVM per scan
call. That is the same, real level of isolation this codebase's Plaso path
already provides -- this class does not claim more than that.

**Deliberately a separate class, not a `FirecrackerLauncher` subclass.**
The two have structurally different output shapes -- a `TimelineRecord`
stream vs. a bounded set of rule matches carrying matched-string byte
offsets -- and `FirecrackerLauncher`'s constructor/interface is tightly
coupled to Plaso specifics (``parser_name``/``parser_version`` defaults,
dfVFS ``display_name`` prefix parsing) that a YARA-X scan has no analogue
for. Same subprocess/JSON-io/timeout *pattern*, deliberately not the same
class -- mirrors this codebase's own ``TarArchiveParser``/``ZipArchiveParser``
precedent (roadmap E1): two classes sharing one architecture, not one class
forced to serve two shapes.

**Scope note.** This class only runs a scan and returns matches; it does
NOT wire into the parser recursion path or emit ``StructuredArtifact`` --
that is roadmap E3, a separate, not-yet-started item that depends on this
one. ``YaraRuleMatch``/``YaraStringMatch`` below are deliberately plain,
framework-free dataclasses (not ``StructuredArtifact``) so E3 can decide
how to shape ``content`` without this class needing to change.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.exceptions import YaraRuleCompilationError, YaraScanError

logger = logging.getLogger(__name__)

_YARAX_WORKER_PATH = (
    Path(__file__).parent.parent.parent.parent / "docker" / "yara" / "kronos-yarax-worker.py"
)

# Wall-clock ceiling for the *subprocess itself*, layered above the in-worker
# yara_x.Scanner.set_timeout() the worker script applies. Two independent
# timeouts, same reasoning as kronos-plaso-worker.py's _L2T_TIMEOUT/
# _PSORT_TIMEOUT vs. the Celery task's own time_limit: if the in-worker
# timeout somehow fails to fire (e.g. the interpreter itself wedges), this
# outer one still guarantees the caller gets control back.
_SUBPROCESS_TIMEOUT_MARGIN_SECONDS = 10


@dataclass(frozen=True)
class YaraStringMatch:
    """One real occurrence of one rule pattern inside the scanned target.

    ``offset``/``length`` are real byte positions in the scanned blob --
    this is the data roadmap E3 needs to report "rule X matched at byte N
    inside file Y," an independently verifiable, admissible statement per
    E3's own objective.
    """

    pattern_identifier: str
    offset: int
    length: int
    xor_key: int | None = None


@dataclass(frozen=True)
class YaraRuleMatch:
    """One YARA-X rule that matched, with every real occurrence of its patterns."""

    identifier: str
    namespace: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    matched_strings: tuple[YaraStringMatch, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class YaraScanResult:
    """The full, real output of one sandboxed YARA-X scan (possibly zero matches)."""

    matched_rules: tuple[YaraRuleMatch, ...] = field(default_factory=tuple)

    @property
    def matched(self) -> bool:
        """True if at least one rule matched -- a zero-match scan is not an error."""
        return len(self.matched_rules) > 0


class YaraXSandboxRunner:
    """Compile YARA-X rule text and scan a byte blob in a sandboxed subprocess.

    Never compiles or scans caller-supplied rule text/bytes in this (the
    caller's) process -- see this module's docstring and CLAUDE.md §G.3.
    """

    def __init__(
        self,
        worker_path: Path | None = None,
        python_bin: str = sys.executable,
        timeout_seconds: int = 30,
    ) -> None:
        self._worker_path = worker_path or _YARAX_WORKER_PATH
        self._python_bin = python_bin
        self._timeout = timeout_seconds

    async def run(self, rule_source: str, target: bytes) -> YaraScanResult:
        """Compile ``rule_source`` and scan ``target`` bytes; return real matches.

        Runs the blocking subprocess call in a worker thread
        (``asyncio.to_thread``) so this never blocks the caller's event loop
        -- CLAUDE.md §A.5.

        Raises:
            YaraRuleCompilationError: ``rule_source`` is not valid YARA-X
                syntax (a rule-author error; retrying without changing the
                rule will not help).
            YaraScanError: the sandbox subprocess failed to launch, exited
                non-zero, produced unparseable output, or the scan itself
                timed out or errored inside the worker.
        """
        return await asyncio.to_thread(self._run_sync, rule_source, target)

    def _run_sync(self, rule_source: str, target: bytes) -> YaraScanResult:
        rule_path, target_path = self._write_temp_inputs(rule_source, target)
        try:
            return self._run_worker(rule_path, target_path)
        finally:
            for path in (rule_path, target_path):
                Path(path).unlink(missing_ok=True)

    @staticmethod
    def _write_temp_inputs(rule_source: str, target: bytes) -> tuple[str, str]:
        """Materialize rule source + target bytes as real files on disk.

        Real files (not stdin) cross the subprocess boundary -- avoids pipe
        backpressure/argv-length limits for a large target blob or a long
        rule file, same reasoning kronos-plaso-worker.py's evidence_path arg
        already establishes for the Plaso path.
        """
        rule_fd = tempfile.NamedTemporaryFile(  # noqa: SIM115
            mode="w", suffix=".yar", encoding="utf-8", delete=False
        )
        try:
            rule_fd.write(rule_source)
        finally:
            rule_fd.close()

        target_fd = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)  # noqa: SIM115
        try:
            target_fd.write(target)
        finally:
            target_fd.close()

        return rule_fd.name, target_fd.name

    def _run_worker(self, rule_path: str, target_path: str) -> YaraScanResult:
        cmd = [
            self._python_bin,
            str(self._worker_path),
            "--rule-file",
            rule_path,
            "--target-file",
            target_path,
            "--timeout-seconds",
            str(self._timeout),
        ]

        logger.info("yarax_launch", extra={"worker": str(self._worker_path)})

        try:
            completed = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout + _SUBPROCESS_TIMEOUT_MARGIN_SECONDS,
                check=False,
            )
        except FileNotFoundError as exc:
            logger.error("yarax_worker_not_found", extra={"path": str(self._worker_path)})
            raise YaraScanError(
                f"YARA-X worker not found: {self._worker_path}",
                context={"path": str(self._worker_path)},
            ) from exc
        except subprocess.TimeoutExpired as exc:
            logger.error("yarax_worker_wallclock_timeout", extra={"timeout": self._timeout})
            raise YaraScanError(
                "YARA-X worker exceeded its outer wall-clock timeout",
                context={"timeout_seconds": self._timeout},
            ) from exc

        if completed.stderr and completed.stderr.strip():
            # Logged on every run, success or failure -- Track B1's own fix
            # to FirecrackerLauncher applies identically here: a clean exit
            # can still carry a meaningful diagnostic (e.g. "yara_x not
            # installed in worker runtime").
            logger.info("yarax_worker_stderr", extra={"stderr": completed.stderr[:2000]})

        if completed.returncode != 0:
            logger.error(
                "yarax_worker_failed",
                extra={"returncode": completed.returncode, "stderr": completed.stderr[:500]},
            )
            raise YaraScanError(
                f"YARA-X worker exited with code {completed.returncode}: "
                f"{completed.stderr[:200]}",
                context={"returncode": completed.returncode},
            )

        stdout = completed.stdout.strip()
        if not stdout:
            raise YaraScanError("YARA-X worker produced no output on stdout")

        try:
            payload = json.loads(stdout.splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise YaraScanError(
                f"YARA-X worker produced unparseable output: {stdout[:200]}"
            ) from exc

        return self._payload_to_result(payload)

    @staticmethod
    def _payload_to_result(payload: dict[str, Any]) -> YaraScanResult:
        status = payload.get("status")
        if status == "compile_error":
            raise YaraRuleCompilationError(
                payload.get("error") or "YARA-X rule compilation failed",
                context={"rule_error": payload.get("error")},
            )
        if status in ("scan_error", "timeout"):
            raise YaraScanError(
                payload.get("error") or f"YARA-X worker reported status={status}",
                context={"status": status},
            )
        if status != "ok":
            raise YaraScanError(f"YARA-X worker returned an unrecognized status: {status!r}")

        matched_rules = tuple(
            YaraRuleMatch(
                identifier=rule["identifier"],
                namespace=rule["namespace"],
                tags=tuple(rule.get("tags", [])),
                matched_strings=tuple(
                    YaraStringMatch(
                        pattern_identifier=s["pattern_identifier"],
                        offset=s["offset"],
                        length=s["length"],
                        xor_key=s.get("xor_key"),
                    )
                    for s in rule.get("matched_strings", [])
                ),
            )
            for rule in payload.get("matched_rules", [])
        )

        logger.info("yarax_scan_complete", extra={"matched_rules": len(matched_rules)})
        return YaraScanResult(matched_rules=matched_rules)
