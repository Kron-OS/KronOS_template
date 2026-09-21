"""VolatilityModule: real ``volatility3`` memory-forensics wrapping (§G, roadmap E5).

Wraps ``VolatilityLauncher`` (``src/external/sandbox/volatility_launcher.py``)
in the ``ForensicParser`` interface -- see that module's docstring for the
sandboxing rationale (CLAUDE.md §G.3).

**Milestone CCCCC: multi-plugin analyst coverage.** Previously this module
ran exactly two plugins (``windows.pstree`` with a conditional
``windows.psscan`` fallback). Real-verified this session
(``poc/volatility_multiplugin/``, against both the classic public
``cridex.vmem`` sample and a real 1.6 GB user-uploaded image) that
volatility3's own framework API lets one resolved automagic context serve
many plugins cheaply -- so this module now requests a fixed, real,
CERT-analyst-facing plugin set every time (``DEFAULT_PLUGINS``,
``volatility_launcher.py``): process tree/listing, loaded DLLs, command
lines, injected/suspicious memory regions (``malfind``), file objects
resident in memory, and registry hive enumeration. Each plugin's own
outcome (``VolatilityPluginOutcome``) is independent -- one plugin failing
never prevents the others from producing their own ``StructuredArtifact``s
(CLAUDE.md's "one bad thing doesn't sink the evidence" precedent, now
applied across N plugins instead of a hardcoded pair).

Deliberately still out of scope this cycle (see
``docs/GAP_AUDIT_2026-08-28_MILESTONE_CCCCC.md`` for the full reasoning):
``windows.dumpfiles`` (needs a specific PID/virtual-address target, cannot
run unconditionally -- becomes a separate, on-demand path, Milestone
EEEEE), unscoped/recursive ``windows.registry.printkey`` (measured live at
over 200s with no key filter -- a real, not guessed, reason to keep this
on-demand and scoped rather than eager), ``windows.netscan``/``timeliner``
(timeline-shaped, belongs in a future ``parse()`` dual-emit extension, not
this artifact-focused pass), and ``windows.hashdump``/``lsadump``/
``cachedump`` (confirmed live: currently fail to even import in the worker
image, missing ``pycryptodome`` -- a separate infrastructure fix).

**Dual-emit (Gap Audit Milestone AAAAA, preserved): both ``parse()`` and
``extract_artifacts()`` are real.** The structural snapshots
(``pstree``/``psscan``/etc, keyed by PID/PPID or offset, not chronology --
``reviews/DFIR_Artifact_Landscape.md`` §2) are not timeline-shaped, so they
become ``StructuredArtifact``s. But a real, individual *row* within
``pstree``/``psscan`` frequently carries its own genuine per-process
``CreateTime`` -- a real process-creation event, independently
timeline-shaped even though the plugin's output *as a whole* isn't.
Confirmed live this session that none of the five NEW plugins'
(dlllist/cmdline/malfind/filescan/hivelist) rows carry a ``CreateTime``
field at all, so the dual-emit logic itself is unchanged: it still only
looks at ``pstree``/``psscan`` rows, now selected from the multi-plugin
result rather than a primary/fallback pair (see ``_timeline_rows`` below).

**One scan, not N.** ``ParsingOrchestrationService.execute_parse()`` calls
``parse()`` then ``extract_artifacts()`` as two independent passes for
every parser that implements both (``reviews/Data_Source_Module_System.md``
§5/§9's own documented v1 tradeoff) -- a real multi-plugin volatility3 run
is comparatively expensive (~40s measured for the full 7-plugin set against
a 1.6GB real image, heavier plugins/larger images cost more), so running it
twice for the same evidence file would double a real memory-forensics job's
cost for no benefit. Both methods are always invoked back-to-back within
the same ``execute_parse()`` async call for a given evidence file, and
Celery invokes it via a fresh ``asyncio.run()`` per task
(``celery_runtime.run_evidence_coro``) -- so a plain module-level
``ContextVar``, set once inside ``parse()`` and read once inside
``extract_artifacts()``, is naturally isolated per task with zero risk of
cross-evidence leakage between concurrent Celery tasks, exactly mirroring
this codebase's own existing precedent for this identical orchestration
seam (``yara_scan_org_var``, ``src/application/yara_rules.py``).
``extract_artifacts()`` still falls back to running the scan itself if
called standalone (no cached result present) -- same "still independently
callable" contract every other ``extract_artifacts()`` override honours.

**Detection is extension-only, verified for real, not guessed.** Raw
physical memory dumps have no standard magic bytes the way EWF/ustar do.
Verified directly against the real, classic ``cridex.vmem`` sample
(poc/volatility_memory_module/README.md): its first 2 KiB carry no
Microsoft crash-dump magic (``PAGEDUMP``/``PAGEDU64``) and no LiME magic --
just raw kernel page-table bytes with no header at all. This module's
``supports()`` therefore matches purely on extension
(``.vmem``/``.mem``/``.raw``/``.dmp``/``.lime``); see
``src/application/validation.py``'s own ``_MEMORY_DUMP_EXTENSIONS`` for the
matching upload-time validator change and its identical honesty note.

**Real Linux support (TaskList #13-15, reviews/Volatility_Linux_Plugin_Research.md,
poc/volatility_linux_module/).** ``VolatilityModule()`` (no explicit
``plugins`` argument -- the real production construction,
``get_parser_registry()``) now detects the target image's real OS family
per file via ``VolatilityLauncher.detect_os_family()`` (the OS-agnostic
``banners.Banners`` plugin, real-verified against both a real Windows and
a real self-generated Linux sample) and requests ``LINUX_DEFAULT_PLUGINS``
instead of ``DEFAULT_PLUGINS`` for a Linux image. An explicit ``plugins``
argument (tests, the on-demand picker) bypasses detection entirely and is
used as given -- detection only ever fills in for "the real default,"
never overrides a caller's own explicit choice.

**Linux dual-emit (poc/volatility_linux_boottime/, real-verified both
ways).** Linux's ``pstree``/``psscan`` carry no per-row timestamp in this
volatility3 version, but ``linux.pslist.PsList``'s "CREATION TIME" column
does -- a real absolute wall-clock datetime volatility3 computes
internally (``task.get_create_time()`` = boot time + the task's
boot-relative ``start_time``), not something this module combines by
hand. Whether that column is actually populated depends on the target
image's ISF (symbol table) having been built by ``dwarf2json`` rather than
``btf2json``: ``dwarf2json``-derived ISFs correctly type the kernel's
``tk_core``/``timekeeper`` symbol, so ``linux.boottime.Boottime`` (and
therefore every ``pslist`` row's CREATION TIME) resolves to a real
timestamp; ``btf2json``-derived ISFs (this codebase's own self-generated
sample, and likely any BTF-only kernel) leave that symbol's type
unresolved (``Void``), so CREATION TIME comes back ``null`` for every row.
Verified both ways against the identical real kernel build/memory capture
(``poc/volatility_linux_boottime/``): a real ``dwarf2json``-built ISF for
the same ``5.15.0-191-generic`` kernel (built from the matching Ubuntu
``-dbgsym`` package) gave all 105 real sample rows a real, plausible,
monotonically-increasing CREATION TIME; the codebase's own ``btf2json``
ISF gives every row ``null``. This is handled honestly, not as a
regression risk: a ``null`` CREATION TIME is just another "not a
timeline-shaped row" case (see ``_row_to_timeline_record``), so a
``btf2json``-ISF org continues to get zero Linux ``TimelineRecord``s
(exactly today's behavior), while a ``dwarf2json``-ISF org (the common
case for most distro kernels with a debug/dbgsym package available) now
gets real ones.

**Registration order matters.** Must be registered LAST in
``get_parser_registry`` (``src/external/dependencies.py``), after
``PlasoParser``: a ``.raw`` extension is ambiguous between "unwrapped disk
image" (``PlasoParser``, detected via real ext2/3/4-NTFS-FAT superblock
magic bytes) and "raw memory dump" (this module, extension-only). Magic-byte
detection must win first -- verified directly against the real
``cridex.vmem`` header bytes at every one of ``PlasoParser``'s own fixed
magic offsets (0/3/4/54/82/1080): none collide for this real sample (see
``poc/volatility_memory_module/README.md``). Placing this module after every
magic-based parser means a genuine raw disk image with a real filesystem
magic is still claimed by ``PlasoParser`` first; only a ``.raw``/``.dmp``
file that isn't a recognised filesystem falls through to this module.
"""

from __future__ import annotations

import json
import logging
import tempfile
from collections.abc import AsyncIterator, Iterator, Sequence
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.application.parsing import ForensicParser, ParserType
from src.domain.artifact import StructuredArtifact
from src.domain.evidence import Evidence
from src.domain.timeline import EvidenceProvenance, TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import VolatilityScanError
from src.external.sandbox.volatility_launcher import DEFAULT_PLUGINS, LINUX_DEFAULT_PLUGINS

if TYPE_CHECKING:
    from src.adapter.repository.evidence import EvidenceRepository
    from src.adapter.storage.storage import EvidenceStorage
    from src.external.sandbox.volatility_launcher import (
        VolatilityMultiPluginResult,
    )

logger = logging.getLogger(__name__)

# Gap Audit Milestone AAAAA (extended CCCCC): carries one real
# VolatilityMultiPluginResult from parse() to extract_artifacts() within the
# same execute_parse() call, so the (comparatively expensive) real
# volatility3 subprocess only runs once per evidence file -- see this
# module's own docstring for the full "one scan, not N" account, including
# why a plain ContextVar is safe here (mirrors yara_scan_org_var's identical
# orchestration-seam precedent, src/application/yara_rules.py).
_cached_scan_result: ContextVar[VolatilityMultiPluginResult | None] = ContextVar(
    "_kronos_volatility_cached_scan_result", default=None
)

# See this module's own docstring: no verified magic bytes exist for this
# format family, so extension is the only honest signal.
_MEMORY_DUMP_EXTENSIONS: frozenset[str] = frozenset({".vmem", ".mem", ".raw", ".dmp", ".lime"})

# Real plugin names that carry a per-row CreateTime (verified live this
# session for the full current plugin set: only these two do). Checked in
# this preference order -- pstree first, psscan only if pstree contributed
# nothing -- to avoid double-emitting the same real process-creation event
# from both a linked-list walk and a pool-tag scan when both plugins
# recover the same process (the common case once pstree succeeds; see the
# worker script's own docstring for the cridex.vmem case where pstree is
# legitimately empty and psscan is the only real source).
_PSTREE_PLUGIN = "windows.pstree.PsTree"
_PSSCAN_PLUGIN = "windows.psscan.PsScan"
# Real Linux dual-emit source (poc/volatility_linux_boottime/) -- see this
# module's own docstring for the dwarf2json-vs-btf2json ISF dependency.
# Checked only after both Windows sources contribute nothing, since a given
# run only ever has one OS family's plugins present (LINUX_DEFAULT_PLUGINS
# vs DEFAULT_PLUGINS) unless a caller passed an explicit mixed list.
_LINUX_PSLIST_PLUGIN = "linux.pslist.PsList"

# Real, per-plugin row field names for the two shapes this module dual-emits
# from -- Windows pstree/psscan rows use CreateTime/ImageFileName; Linux
# pslist rows use CREATION TIME/COMM (confirmed live,
# poc/volatility_linux_boottime/). Keyed by plugin so _row_to_timeline_record
# doesn't need to guess which shape a row came from.
_ROW_FIELD_NAMES: dict[str, tuple[str, str]] = {
    _LINUX_PSLIST_PLUGIN: ("CREATION TIME", "COMM"),
}
_DEFAULT_ROW_FIELD_NAMES = ("CreateTime", "ImageFileName")

# Real, reproduced incident (poc/volatility_vmware_companion/), raised
# twice on real measurement, see celery_app.py's kronos.parse_artefact_heavy
# for the full account of both incidents this tracks. Kept comfortably
# under that task's own soft_time_limit (2400s) so a genuine timeout raises
# here first as a catchable VolatilityScanError (see _run_volatility's own
# try/except) rather than only ever being caught by Celery's own hard
# SIGKILL, which bypasses this class's cleanup entirely.
_DEFAULT_TIMEOUT_SECONDS = 2200

# The real, pinned external tool version (see
# poc/volatility_memory_module/README.md) -- a module constant (not just a
# property body) so _row_to_timeline_record can stamp the same value onto
# a dual-emitted TimelineRecord without constructing a throwaway instance.
_PARSER_VERSION = "2.28.0"

# Real, enforced cap this codebase's ArtifactIngestService applies per
# artifact (8 MiB, measured on JSON-serialized size -- see
# src/application/artifact_ingest.py::_MAX_CONTENT_BYTES). This module builds
# its own artifacts under a slightly smaller local budget so the JSON
# envelope this class adds (kind/kronos/etc, all added downstream by
# StructuredArtifact/ArtifactIngestService) never accidentally pushes a
# batch that measured just under the *content* cap over the real limit.
_MAX_ROWS_CONTENT_BYTES = 7 * 1024 * 1024

# volatility3's own plugin-tree reorganizations must never silently change a
# kind name a case's already-stored artifacts (and any frontend kind-dispatch
# built against it) rely on. Real, observed case: malfind's canonical import
# path moved from `windows.malfind.Malfind` to `windows.malware.malfind.Malfind`
# in this pinned version (deprecation warning confirmed live) -- naive
# path-derivation would produce `volatility.malware.malfind`, a worse, less
# stable name than the intended `volatility.malfind`. Explicit, curated
# overrides for the (small, fixed) plugin set this module actually runs,
# checked before the generic derivation in _plugin_to_kind.
_PLUGIN_KIND_OVERRIDES: dict[str, str] = {
    "windows.malware.malfind.Malfind": "volatility.malfind",
    # Same real cross-OS kind-unification this class already does for
    # same-named plugins (pstree/psscan naturally unify via the generic
    # prefix-strip in _plugin_to_kind) -- malfind needs an explicit entry
    # on both OS families because both real class paths live one level
    # deeper, under `*.malware.*`, which the generic derivation can't
    # collapse on its own (see the Windows entry above, added first).
    "linux.malware.malfind.Malfind": "volatility.malfind",
}


class CompanionFileResolver:
    """Downloads and stages an evidence item's companion file next to its
    primary temp file, under a matching basename -- the one thing
    volatility3's own ``VmwareStacker`` requires to find a VMware
    ``.vmsn``/``.vmss`` alongside a ``.vmem`` (poc/volatility_vmware_companion/,
    ``volatility3/framework/layers/vmware.py``: ``vmss = location[:-5] +
    ".vmss"`` -- same-directory, same-basename filesystem adjacency, no
    flag or API exists to point volatility3 at a companion living
    elsewhere). Single responsibility, independently unit-testable with a
    fake repository/storage -- this is the one class that knows how to turn
    ``Evidence.companion_evidence_id`` into real bytes on disk; everything
    else about the companion relationship (attaching it, gating the FSM
    re-entry) lives in ``ParsingOrchestrationService``, not here.

    Not registered anywhere by name -- constructed inline by
    ``VolatilityModule._run_volatility()`` the same way that method already
    constructs ``Settings()`` inline rather than through
    ``get_parser_registry()`` (which has no per-request DI seam of its own).
    Deliberately generic: nothing here mentions VMware or Volatility by name
    in its public contract, so a future parser with its own multi-file
    format need not invent a second resolver.
    """

    def __init__(
        self, evidence_repository: EvidenceRepository, evidence_storage: EvidenceStorage
    ) -> None:
        self._repo = evidence_repository
        self._storage = evidence_storage

    async def stage(
        self,
        evidence: Evidence,
        tenant: TenantContext,
        primary_path: Path,
    ) -> Path | None:
        """If *evidence* has a companion, download it and write it next to
        *primary_path* under a matching basename (same stem, companion's own
        real extension). Returns the companion's real path, or ``None`` if
        there is no companion (the common case, every non-VMware format) or
        the companion can't actually be resolved -- logged, never raised,
        matching this module's own "one bad thing doesn't sink the evidence"
        precedent: a broken companion link degrades to the pre-companion
        behavior, it never fails the whole scan.
        """
        if evidence.companion_evidence_id is None:
            return None

        companion = await self._repo.get_by_id(evidence.companion_evidence_id, tenant.org_id)
        if companion is None or not companion.minio_evidence_key:
            logger.warning(
                "volatility_companion_unresolvable",
                extra={
                    "evidence_id": str(evidence.evidence_id),
                    "companion_evidence_id": str(evidence.companion_evidence_id),
                },
            )
            return None

        companion_suffix = Path(companion.metadata.original_filename).suffix
        companion_path = primary_path.with_name(primary_path.stem + companion_suffix)

        stream = await self._storage.stream_object(companion.minio_evidence_key, bucket="evidence")
        with companion_path.open("wb") as f:
            async for chunk in stream:
                f.write(chunk)

        logger.info(
            "volatility_companion_staged",
            extra={
                "evidence_id": str(evidence.evidence_id),
                "companion_evidence_id": str(companion.evidence_id),
                "companion_path": str(companion_path),
            },
        )
        return companion_path


class VolatilityModule(ForensicParser):
    """Runs real volatility3 plugins against a memory image via VolatilityLauncher.

    Yields one ``StructuredArtifact`` (or several, split by content size)
    per plugin that ran successfully -- ``kind`` is the plugin name mapped
    onto this module's namespace (e.g. ``windows.pstree.PsTree`` ->
    ``volatility.pstree``) so a future ``linux.pslist`` lands under the
    same ``volatility.pslist`` kind a Windows run would use.
    """

    def __init__(
        self,
        plugins: Sequence[str] | None = None,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # None (the real production default, see get_parser_registry()) means
        # "detect for real, per evidence file" -- see _run_volatility()'s own
        # real banners.Banners-based OS-family detection
        # (VolatilityLauncher.detect_os_family). An explicit *plugins*
        # sequence bypasses detection entirely and is used verbatim, same as
        # before this method existed -- a caller who asked for a specific
        # plugin list is never second-guessed.
        self._plugins = tuple(plugins) if plugins is not None else None
        self._timeout_seconds = timeout_seconds

    @property
    def parser_name(self) -> str:
        return "volatility3"

    @property
    def parser_version(self) -> str:
        # Mirrors PlasoParser's own convention of using the wrapped tool's
        # version, not a from-scratch semver for this wrapper class.
        return _PARSER_VERSION

    @property
    def parser_type(self) -> ParserType:
        # Always HEAVY: real memory-image analysis delegated to an external
        # tool subprocess, unconditionally -- mirrors
        # ZipArchiveParser/TarArchiveParser/PlasoParser's own reasoning (see
        # each class's own parser_type docstring), never a per-input decision.
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return Path(filename).suffix.lower() in _MEMORY_DUMP_EXTENSIONS

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Runs the real multi-plugin volatility3 scan and yields one
        TimelineRecord per pstree/psscan row that carries a real, parseable
        ``CreateTime`` -- see this module's own docstring for the dual-emit
        design and why this is the ONE place the scan actually runs (cached
        for ``extract_artifacts()`` via ``_cached_scan_result``).
        """
        result = await self._run_volatility(stream, evidence, tenant)
        _cached_scan_result.set(result)
        if result is None:
            return

        plugin, rows = _timeline_rows(result)
        if plugin is None:
            return

        record_index = 0
        for row in rows:
            record = _row_to_timeline_record(
                row, plugin=plugin, evidence=evidence, record_index=record_index
            )
            if record is not None:
                yield record
                record_index += 1

    async def extract_artifacts(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[StructuredArtifact]:
        """Emit the full structural snapshot as StructuredArtifacts, one
        (or more, split by size) per plugin that ran successfully.

        Reuses the scan result ``parse()`` already cached for this same
        evidence file within this same ``execute_parse()`` call (the
        common, real path) -- falls back to running the scan itself only
        when called standalone with nothing cached (e.g. a direct unit
        test), same "still independently callable" contract every other
        ``extract_artifacts()`` override honours.
        """
        cached = _cached_scan_result.get()
        result: VolatilityMultiPluginResult
        if cached is not None:
            _cached_scan_result.set(None)  # consume-once: never reused stale
            result = cached
        else:
            maybe_result = await self._run_volatility(stream, evidence, tenant)
            if maybe_result is None:
                return
            result = maybe_result

        # Real, confirmed gap this fixes: when EVERY plugin fails (e.g.
        # volatility3's automagic genuinely can't identify this image's
        # kernel -- "UnsatisfiedException"/"No suitable kernels found
        # during pdbscan", live-verified against real evidence on case
        # 43097ab0-aae3-4968-915b-8f0229ac3865), the analyst previously saw
        # "COMPLETE, 0 artifacts" with the real reason discarded ("Logged
        # by the worker/launcher already" -- true, but only in ephemeral
        # Celery stdout, never anywhere the analyst can see it). The
        # frontend's own empty-state message claims "Check the Audit tab
        # for the real underlying error" -- confirmed live that this was
        # never true for Volatility failures. This diagnostic artifact is
        # what makes that claim honest: one real, permanent, analyst-
        # visible record of why nothing else exists for this file. Only
        # emitted when literally everything failed -- a normal run with at
        # least one successful plugin (even a real, honest zero-row
        # success) never gets this, matching the existing "zero-row !=
        # failed" distinction the codebase already draws everywhere else.
        if result.outcomes and all(not o.ok for o in result.outcomes):
            yield _build_diagnostic_artifact(
                result, evidence, self.parser_name, self.parser_version
            )
            return

        record_index = 0
        for outcome in result.outcomes:
            if not outcome.ok:
                # A genuine plugin failure (scan_error/skipped_timeout_budget)
                # is honestly different from "ran cleanly and found nothing" --
                # no artifact at all, not a fabricated empty one. Logged by
                # the worker/launcher already; nothing further to do here.
                continue
            for artifact in rows_to_artifacts(
                outcome.rows,
                plugin=outcome.plugin,
                evidence=evidence,
                record_index_start=record_index,
                parser_name=self.parser_name,
                parser_version=self.parser_version,
            ):
                yield artifact
                record_index += 1

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _run_volatility(
        self, stream: AsyncIterator[bytes], evidence: Evidence, tenant: TenantContext
    ) -> VolatilityMultiPluginResult | None:
        """Write the memory image to a temp file and run the full,
        real multi-plugin volatility3 scan once.

        Returns ``None`` on a real whole-run failure (logged, never
        raised -- mirrors TarArchiveParser's "one bad thing doesn't sink
        the evidence" precedent, ``yara_ruleset_compile_failed``): a
        volatility3 failure must never abort this evidence file's
        parse()/completion, only skip this module's own output. A
        *partial* failure (some plugins ok, some not) is NOT this case --
        that's a normal ``VolatilityMultiPluginResult`` with mixed
        ``VolatilityPluginOutcome.status`` values, handled by the callers
        above.
        """
        from src.external.sandbox.volatility_launcher import VolatilityLauncher  # noqa: PLC0415

        with tempfile.NamedTemporaryFile(
            suffix=Path(evidence.metadata.original_filename).suffix,
            delete=False,
        ) as tmp:
            async for chunk in stream:
                tmp.write(chunk)
            tmp_path = tmp.name

        logger.info(
            "volatility_temp_file_ready",
            extra={"evidence_id": str(evidence.evidence_id), "path": tmp_path},
        )

        from src.config import Settings  # noqa: PLC0415

        settings = Settings()
        worker_path = (
            Path(settings.volatility_worker_path) if settings.volatility_worker_path else None
        )

        # poc/volatility_vmware_companion/: a VMware .vmem needs its
        # .vmsn/.vmss co-located under a matching basename before automagic
        # runs -- must happen before detect_os_family/launcher.run below,
        # not after, since both read this same tmp_path. Real, decisive
        # PoC result: linux.pstree.PsTree/linux.pslist.PsList went from 0
        # rows to a full real process tree/344 rows on the identical file
        # once staged this way. Guarded on companion_evidence_id being set
        # so the overwhelmingly common no-companion case never touches any
        # of this at all -- keeps every existing test unaffected.
        #
        # Real, live-verified finding (not the design originally assumed):
        # get_evidence_repository() -- unlike get_evidence_storage() --
        # is NEVER configured inside a Celery worker process.
        # celery_runtime.py's own module docstring explains why:
        # wire_dependencies_sync() (worker_init) deliberately leaves the
        # Postgres repositories unconfigured as process singletons, and
        # each task instead builds a fresh, event-loop-scoped
        # PostgresEvidenceRepository over a fresh NullPool engine inside
        # _build_task_resources() -- reusing a pooled asyncpg connection
        # across a different asyncio.run() event loop is a real, documented
        # bug class this codebase already engineered around once. Calling
        # get_evidence_repository() here raised a real RuntimeError
        # ("EvidenceRepository is not configured") the first time this ran
        # for real inside celery-worker-plaso. Mirrors
        # _build_task_resources()'s own fresh-engine-per-task pattern
        # exactly, not a new one -- disposed in the same finally block that
        # cleans up the temp files, since it's scoped to this one call.
        # Both declared before the try below, and both cleanup steps live in
        # that same try's finally -- a real bug found and fixed while
        # verifying this against the real dev stack: the companion-staging
        # block used to run BEFORE this try/finally, so an exception raised
        # while staging the companion (a real one hit live: the
        # get_evidence_repository() design this replaced didn't work inside
        # a Celery worker, see below) leaked the primary temp file (tmp_path)
        # entirely -- the finally that deletes it was never reached at all.
        companion_path: Path | None = None
        companion_engine = None
        try:
            if evidence.companion_evidence_id is not None:
                from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
                from sqlalchemy.pool import NullPool  # noqa: PLC0415

                from src.adapter.repository.postgres_evidence import (  # noqa: PLC0415
                    PostgresEvidenceRepository,
                )
                from src.external.dependencies import get_evidence_storage  # noqa: PLC0415

                # Real, live-verified finding (not the design originally
                # assumed): get_evidence_repository() -- unlike
                # get_evidence_storage() -- is NEVER configured inside a
                # Celery worker process. celery_runtime.py's own module
                # docstring explains why: wire_dependencies_sync()
                # (worker_init) deliberately leaves the Postgres
                # repositories unconfigured as process singletons, and each
                # task instead builds a fresh, event-loop-scoped
                # PostgresEvidenceRepository over a fresh NullPool engine
                # inside _build_task_resources() -- reusing a pooled asyncpg
                # connection across a different asyncio.run() event loop is
                # a real, documented bug class this codebase already
                # engineered around once. Calling get_evidence_repository()
                # here raised a real RuntimeError ("EvidenceRepository is
                # not configured") the first time this ran for real inside
                # celery-worker-plaso. Mirrors _build_task_resources()'s own
                # fresh-engine-per-task pattern exactly, not a new one.
                companion_engine = create_async_engine(
                    settings.database_url.get_secret_value(), poolclass=NullPool
                )
                companion_repo = PostgresEvidenceRepository(companion_engine)
                resolver = CompanionFileResolver(companion_repo, get_evidence_storage())
                companion_path = await resolver.stage(evidence, tenant, Path(tmp_path))

            launcher = VolatilityLauncher(
                worker_path=worker_path,
                timeout_seconds=self._timeout_seconds,
                remote_isf_url=settings.volatility_remote_isf_url or None,
            )
            plugins_to_run = self._plugins
            if plugins_to_run is None:
                os_family = await launcher.detect_os_family(tmp_path)
                plugins_to_run = LINUX_DEFAULT_PLUGINS if os_family == "linux" else DEFAULT_PLUGINS
                logger.info(
                    "volatility_os_family_detected",
                    extra={
                        "evidence_id": str(evidence.evidence_id),
                        "os_family": os_family,
                        "plugins": list(plugins_to_run),
                    },
                )
            try:
                return await launcher.run(evidence_path=tmp_path, plugins=plugins_to_run)
            except VolatilityScanError as exc:
                logger.warning(
                    "volatility_scan_failed",
                    extra={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
                )
                return None
        finally:
            Path(tmp_path).unlink(missing_ok=True)
            if companion_path is not None:
                companion_path.unlink(missing_ok=True)
            if companion_engine is not None:
                await companion_engine.dispose()


def _timeline_rows(
    result: VolatilityMultiPluginResult,
) -> tuple[str | None, tuple[dict[str, Any], ...]]:
    """Pick the one real source of CreateTime-bearing rows for the
    TimelineRecord dual-emit -- pstree preferred, psscan only if pstree
    contributed nothing (real, verified: this avoids double-emitting the
    same process-creation event when both plugins recover the same
    process, the common case once pstree succeeds; see this module's own
    docstring). Neither present/ok, or both empty, falls through to the
    real Linux source (``linux.pslist.PsList``); if that's absent/empty
    too, returns ``(None, ())``.

    **Linux uses a different plugin, real finding not an oversight**:
    ``linux.pstree.PsTree``/``linux.psscan.PsScan`` rows in this pinned
    volatility3 version carry no per-row wall-clock timestamp field at all
    (no ``CreateTime`` or equivalent -- just ``PID``/``TID``/``PPID``/
    ``COMM``/offset, confirmed live, ``poc/volatility_linux_module/``), so
    they're never checked for Linux. ``linux.pslist.PsList``'s "CREATION
    TIME" column is the real source instead (see this module's own
    docstring for the dwarf2json-vs-btf2json ISF dependency that
    determines whether it's actually populated for a given image) --
    ``_row_to_timeline_record`` handles its different field names via
    ``_ROW_FIELD_NAMES`` and a ``null``/missing value there is handled the
    same honest way as a Windows row with no ``CreateTime``: no record for
    that row, not an error.
    """
    pstree = result.for_plugin(_PSTREE_PLUGIN)
    if pstree is not None and pstree.ok and pstree.rows:
        return _PSTREE_PLUGIN, pstree.rows
    psscan = result.for_plugin(_PSSCAN_PLUGIN)
    if psscan is not None and psscan.ok and psscan.rows:
        return _PSSCAN_PLUGIN, psscan.rows
    pslist = result.for_plugin(_LINUX_PSLIST_PLUGIN)
    if pslist is not None and pslist.ok and pslist.rows:
        return _LINUX_PSLIST_PLUGIN, pslist.rows
    return None, ()


def _plugin_to_kind(plugin: str) -> str:
    """Map a real volatility3 plugin name (``module.path.ClassName`` form)
    onto this module's namespaced artifact kind.

    e.g. ``"windows.pstree.PsTree"`` -> ``"volatility.pstree"``,
    ``"windows.registry.hivelist.HiveList"`` -> ``"volatility.registry.hivelist"``.
    Strips the OS-family prefix (windows./linux./mac.) and the trailing
    class-name segment (detected by its leading uppercase letter --
    Python's own module-vs-class naming convention, true for every real
    plugin this module runs) -- the kind describes *what the data is*, not
    which OS build or Python class produced it, so a future ``linux.pslist``
    lands under the same ``volatility.pslist`` kind a Windows run would use.
    Checks ``_PLUGIN_KIND_OVERRIDES`` first for the rare case where
    volatility3's own module reorganization would otherwise change a
    kind name that already-stored artifacts/frontend code depend on.
    """
    if plugin in _PLUGIN_KIND_OVERRIDES:
        return _PLUGIN_KIND_OVERRIDES[plugin]
    parts = plugin.split(".")
    if len(parts) >= 2 and parts[-1][:1].isupper():
        parts = parts[:-1]
    if len(parts) >= 2:
        parts = parts[1:]
    return f"volatility.{'.'.join(parts)}"


def rows_to_artifacts(
    rows: tuple[dict[str, Any], ...],
    *,
    plugin: str,
    evidence: Evidence,
    record_index_start: int,
    parser_name: str,
    parser_version: str,
) -> Iterator[StructuredArtifact]:
    """Yield one or more StructuredArtifacts covering *rows*.

    Module-level (not a ``VolatilityModule`` method) so both the eager
    ``extract_artifacts()`` path and ``VolatilityOnDemandService``'s
    curated-plugin on-demand path (which has no ``VolatilityModule``
    instance of its own) share the exact same batching/kind-mapping logic
    instead of a second, drifting copy.

    Splits on ``_MAX_ROWS_CONTENT_BYTES`` -- mirrors
    ``ArtifactIngestService``'s own documented convention (see
    ``src/application/artifact_ingest.py``): split into multiple
    artifacts of the same ``kind`` rather than asking to raise the cap.
    A zero-row result still yields exactly one artifact with an empty
    ``rows`` list -- a real, honest "this plugin found nothing" result
    (see this module's own docstring re: ``windows.pstree`` against
    ``cridex.vmem``), not silently dropped.
    """
    kind = _plugin_to_kind(plugin)
    if not rows:
        yield _build_artifact(
            (), kind, plugin, evidence, parser_name, parser_version, record_index_start
        )
        return

    # Real, reproduced incident (poc/volatility_vmware_companion/): the
    # previous version re-serialized the ENTIRE growing `batch` to JSON on
    # every row to measure its size -- an O(n^2) cost that was invisible
    # against every plugin this module was ever real-verified against
    # before (a few hundred rows at most), but a real companion-linked
    # linux.lsof.Lsof result (24,562 real rows, correctly recovered only
    # because the companion fix made lsof's underlying data walkable at
    # all) turned that into a genuine 30+ minute silent hang inside one
    # Python loop with no intermediate logging -- confirmed live: a real,
    # full-size 7MiB Postgres JSONB insert of the exact same content took
    # 17.6ms, ruling out the database. Fixed by computing each row's own
    # serialized size exactly once and keeping a running total instead of
    # re-serializing the whole batch -- O(n), not O(n^2). The `+1` per row
    # approximates the JSON array's own comma separators; this cap was
    # always a soft engineering boundary (splitting artifacts, not a byte-
    # exact contract), so the small, constant per-row undercount is fine.
    batch: list[dict[str, Any]] = []
    batch_bytes = 2  # "[" + "]"
    index = record_index_start
    for row in rows:
        row_bytes = len(json.dumps(row, default=str).encode("utf-8")) + 1
        if batch and batch_bytes + row_bytes > _MAX_ROWS_CONTENT_BYTES:
            yield _build_artifact(
                tuple(batch), kind, plugin, evidence, parser_name, parser_version, index
            )
            index += 1
            batch = [row]
            batch_bytes = 2 + row_bytes
        else:
            batch.append(row)
            batch_bytes += row_bytes
    if batch:
        yield _build_artifact(
            tuple(batch), kind, plugin, evidence, parser_name, parser_version, index
        )


def _build_artifact(
    rows: tuple[dict[str, Any], ...],
    kind: str,
    plugin: str,
    evidence: Evidence,
    parser_name: str,
    parser_version: str,
    record_index: int,
) -> StructuredArtifact:
    content: dict[str, Any] = {"plugin": plugin, "rows": list(rows)}
    provenance = EvidenceProvenance(
        evidence_id=evidence.evidence_id,
        case_id=evidence.metadata.case_id,
        org_id=evidence.metadata.org_id,
        org_alias=evidence.metadata.org_alias,
        sha256=evidence.sha256 or "",
        parser=parser_name,
        parser_version=parser_version,
        record_index=record_index,
        ingest_timestamp=datetime.now(UTC),
    )
    return StructuredArtifact(kind=kind, content=content, kronos=provenance)


def _build_diagnostic_artifact(
    result: VolatilityMultiPluginResult,
    evidence: Evidence,
    parser_name: str,
    parser_version: str,
) -> StructuredArtifact:
    """One real, permanent record of why a Volatility run produced nothing.

    Only called when every requested plugin's own outcome is non-ok (see
    ``extract_artifacts()`` above) -- ``content`` carries each plugin's
    real ``error`` string verbatim (e.g. volatility3's own
    ``"UnsatisfiedException: "``/``"No suitable kernels found during
    pdbscan"`` text, live-verified against real evidence on case
    43097ab0-aae3-4968-915b-8f0229ac3865), not a paraphrase, so an analyst
    reading it sees the same thing this session's own diagnostic run did.
    """
    content: dict[str, Any] = {
        "plugin_errors": {outcome.plugin: outcome.error for outcome in result.outcomes},
    }
    provenance = EvidenceProvenance(
        evidence_id=evidence.evidence_id,
        case_id=evidence.metadata.case_id,
        org_id=evidence.metadata.org_id,
        org_alias=evidence.metadata.org_alias,
        sha256=evidence.sha256 or "",
        parser=parser_name,
        parser_version=parser_version,
        record_index=0,
        ingest_timestamp=datetime.now(UTC),
    )
    return StructuredArtifact(kind="volatility.diagnostic", content=content, kronos=provenance)


def _parse_create_time(raw: Any) -> datetime | None:
    """Return a real, aware datetime for a row's create-time field, or None.

    Real volatility3 ``psscan``/``pstree`` (Windows, ``CreateTime``) and
    ``pslist`` (Linux, ``CREATION TIME``) rows render it as an ISO-8601
    string with an explicit UTC offset (confirmed against the real
    captured ``cridex.vmem`` output, e.g. ``"2012-07-22T02:42:33+00:00"`` --
    ``poc/volatility_pipeline_ingest/artifact_verification.json`` --
    and, for Linux, ``poc/volatility_linux_boottime/``, e.g.
    ``"2026-09-19T14:50:06.111155+00:00"``) -- ``datetime.fromisoformat``
    parses both directly, no replace() tricks needed (unlike Plaso's own
    epoch-microsecond convention, ``firecracker.py``). A row can genuinely
    have no create-time at all (e.g. some Windows rows only carry
    ``ExitTime``; every Linux row when the image's ISF was built by
    ``btf2json`` rather than ``dwarf2json``, see this module's own
    docstring) or a null value -- both are honest "not a timeline-shaped
    row," not an error.
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _row_to_timeline_record(
    row: dict[str, Any],
    *,
    plugin: str,
    evidence: Evidence,
    record_index: int,
) -> TimelineRecord | None:
    """Return a process-creation TimelineRecord for *row*, or None if it
    carries no real, parseable create-time (see this module's own
    docstring for the dual-emit design this backs).

    ECS mapping: ``event.category=["process"]``/``event.type=["start"]``
    (a real process-creation event, not a snapshot-in-general), the two
    already-flattened ``process.pid``/``process.name`` fields
    ``TimelineRecord`` provides directly, everything else (parent pid,
    thread count, the plugin's own raw memory offset -- forensically
    meaningful on its own, e.g. for a follow-up ``vol -o <offset>``
    targeted re-scan) into ``extra`` with dotted ECS-style keys, the same
    convention ``FastEvtxParser``/``PlasoParser`` already use for
    format-specific fields ``TimelineRecord`` has no dedicated column for.

    Field names differ by plugin/OS family (``_ROW_FIELD_NAMES``): Windows
    ``pstree``/``psscan`` rows use ``CreateTime``/``ImageFileName``; Linux
    ``pslist`` rows use ``CREATION TIME``/``COMM`` (real, verified,
    ``poc/volatility_linux_boottime/``).
    """
    create_time_field, image_name_field = _ROW_FIELD_NAMES.get(plugin, _DEFAULT_ROW_FIELD_NAMES)
    timestamp = _parse_create_time(row.get(create_time_field))
    if timestamp is None:
        return None

    pid = row.get("PID")
    image_name = row.get(image_name_field)
    message = (
        f"Process {image_name} (PID {pid}) created"
        if image_name is not None and pid is not None
        else "Process created"
    )

    extra: dict[str, Any] = {"volatility.plugin": plugin}
    if row.get("PPID") is not None:
        extra["process.parent.pid"] = row["PPID"]
    if row.get("Threads") is not None:
        extra["process.thread.count"] = row["Threads"]
    if row.get("SessionId") is not None:
        extra["volatility.session_id"] = row["SessionId"]
    # Windows rows render "Offset(V)"; Linux pslist renders "OFFSET (V)"
    # (confirmed live, poc/volatility_linux_boottime/) -- both checked since
    # a plugin only ever populates one of the two.
    offset = row.get("Offset(V)")
    if offset is None:
        offset = row.get("OFFSET (V)")
    if offset is not None:
        extra["volatility.offset_v"] = offset

    provenance = EvidenceProvenance(
        evidence_id=evidence.evidence_id,
        case_id=evidence.metadata.case_id,
        org_id=evidence.metadata.org_id,
        org_alias=evidence.metadata.org_alias,
        sha256=evidence.sha256 or "",
        parser="volatility3",
        parser_version=_PARSER_VERSION,
        record_index=record_index,
        ingest_timestamp=datetime.now(UTC),
    )
    return TimelineRecord(
        **{"@timestamp": timestamp},
        message=message,
        event_kind="event",
        event_category=["process"],
        event_type=["start"],
        process_pid=pid if isinstance(pid, int) else None,
        process_name=image_name if isinstance(image_name, str) else None,
        extra=extra,
        kronos=provenance,
    )
