"""VolatilityModule: real ``volatility3`` memory-forensics wrapping (§G, roadmap E5).

Wraps ``VolatilityLauncher`` (``src/external/sandbox/volatility_launcher.py``)
in the ``ForensicParser`` interface -- see that module's docstring for the
sandboxing rationale (CLAUDE.md §G.3) and the real, verified
``windows.pstree`` -> ``windows.psscan`` fallback behaviour.

**Dual-emit (Gap Audit Milestone AAAAA): both ``parse()`` and
``extract_artifacts()`` are now real.** The structural snapshot as a whole
(``pstree``/``psscan``, keyed by PID/PPID, not chronology --
``reviews/DFIR_Artifact_Landscape.md`` §2) still isn't timeline-shaped, so
it still becomes ``StructuredArtifact``s exactly as before. But a real,
individual *row* within that snapshot frequently carries its own genuine
per-process ``CreateTime`` -- a real process-creation event, independently
timeline-shaped even though the plugin's output *as a whole* isn't.
Confirmed against the real captured ``psscan`` output this module already
verified against ``cridex.vmem`` (``poc/volatility_pipeline_ingest/``):
every recovered process row carries a real ISO-8601 ``CreateTime``. So
``parse()`` now derives one ``TimelineRecord`` per row with a parseable
``CreateTime`` (any plugin, not hardcoded to ``psscan`` -- the field is
checked generically, so a future plugin that also renders one keeps
working without a new special case), letting the existing Timeline tab
correlate process starts against every other evidence source in the same
case -- while ``extract_artifacts()`` still emits the full structural
snapshot for the dedicated Artifacts view. Real volatility3 CLI/plugin
invocations documented elsewhere in this module still apply unchanged
(fallback behaviour, timeouts, sandboxing).

**One scan, not two.** ``ParsingOrchestrationService.execute_parse()``
calls ``parse()`` then ``extract_artifacts()`` as two independent passes
for every parser that implements both (``reviews/Data_Source_Module_System.md``
§5/§9's own documented v1 tradeoff) -- fine for e.g. ``ZipArchiveParser``,
whose own ``parse()`` is a true no-op, but wrong here: a real volatility3
subprocess run is comparatively expensive (a single real
`vol -f <512MB image> windows.psscan` run against ``cridex.vmem`` measured
well under 5s, per ``volatility_launcher.py``'s own docstring, but a
larger real-world image or a heavier plugin can take much longer), and
running it twice for the same evidence file would silently double a real
memory-forensics job's cost for no benefit. Both methods are always
invoked back-to-back within the same ``execute_parse()`` async call for a
given evidence file (confirmed by reading that method before writing
this), and Celery invokes it via a fresh ``asyncio.run()`` per task
(``celery_runtime.run_evidence_coro``) -- so a plain module-level
``ContextVar``, set once inside ``parse()`` and read once inside
``extract_artifacts()``, is naturally isolated per task with zero risk of
cross-evidence leakage between concurrent Celery tasks, exactly mirroring
this codebase's own existing precedent for this identical orchestration
seam (``yara_scan_org_var``, ``src/application/yara_rules.py``).
``extract_artifacts()`` still falls back to running the scan itself if
called standalone (no cached result present) -- same "still independently
callable" contract every other ``extract_artifacts()`` override honours.

Every plugin this module runs today (``windows.pstree``, ``windows.psscan``)
is fundamentally non-timeline output *as a whole* -- a process tree/listing
keyed by PID/PPID, not a stream of timestamped events (see
``reviews/DFIR_Artifact_Landscape.md`` §2's own classification) -- the
per-row ``CreateTime`` dual-emit above is additive to that, not a
reclassification of it. Plugins whose *primary* output is itself
timeline-shaped (``timeliner``, ``windows.netscan``) remain explicitly out
of scope for this item -- verifying those against a real sample is a
separate, follow-up unit of work, not something to bolt on speculatively
(CLAUDE.md §G.5).

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
from collections.abc import AsyncIterator, Iterator
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

if TYPE_CHECKING:
    from src.external.sandbox.volatility_launcher import VolatilityPluginResult

logger = logging.getLogger(__name__)

# Gap Audit Milestone AAAAA: carries one real VolatilityPluginResult from
# parse() to extract_artifacts() within the same execute_parse() call, so
# the (comparatively expensive) real volatility3 subprocess only runs
# once per evidence file -- see this module's own docstring for the full
# "one scan, not two" account, including why a plain ContextVar is safe
# here (mirrors yara_scan_org_var's identical orchestration-seam
# precedent, src/application/yara_rules.py).
_cached_scan_result: ContextVar[VolatilityPluginResult | None] = ContextVar(
    "_kronos_volatility_cached_scan_result", default=None
)

# See this module's own docstring: no verified magic bytes exist for this
# format family, so extension is the only honest signal.
_MEMORY_DUMP_EXTENSIONS: frozenset[str] = frozenset({".vmem", ".mem", ".raw", ".dmp", ".lime"})

_DEFAULT_PLUGIN = "windows.pstree"
_DEFAULT_FALLBACK_PLUGIN = "windows.psscan"
_DEFAULT_TIMEOUT_SECONDS = 300

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


class VolatilityModule(ForensicParser):
    """Runs real volatility3 plugins against a memory image via VolatilityLauncher.

    Yields one or more ``StructuredArtifact``s per plugin that produced
    output -- ``kind`` is the plugin name mapped onto this module's
    namespace (e.g. ``windows.pstree`` -> ``volatility.pstree``,
    ``windows.psscan`` -> ``volatility.psscan``) so a future ``linux.pslist``
    lands under the same ``volatility.pslist`` kind a Windows run would use.
    """

    def __init__(
        self,
        plugin: str = _DEFAULT_PLUGIN,
        fallback_plugin: str | None = _DEFAULT_FALLBACK_PLUGIN,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._plugin = plugin
        self._fallback_plugin = fallback_plugin
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
        """Runs the real volatility3 scan and yields one TimelineRecord per
        row that carries a real, parseable ``CreateTime`` -- see this
        module's own docstring for the dual-emit design and why this is
        the ONE place the scan actually runs (cached for
        ``extract_artifacts()`` via ``_cached_scan_result``).
        """
        result = await self._run_volatility(stream, evidence)
        _cached_scan_result.set(result)
        if result is None:
            return

        record_index = 0
        for row in result.rows:
            record = _row_to_timeline_record(
                row, plugin=result.plugin, evidence=evidence, record_index=record_index
            )
            if record is not None:
                yield record
                record_index += 1

        if result.used_fallback and result.fallback_rows is not None:
            for row in result.fallback_rows:
                record = _row_to_timeline_record(
                    row,
                    plugin=result.fallback_plugin or "",
                    evidence=evidence,
                    record_index=record_index,
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
        """Emit the full structural snapshot as StructuredArtifacts.

        Reuses the scan result ``parse()`` already cached for this same
        evidence file within this same ``execute_parse()`` call (the
        common, real path) -- falls back to running the scan itself only
        when called standalone with nothing cached (e.g. a direct unit
        test), same "still independently callable" contract every other
        ``extract_artifacts()`` override honours.
        """
        cached = _cached_scan_result.get()
        result: VolatilityPluginResult
        if cached is not None:
            _cached_scan_result.set(None)  # consume-once: never reused stale
            result = cached
        else:
            maybe_result = await self._run_volatility(stream, evidence)
            if maybe_result is None:
                return
            result = maybe_result

        record_index = 0
        for artifact in self._rows_to_artifacts(
            result.rows,
            plugin=result.plugin,
            evidence=evidence,
            record_index_start=record_index,
        ):
            yield artifact
            record_index += 1

        if result.used_fallback and result.fallback_rows is not None:
            for artifact in self._rows_to_artifacts(
                result.fallback_rows,
                plugin=result.fallback_plugin or "",
                evidence=evidence,
                record_index_start=record_index,
            ):
                yield artifact
                record_index += 1

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _run_volatility(
        self, stream: AsyncIterator[bytes], evidence: Evidence
    ) -> VolatilityPluginResult | None:
        """Write the memory image to a temp file and run volatility3 once.

        Returns ``None`` on a real scan failure (logged, never raised --
        mirrors TarArchiveParser's "one bad thing doesn't sink the
        evidence" precedent, ``yara_ruleset_compile_failed``): a
        volatility3 failure must never abort this evidence file's
        parse()/completion, only skip this module's own output.
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

        try:
            launcher = VolatilityLauncher(
                worker_path=worker_path, timeout_seconds=self._timeout_seconds
            )
            try:
                return await launcher.run(
                    evidence_path=tmp_path,
                    plugin=self._plugin,
                    fallback_plugin=self._fallback_plugin,
                )
            except VolatilityScanError as exc:
                logger.warning(
                    "volatility_scan_failed",
                    extra={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
                )
                return None
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _rows_to_artifacts(
        self,
        rows: tuple[dict[str, Any], ...],
        *,
        plugin: str,
        evidence: Evidence,
        record_index_start: int,
    ) -> Iterator[StructuredArtifact]:
        """Yield one or more StructuredArtifacts covering *rows*.

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
            yield _build_artifact((), kind, plugin, evidence, self, record_index_start)
            return

        batch: list[dict[str, Any]] = []
        index = record_index_start
        for row in rows:
            candidate = [*batch, row]
            size = len(json.dumps(candidate, default=str).encode("utf-8"))
            if size > _MAX_ROWS_CONTENT_BYTES and batch:
                yield _build_artifact(tuple(batch), kind, plugin, evidence, self, index)
                index += 1
                batch = [row]
            else:
                batch = candidate
        if batch:
            yield _build_artifact(tuple(batch), kind, plugin, evidence, self, index)


def _plugin_to_kind(plugin: str) -> str:
    """Map a volatility3 plugin name onto this module's namespaced artifact kind.

    e.g. ``"windows.pstree"`` -> ``"volatility.pstree"``,
    ``"windows.psscan"`` -> ``"volatility.psscan"``. Strips the OS-family
    prefix (windows./linux./mac.) -- the kind describes *what the data is*,
    not which OS build produced it, so a future ``linux.pslist`` run lands
    under the same ``volatility.pslist`` kind a Windows run would use.
    """
    suffix = plugin.split(".", 1)[-1] if "." in plugin else plugin
    return f"volatility.{suffix}"


def _build_artifact(
    rows: tuple[dict[str, Any], ...],
    kind: str,
    plugin: str,
    evidence: Evidence,
    parser: VolatilityModule,
    record_index: int,
) -> StructuredArtifact:
    content: dict[str, Any] = {"plugin": plugin, "rows": list(rows)}
    provenance = EvidenceProvenance(
        evidence_id=evidence.evidence_id,
        case_id=evidence.metadata.case_id,
        org_id=evidence.metadata.org_id,
        org_alias=evidence.metadata.org_alias,
        sha256=evidence.sha256 or "",
        parser=parser.parser_name,
        parser_version=parser.parser_version,
        record_index=record_index,
        ingest_timestamp=datetime.now(UTC),
    )
    return StructuredArtifact(kind=kind, content=content, kronos=provenance)


def _parse_create_time(raw: Any) -> datetime | None:
    """Return a real, aware datetime for a row's ``CreateTime``, or None.

    Real volatility3 ``psscan``/``pstree`` rows render ``CreateTime`` as an
    ISO-8601 string with an explicit UTC offset (confirmed against the real
    captured ``cridex.vmem`` output, e.g. ``"2012-07-22T02:42:33+00:00"`` --
    ``poc/volatility_pipeline_ingest/artifact_verification.json``) --
    ``datetime.fromisoformat`` parses that directly, no replace() tricks
    needed (unlike Plaso's own epoch-microsecond convention,
    ``firecracker.py``). A row can genuinely have no ``CreateTime`` at all
    (e.g. some plugins/rows only carry ``ExitTime``) or a null value --
    both are honest "not a timeline-shaped row," not an error.
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
    carries no real, parseable ``CreateTime`` (see this module's own
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
    """
    timestamp = _parse_create_time(row.get("CreateTime"))
    if timestamp is None:
        return None

    pid = row.get("PID")
    image_name = row.get("ImageFileName")
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
    offset = row.get("Offset(V)")
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
