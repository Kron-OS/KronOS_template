"""VolatilityModule: real ``volatility3`` memory-forensics wrapping (§G, roadmap E5).

Wraps ``VolatilityLauncher`` (``src/external/sandbox/volatility_launcher.py``)
in the ``ForensicParser`` interface -- see that module's docstring for the
sandboxing rationale (CLAUDE.md §G.3) and the real, verified
``windows.pstree`` -> ``windows.psscan`` fallback behaviour.

**``extract_artifacts()`` is the real, load-bearing deliverable; ``parse()``
is a documented no-op.** ``ForensicParser.parse()`` is abstract (unlike
``extract_artifacts()``, which has a concrete "yields nothing" default), so
every subclass must provide *some* implementation -- this one mirrors that
same base-class default explicitly, rather than leaving it unimplemented.
Every plugin this module runs today (``windows.pstree``, ``windows.psscan``)
is fundamentally non-timeline output -- a process tree/listing keyed by
PID/PPID, not a stream of timestamped events (see
``reviews/DFIR_Artifact_Landscape.md`` §2's own classification). Timeline-
shaped plugins (``timeliner``, ``pslist``/``linux.pslist`` CreateTime,
``windows.netscan``) are explicitly out of scope for this item -- verifying
those against a real sample is a separate, follow-up unit of work, not
something to bolt on speculatively (CLAUDE.md §G.5).

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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.application.parsing import ForensicParser, ParserType
from src.domain.artifact import StructuredArtifact
from src.domain.evidence import Evidence
from src.domain.timeline import EvidenceProvenance, TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import VolatilityScanError

logger = logging.getLogger(__name__)

# See this module's own docstring: no verified magic bytes exist for this
# format family, so extension is the only honest signal.
_MEMORY_DUMP_EXTENSIONS: frozenset[str] = frozenset({".vmem", ".mem", ".raw", ".dmp", ".lime"})

_DEFAULT_PLUGIN = "windows.pstree"
_DEFAULT_FALLBACK_PLUGIN = "windows.psscan"
_DEFAULT_TIMEOUT_SECONDS = 300

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
        # The real, pinned external tool version (see
        # poc/volatility_memory_module/README.md) -- mirrors PlasoParser's
        # own convention of using the wrapped tool's version, not a
        # from-scratch semver for this wrapper class.
        return "2.28.0"

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
        """Yields nothing -- see this module's own docstring.

        Every volatility3 plugin this module wraps today produces
        fundamentally non-timeline output; ``extract_artifacts()`` is where
        this module's real work happens. Explicit override (not inherited)
        because ``ForensicParser.parse()`` is abstract, unlike
        ``extract_artifacts()``.
        """
        return
        yield  # noqa: RET504

    async def extract_artifacts(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[StructuredArtifact]:
        """Write the memory image to a temp file, run volatility3, emit artifacts."""
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
                result = await launcher.run(
                    evidence_path=tmp_path,
                    plugin=self._plugin,
                    fallback_plugin=self._fallback_plugin,
                )
            except VolatilityScanError as exc:
                # Mirrors TarArchiveParser's "one bad thing doesn't sink the
                # evidence" precedent (yara_ruleset_compile_failed): a
                # volatility3 failure must never abort this evidence file's
                # parse()/completion, only skip this module's own artifacts.
                logger.warning(
                    "volatility_scan_failed",
                    extra={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
                )
                return

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
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

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
