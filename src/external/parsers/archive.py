"""ZipArchiveParser: explodes a ZIP container (e.g. a KAPE triage collection)
into inner artifacts and recursively re-dispatches each through the same
ParserRegistry, so a KAPE ``.zip`` works with every parser already registered
without any of them needing to know about containers.

Deliberate simplification vs. reviews/Extensibility_Architecture_Proposal.md's
originally sketched design (a separate ``ArchiveExtractor`` ABC + registry,
wired as a new branch in ``ParsingOrchestrationService``): this ships as a
``ForensicParser`` subclass instead, registered *first* in ``ParserRegistry``.
That means zero changes were needed to orchestration -- it still just
"resolve one parser via first-match-wins, call parse(), get records" -- which
is far lower-risk to ship and verify than a parallel dispatch path. The
tradeoff is that an extracted member's bytes must be fully buffered in memory
per-member (bounded by MAX_PER_FILE_UNCOMPRESSED_BYTES) rather than streamed
member-by-member from a lazily-reopened archive handle; real KAPE artifacts
(individual EVTX/registry/prefetch/SQLite files) are routinely well under
that bound.

Zip-bomb defense reads each member through a bounded ``read(cap + 1)`` (never
trusting the archive's own declared ``ZipInfo.file_size``, which a malicious
zip can lie about) and charges a *shared* budget across the whole recursive
extraction tree via a ContextVar, so nested zip-in-zip containers can't each
individually stay "under limit" while the aggregate explodes.
"""

from __future__ import annotations

import logging
import tempfile
import zipfile
from collections.abc import AsyncIterator
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import ParsingError

if TYPE_CHECKING:
    from src.application.parser_registry import ParserRegistry

logger = logging.getLogger(__name__)

_ZIP_MAGIC = b"PK\x03\x04"

MAX_CONTAINER_DEPTH = 3
MAX_MEMBER_COUNT = 50_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 4 * 1024**3  # 4 GiB
MAX_PER_FILE_UNCOMPRESSED_BYTES = 1024**3  # 1 GiB -- matches the single-file upload cap

# One shared budget per top-level evidence parse (one Celery task == one
# asyncio task == one context), so nested containers can't each locally pass
# a per-call check while the aggregate explodes. Reset when the outermost
# ZipArchiveParser.parse() call (the one that created it) returns.
_budget: ContextVar[_ExtractionBudget | None] = ContextVar("_kape_zip_budget", default=None)
_depth: ContextVar[int] = ContextVar("_kape_zip_depth", default=0)


@dataclass
class _ExtractionBudget:
    files_used: int = 0
    bytes_used: int = 0

    def charge(self, n_bytes: int, evidence: Evidence) -> None:
        self.files_used += 1
        self.bytes_used += n_bytes
        if self.files_used > MAX_MEMBER_COUNT:
            raise ParsingError(
                "Container exceeds maximum member count",
                context={"evidence_id": str(evidence.evidence_id), "limit": MAX_MEMBER_COUNT},
            )
        if self.bytes_used > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ParsingError(
                "Container exceeds maximum total extracted bytes",
                context={
                    "evidence_id": str(evidence.evidence_id),
                    "limit": MAX_TOTAL_UNCOMPRESSED_BYTES,
                },
            )


def _is_unsafe_member_path(name: str) -> bool:
    """Reject zip-slip paths: absolute, or containing a '..' traversal segment."""
    if name.startswith("/") or name.startswith("\\"):
        return True
    normalized = name.replace("\\", "/")
    return any(part == ".." for part in normalized.split("/"))


class ZipArchiveParser(ForensicParser):
    """Explodes a ZIP into inner artifacts, re-dispatching each through the
    injected ``ParserRegistry``.

    Must be registered FIRST in that same registry (see
    ``src/external/dependencies.py::get_parser_registry``): first-match-wins
    detection means it claims every ZIP before any other parser gets a
    chance, and its own recursive ``get_parser()`` calls transparently
    support zip-in-zip nesting (bounded by ``MAX_CONTAINER_DEPTH``) since a
    nested zip member resolves back to this same class in the registry.
    """

    def __init__(self, registry: ParserRegistry) -> None:
        self._registry = registry

    @property
    def parser_name(self) -> str:
        return "zip-archive"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        # Always HEAVY: an inner member may require Plaso (registry hive,
        # prefetch, SQLite), and only the heavy queue's worker image has
        # Plaso installed (docker/Dockerfile.plaso-worker's venv is `pip
        # install .` PLUS plaso -- a strict superset, so every first-party
        # fast parser also runs fine there; the reverse is not true).
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return header_bytes[: len(_ZIP_MAGIC)] == _ZIP_MAGIC

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        depth = _depth.get()
        if depth >= MAX_CONTAINER_DEPTH:
            raise ParsingError(
                "Container nesting exceeds maximum depth",
                context={
                    "evidence_id": str(evidence.evidence_id),
                    "max_depth": MAX_CONTAINER_DEPTH,
                },
            )

        budget = _budget.get()
        owns_budget = budget is None
        if owns_budget:
            budget = _ExtractionBudget()
            _budget.set(budget)

        depth_token = _depth.set(depth + 1)
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                async for chunk in stream:
                    tmp.write(chunk)
                tmp_path = tmp.name

            try:
                async for record in self._walk_zip(tmp_path, evidence, tenant, budget):
                    yield record
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        finally:
            _depth.reset(depth_token)
            if owns_budget:
                _budget.set(None)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _walk_zip(
        self,
        zip_path: str,
        evidence: Evidence,
        tenant: TenantContext,
        budget: _ExtractionBudget,
    ) -> AsyncIterator[TimelineRecord]:
        try:
            zf = zipfile.ZipFile(zip_path)
        except zipfile.BadZipFile as exc:
            raise ParsingError(
                "Not a valid ZIP archive",
                context={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
            ) from exc

        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if _is_unsafe_member_path(info.filename):
                    logger.warning(
                        "zip_member_path_rejected",
                        extra={"evidence_id": str(evidence.evidence_id), "member": info.filename},
                    )
                    continue

                # Never trust ZipInfo.file_size (a malicious archive can lie
                # about it) -- bound the actual decompressed read instead.
                with zf.open(info) as member_fp:
                    data = member_fp.read(MAX_PER_FILE_UNCOMPRESSED_BYTES + 1)
                if len(data) > MAX_PER_FILE_UNCOMPRESSED_BYTES:
                    logger.warning(
                        "zip_member_too_large_skipped",
                        extra={"evidence_id": str(evidence.evidence_id), "member": info.filename},
                    )
                    continue

                budget.charge(len(data), evidence)

                async for record in self._dispatch_member(info.filename, data, evidence, tenant):
                    yield record

    async def _dispatch_member(
        self,
        member_path: str,
        data: bytes,
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        basename = Path(member_path).name
        header = data[:8192]
        parser = self._registry.get_parser(basename, "application/octet-stream", header)
        if parser is None:
            logger.info(
                "zip_member_no_parser",
                extra={"evidence_id": str(evidence.evidence_id), "member": member_path},
            )
            return

        async def _one_shot() -> AsyncIterator[bytes]:
            yield data

        async for record in parser.parse(_one_shot(), evidence, tenant):
            yield _stamp_source_path(record, member_path, evidence)


def _stamp_source_path(
    record: TimelineRecord, member_path: str, evidence: Evidence
) -> TimelineRecord:
    """Attach/extend the record's kronos.source_path with this container level.

    A leaf parser's own output has ``source_path`` unset (None); a nested
    ZipArchiveParser's output already carries the inner container's own
    member path, so this level's member_path is prepended rather than
    overwritten -- producing e.g. ``nested.zip/C/Windows/.../System.evtx``.
    """
    existing = record.kronos.source_path
    full_path = f"{member_path}/{existing}" if existing else member_path
    updated_kronos = record.kronos.model_copy(
        update={"source_path": full_path, "container_sha256": evidence.sha256}
    )
    return record.model_copy(update={"kronos": updated_kronos})
