"""Shared container-recursion defenses for archive-unwrapping parsers.

``ZipArchiveParser`` (archive.py) and ``TarArchiveParser`` (tar_archive.py)
both explode a container into member files and recursively re-dispatch each
member through the same ``ParserRegistry`` (see archive.py's module
docstring for the full recursive-unwrap design rationale). Both containers
pose the *identical* "container bomb" and "path traversal" risks, so the
shared runtime state -- current recursion depth and the cumulative
files/bytes charged against the whole extraction tree's budget -- lives
here, as module-level ``ContextVar``s imported by both parser modules,
rather than each parser keeping an independent copy.

This closes a real bypass that two *independent* budgets would not: a
zip-in-tar-in-zip (or any alternating-container-type) nesting tree could
not reset either counter just by switching container *type* partway down,
since both parsers charge into the very same ``ContextVar``-backed budget
object and increment the very same shared depth counter.

Each parser module still owns its own ``MAX_CONTAINER_DEPTH`` /
``MAX_MEMBER_COUNT`` / ``MAX_TOTAL_UNCOMPRESSED_BYTES`` /
``MAX_PER_FILE_UNCOMPRESSED_BYTES`` constants (matching the pre-existing,
test-monkeypatched convention ``archive.py`` already established) -- only
the counters they check *against* are shared.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass

from src.domain.artifact import StructuredArtifact
from src.domain.evidence import Evidence
from src.domain.timeline import EvidenceProvenance, TimelineRecord
from src.exceptions import ParsingError


@dataclass
class ExtractionBudget:
    """Cumulative files/bytes charged across one whole recursive extraction tree."""

    files_used: int = 0
    bytes_used: int = 0

    def charge(
        self,
        n_bytes: int,
        evidence: Evidence,
        *,
        max_member_count: int,
        max_total_bytes: int,
    ) -> None:
        """Charge one member's decompressed/extracted size against the shared budget.

        Raises ParsingError once either the calling parser's own configured
        member-count or total-bytes ceiling is exceeded by the *aggregate*
        (cross-container-type) total.
        """
        self.files_used += 1
        self.bytes_used += n_bytes
        if self.files_used > max_member_count:
            raise ParsingError(
                "Container exceeds maximum member count",
                context={"evidence_id": str(evidence.evidence_id), "limit": max_member_count},
            )
        if self.bytes_used > max_total_bytes:
            raise ParsingError(
                "Container exceeds maximum total extracted bytes",
                context={"evidence_id": str(evidence.evidence_id), "limit": max_total_bytes},
            )


# One shared budget per top-level evidence parse (one Celery task == one
# asyncio task == one context), so nested containers -- zip, tar, or any
# combination -- can't each locally pass a per-call check while the
# aggregate explodes. Reset to None when the outermost archive parser's
# parse() call (the one that created it) returns.
budget_var: ContextVar[ExtractionBudget | None] = ContextVar(
    "_kronos_container_budget", default=None
)
# Shared across container *types*: a tar containing a zip containing a tar
# still only gets MAX_CONTAINER_DEPTH levels total, not per-type.
depth_var: ContextVar[int] = ContextVar("_kronos_container_depth", default=0)


def is_unsafe_member_path(name: str) -> bool:
    """Reject zip-slip/tar-slip paths: absolute, or containing a '..' segment."""
    if name.startswith("/") or name.startswith("\\"):
        return True
    normalized = name.replace("\\", "/")
    return any(part == ".." for part in normalized.split("/"))


def stamp_source_path(
    record: TimelineRecord, member_path: str, evidence: Evidence
) -> TimelineRecord:
    """Attach/extend the record's kronos.source_path with this container level.

    A leaf parser's own output has ``source_path`` unset (None); a nested
    container parser's own output already carries the inner container's own
    member path, so this level's member_path is prepended rather than
    overwritten -- producing e.g. ``outer.tar/inner.zip/C/Windows/x.evtx``.

    Container parsers only ever recurse into file-based evidence, never
    stream telemetry, so ``record.kronos`` is always ``EvidenceProvenance``
    here -- real mypy type-narrowing (``kronos`` is the
    ``EvidenceProvenance | StreamProvenance`` union since roadmap D4), not
    defensive dead code.
    """
    assert isinstance(record.kronos, EvidenceProvenance)  # noqa: S101
    existing = record.kronos.source_path
    full_path = f"{member_path}/{existing}" if existing else member_path
    updated_kronos = record.kronos.model_copy(
        update={"source_path": full_path, "container_sha256": evidence.sha256}
    )
    return record.model_copy(update={"kronos": updated_kronos})


def stamp_artifact_source_path(
    artifact: StructuredArtifact, member_path: str, evidence: Evidence
) -> StructuredArtifact:
    """``StructuredArtifact`` analogue of :func:`stamp_source_path` (roadmap E3).

    Same "prepend this level's member_path, extend rather than overwrite"
    behavior as the ``TimelineRecord`` version above -- needed now that
    container parsers produce ``StructuredArtifact`` output too (YARA
    matches), not just ``TimelineRecord``, when a container member is itself
    a nested container that ``ZipArchiveParser``/``TarArchiveParser``
    recursively re-scans.
    """
    existing = artifact.kronos.source_path
    full_path = f"{member_path}/{existing}" if existing else member_path
    updated_kronos = artifact.kronos.model_copy(
        update={"source_path": full_path, "container_sha256": evidence.sha256}
    )
    return artifact.model_copy(update={"kronos": updated_kronos})
