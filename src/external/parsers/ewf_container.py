"""EwfContainerParser: unwraps an EWF (E01/Ex01) container's real media
payload and re-dispatches it through the same ``ParserRegistry`` recursion
pattern ``ZipArchiveParser``/``TarArchiveParser`` already established
(``CLAUDE.md`` §G.1: "follow the ZipArchiveParser recursion pattern; do
not invent a parallel mechanism").

**Real, reproduced incident this closes** (case
43097ab0-aae3-4968-915b-8f0229ac3865, evidence "forensic2"): a genuine
``EVF\\x09\\x0d\\x0a\\xff\\x00``-signed EWF file was routed to
``PlasoParser``, which feeds it straight to dfVFS's own whole-disk-image
walk expecting a partition table -- but its real media payload turned out
to be a **tar archive** containing ``image.dd`` (a raw disk image) and
(implicitly, per the same shape ``TarArchiveParser``'s own docstring
already documents) a ``memory.dmp``. dfVFS finds no partition table (the
first bytes are a tar header, not a boot sector) and silently produces
zero timeline events -- verified live via ``poc/ewf_memory_extraction/``:
extracting the real media through ``pyewf`` and inspecting the first 512
bytes shows a genuine POSIX ``ustar`` header (magic at the real, fixed
offset 257; filename field reads ``"image.dd"``), not raw memory or a
disk superblock at all. Running volatility3's own automagic directly
against those same extracted bytes finds **zero** DTB hits -- decisive
confirmation this is not memory, unlike the still-separately-diagnosed
ch2.dmp/contact_me.dmp case (see ``VolatilityModule``'s own docstring),
which DOES show a real DTB.

**Why a new parser, not a change to PlasoParser**: PlasoParser's own EWF
handling is correct and must be preserved unchanged for the common case
(a genuine EWF-wrapped disk image, no extra container inside) --
``TarArchiveParser``/``ZipArchiveParser`` themselves already fully handle
a raw tar/zip file at the top level; the only genuinely missing link is
one layer higher: recognising when an *EWF's own decoded media* is itself
a known container, and only then redirecting into that same existing
recursion instead of Plaso's whole-image walk. Once redirected,
``TarArchiveParser`` finds ``image.dd`` (already routed to Plaso's own
raw-disk-image path, roadmap E1) and ``memory.dmp`` (already routed to
``VolatilityModule`` via its extension-based ``supports()``, roadmap E5)
with **zero further code changes** to either -- both were already fully
wired, just unreachable because nothing unwrapped the outer EWF layer.

**No new dependency.** ``pyewf`` (package ``libewf-python==20240506``) is
already installed in ``celery-worker-plaso`` -- a transitive dependency of
``dfvfs`` (20260731), which Plaso (20260512) already requires. Confirmed
live: ``docker exec celery-worker-plaso-1 python3 -c "import pyewf;
print(pyewf.get_version())"`` -> ``20240506``. No official pyewf usage doc
was reachable from this sandboxed environment; the exact installed
module's own introspected API (``dir(pyewf)``, ``dir(pyewf.handle())``)
was used as ground truth for this exact pinned version instead, verified
against the real forensic2 bytes (``poc/ewf_memory_extraction/``), not
guessed.

**Registered ahead of PlasoParser** (``src/external/dependencies.py::
get_parser_registry``) so it intercepts every EWF-magic file first,
mirroring ``TarArchiveParser``/``ZipArchiveParser``'s own "registered
FIRST" convention. Shares their exact recursion-depth/extraction-budget
``ContextVar``s (``_container_common.py``) -- an EWF-in-EWF (or
EWF-wrapping-a-tar-wrapping-a-zip, etc.) nesting tree is bounded by the
same aggregate limits, not a second independent copy. When the decoded
media does NOT match any registered parser (the common, correct case --
a genuine raw disk image or raw memory, which dfVFS's own signature scan
already recognises unprompted), this class falls straight back to
``PlasoParser`` on the **original, un-decoded EWF bytes** -- today's
existing, already-correct behaviour, completely unchanged.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING

from src.application.parsing import ForensicParser, ParserType
from src.domain.artifact import StructuredArtifact
from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import ParsingError
from src.external.parsers._container_common import (
    EWF_MAGIC,
    ExtractionBudget,
    budget_var,
    depth_var,
    stamp_artifact_source_path,
    stamp_source_path,
)

if TYPE_CHECKING:
    from src.application.parser_registry import ParserRegistry

logger = logging.getLogger(__name__)

MAX_CONTAINER_DEPTH = 3
# A media peek only needs enough bytes to cover every registered magic-byte
# check's own fixed offset -- TarArchiveParser's ustar check is the deepest
# at offset 257 (see that module's own _TAR_MAGIC_OFFSET); 8192 matches the
# header-buffer size every other parser's supports() is already called with
# elsewhere in this codebase (ParsingOrchestrationService._detect_parser's
# own _HEADER_BYTES), so this peek sees exactly as much as a normal
# non-EWF-wrapped upload of the same inner content would.
_PEEK_BYTES = 8192


class EwfContainerParser(ForensicParser):
    """Unwraps EWF, re-dispatches a recognised inner container, else
    delegates straight to PlasoParser on the original EWF bytes."""

    def __init__(self, registry: ParserRegistry, plaso_parser: ForensicParser) -> None:
        self._registry = registry
        self._plaso_parser = plaso_parser

    @property
    def parser_name(self) -> str:
        return "ewf-container"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        # Always HEAVY: the fallback path hands off to PlasoParser (itself
        # always HEAVY) and the redirect path may hand off to TarArchiveParser
        # (also always HEAVY) -- mirrors those classes' own reasoning exactly.
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return header_bytes.startswith(EWF_MAGIC)

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        routed = self._route(stream, evidence, tenant, want_artifacts=False)
        async for record, member_path in routed:
            assert isinstance(record, TimelineRecord)  # noqa: S101 -- want_artifacts=False guarantees this
            yield stamp_source_path(record, member_path, evidence) if member_path else record

    async def extract_artifacts(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[StructuredArtifact]:
        routed = self._route(stream, evidence, tenant, want_artifacts=True)
        async for artifact, member_path in routed:
            assert isinstance(artifact, StructuredArtifact)  # noqa: S101 -- want_artifacts=True guarantees this
            yield (
                stamp_artifact_source_path(artifact, member_path, evidence)
                if member_path
                else artifact
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _route(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
        *,
        want_artifacts: bool,
    ) -> AsyncIterator[tuple[TimelineRecord | StructuredArtifact, str | None]]:
        depth = depth_var.get()
        if depth >= MAX_CONTAINER_DEPTH:
            raise ParsingError(
                "Container nesting exceeds maximum depth",
                context={
                    "evidence_id": str(evidence.evidence_id),
                    "max_depth": MAX_CONTAINER_DEPTH,
                },
            )

        budget = budget_var.get()
        owns_budget = budget is None
        if owns_budget:
            budget = ExtractionBudget()
            budget_var.set(budget)

        depth_token = depth_var.set(depth + 1)
        ewf_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".ewf_container", delete=False) as tmp:
                async for chunk in stream:
                    tmp.write(chunk)
                ewf_path = tmp.name

            peeked = self._peek_media(evidence, ewf_path)
            inner_parser = None
            if peeked is not None:
                inner_parser = self._registry.get_parser(
                    "extracted", "application/octet-stream", peeked
                )
                # Delegating an EWF-magic-again match or a PlasoParser match
                # back through this same "extract media, feed it forward"
                # path would just duplicate the fallback branch below for
                # no benefit (PlasoParser already opens the ORIGINAL EWF
                # bytes directly via dfVFS, which is strictly cheaper than
                # this class re-decoding the media itself first) -- only a
                # genuinely different parser (TarArchiveParser being the
                # real, live-confirmed case) is worth the extra extraction.
                if inner_parser is self._plaso_parser or isinstance(
                    inner_parser, EwfContainerParser
                ):
                    inner_parser = None

            if inner_parser is not None:
                media_path = self._extract_full_media(evidence, ewf_path)
                try:
                    member_label = f"{evidence.metadata.original_filename} (EWF media)"

                    async def _media_stream() -> AsyncIterator[bytes]:
                        with Path(media_path).open("rb") as f:
                            while chunk := f.read(4 * 1024 * 1024):
                                yield chunk

                    if want_artifacts:
                        async for artifact in inner_parser.extract_artifacts(
                            _media_stream(), evidence, tenant
                        ):
                            yield artifact, member_label
                    else:
                        async for record in inner_parser.parse(_media_stream(), evidence, tenant):
                            yield record, member_label
                finally:
                    Path(media_path).unlink(missing_ok=True)
                return

            # Fallback: genuine EWF disk image (or unrecognised media) --
            # today's existing, already-correct behaviour, unchanged.
            assert ewf_path is not None  # noqa: S101 -- always set above before this point
            fallback_ewf_path = ewf_path

            async def _original_stream() -> AsyncIterator[bytes]:
                with Path(fallback_ewf_path).open("rb") as f:
                    while chunk := f.read(4 * 1024 * 1024):
                        yield chunk

            if want_artifacts:
                async for artifact in self._plaso_parser.extract_artifacts(
                    _original_stream(), evidence, tenant
                ):
                    yield artifact, None
            else:
                async for record in self._plaso_parser.parse(_original_stream(), evidence, tenant):
                    yield record, None
        finally:
            if ewf_path is not None:
                Path(ewf_path).unlink(missing_ok=True)
            depth_var.reset(depth_token)
            if owns_budget:
                budget_var.set(None)

    @staticmethod
    def _peek_media(evidence: Evidence, ewf_path: str) -> bytes | None:
        """Cheaply read the first _PEEK_BYTES of the real decoded EWF
        media -- opening via pyewf and reading a bounded prefix is cheap
        regardless of the container's total size (no full decompression
        needed), verified live against the real 250 MB forensic2 file.
        Returns None (never raises) on any real EWF-open failure -- a
        corrupt/unreadable EWF must fall through to PlasoParser's own
        error handling, not abort here.
        """
        try:
            import pyewf  # noqa: PLC0415
        except ImportError:
            logger.warning("pyewf_not_installed", extra={"evidence_id": str(evidence.evidence_id)})
            return None

        handle = pyewf.handle()
        try:
            handle.open([ewf_path])
            peeked: bytes = handle.read(_PEEK_BYTES)
            return peeked
        except OSError as exc:
            logger.warning(
                "ewf_peek_failed",
                extra={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
            )
            return None
        finally:
            handle.close()

    @staticmethod
    def _extract_full_media(evidence: Evidence, ewf_path: str) -> str:
        """Extract the EWF's real, full media payload to a fresh temp file.

        Real, measured cost against the actual 250 MB forensic2 file
        (poc/ewf_memory_extraction/output.txt): sub-second read-and-write.
        """
        import pyewf  # noqa: PLC0415

        handle = pyewf.handle()
        try:
            handle.open([ewf_path])
            media_size = handle.get_media_size()
            with tempfile.NamedTemporaryFile(suffix=".ewf_media", delete=False) as out:
                remaining = media_size
                chunk_size = 4 * 1024 * 1024
                while remaining > 0:
                    chunk = handle.read(min(chunk_size, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
                return out.name
        finally:
            handle.close()
