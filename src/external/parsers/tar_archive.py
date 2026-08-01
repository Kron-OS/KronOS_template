"""TarArchiveParser: explodes a tar container (e.g. a tar-wrapped disk-image
bundle, or UAC's ``.tar.gz`` triage output once uncompressed) into inner
artifacts and recursively re-dispatches each through the same
``ParserRegistry`` -- the exact same recursion pattern ``ZipArchiveParser``
(archive.py) already established, per this repo's own governance
(``CLAUDE.md`` §G.1 / ``docs/NEXTGEN_SOC_ROADMAP.md`` E1): "Follow the
ZipArchiveParser recursion pattern; do not invent a parallel mechanism."

Real, reproduced incident this closes: a ``forensic2.E01``-named evidence
file was actually a **tar archive** containing ``image.dd`` (a raw disk
image) and ``memory.dmp``. Nothing in this codebase recognised the tar
wrapping, so the raw tar bytes were fed straight at Plaso's dfVFS
whole-image path, dfVFS found no partition table (the file starts with a
tar header, not a disk image), and **zero timeline events were extracted**
-- a silent, total data-loss failure for exactly this composite-package
shape.

Registered FIRST in ``ParserRegistry`` (alongside ``ZipArchiveParser`` --
see ``src/external/dependencies.py::get_parser_registry``), ahead of
``PlasoParser``/anything else that could otherwise misclaim the raw tar
bytes. Ordering relative to ``ZipArchiveParser`` itself does not matter --
tar (``ustar`` at offset 257) and zip (``PK\\x03\\x04`` at offset 0) claim
disjoint magic-byte regions, verified by inspection, not assumed.

Python's ``tarfile`` module has a well-documented extraction-footgun
history (CVE-2007-4559 zip/tar-slip via ``extractall()``, plus GNU sparse
member expansion): this module never calls ``extractall()`` and never
trusts a member's path or declared size. Members are read individually via
``extractfile()`` with a bounded ``read(cap + 1)`` -- exactly mirroring how
``archive.py`` never trusts ``ZipInfo.file_size`` -- so a maliciously
inflated (including GNU sparse) member is caught the same way a zip bomb
is. Depth/count/byte budgets are the *same shared* ``ContextVar``-backed
state ``archive.py`` uses (``_container_common.py``), not an independent
copy, so a zip-in-tar-in-zip nesting tree can't reset either counter by
alternating container type.

Only plain (uncompressed) ``ustar``/GNU/PAX-format tar is in scope here --
verified via ``supports()``'s magic-byte check at the real, fixed ustar
offset (257). A ``.tar.gz`` is gzip bytes at offset 0 (magic ``\\x1f\\x8b``)
with the *compressed* tar header buried inside, so it does not match this
parser's magic check and is out of scope for this item (flagged in
``reviews/DFIR_Artifact_Landscape.md`` as a follow-up for UAC output,
per docs/NEXTGEN_SOC_ROADMAP.md's E1 entry).
"""

from __future__ import annotations

import logging
import tarfile
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING

from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import ParsingError
from src.external.parsers._container_common import (
    ExtractionBudget,
    budget_var,
    depth_var,
    is_unsafe_member_path,
    stamp_source_path,
)

if TYPE_CHECKING:
    from src.application.parser_registry import ParserRegistry

logger = logging.getLogger(__name__)

# ustar magic at the fixed POSIX-mandated header offset 257. Verified on this
# host against real archives, not guessed:
#   - GNU tar 1.35 (`tar -cf`, this repo's dev host default)  -> b"ustar  \x00"
#   - Python's own `tarfile` module (DEFAULT_FORMAT=PAX_FORMAT since 3.8,
#     what `tests/` fixtures and most modern tooling -- incl. UAC -- produce)
#     -> b"ustar\x0000"
# Both share the common 5-byte "ustar" prefix -- confirmed identical to
# `tarfile.GNU_MAGIC`/`tarfile.POSIX_MAGIC`'s own first 5 bytes (Python 3.14
# stdlib, the interpreter pinned for this repo's venv). Pre-POSIX (V7) tar
# has no magic field at all -- out of scope: every tar producer a real DFIR
# workflow encounters on a "reasonably current Linux/macOS" (GNU tar, BSD
# tar, Python tarfile, UAC) defaults to ustar-compatible headers.
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"

MAX_CONTAINER_DEPTH = 3
MAX_MEMBER_COUNT = 50_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 4 * 1024**3  # 4 GiB
MAX_PER_FILE_UNCOMPRESSED_BYTES = 1024**3  # 1 GiB -- matches ZipArchiveParser's own cap


class TarArchiveParser(ForensicParser):
    """Explodes a tar archive into inner artifacts, re-dispatching each
    through the injected ``ParserRegistry``.

    Must be registered FIRST in that same registry, alongside
    ``ZipArchiveParser`` (see ``src/external/dependencies.py::
    get_parser_registry``): first-match-wins detection means it claims
    every tar before any other parser gets a chance, and its own recursive
    ``get_parser()`` calls transparently support tar-in-tar (and
    tar-in-zip/zip-in-tar) nesting, bounded by the shared
    ``MAX_CONTAINER_DEPTH`` state in ``_container_common.py``.
    """

    def __init__(self, registry: ParserRegistry) -> None:
        self._registry = registry

    @property
    def parser_name(self) -> str:
        return "tar-archive"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        # Always HEAVY: an inner member may require Plaso (a raw disk image,
        # registry hive, prefetch, SQLite) -- mirrors ZipArchiveParser's own
        # reasoning exactly (see that class's parser_type docstring).
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        end = _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)
        return len(header_bytes) >= end and header_bytes[_TAR_MAGIC_OFFSET:end] == _TAR_MAGIC

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
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
        try:
            with tempfile.NamedTemporaryFile(suffix=".tar", delete=False) as tmp:
                async for chunk in stream:
                    tmp.write(chunk)
                tmp_path = tmp.name

            try:
                async for record in self._walk_tar(tmp_path, evidence, tenant, budget):
                    yield record
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        finally:
            depth_var.reset(depth_token)
            if owns_budget:
                budget_var.set(None)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _walk_tar(
        self,
        tar_path: str,
        evidence: Evidence,
        tenant: TenantContext,
        budget: ExtractionBudget,
    ) -> AsyncIterator[TimelineRecord]:
        try:
            # mode="r:" -- plain tar only, no transparent gzip/bz2/lzma
            # decompression. Our own supports() only ever claims files whose
            # *uncompressed* ustar header is visible at offset 257, so a
            # compressed stream should never reach here; being explicit
            # keeps this parser's actual behaviour matched to what its
            # magic-byte detection promises, rather than silently trusting
            # tarfile's "r" auto-detect to make the same decision twice.
            tf = tarfile.open(tar_path, mode="r:")
        except tarfile.TarError as exc:
            raise ParsingError(
                "Not a valid tar archive",
                context={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
            ) from exc

        with tf:
            for member in tf.getmembers():
                if not member.isfile():
                    # Directories, symlinks, hardlinks, devices, FIFOs: none
                    # carry dispatchable file content, and symlink/hardlink
                    # targets are exactly the documented tarfile traversal
                    # footgun (CVE-2007-4559-class) -- never resolved, just
                    # skipped.
                    continue
                if is_unsafe_member_path(member.name) or (
                    member.linkname and is_unsafe_member_path(member.linkname)
                ):
                    logger.warning(
                        "tar_member_path_rejected",
                        extra={"evidence_id": str(evidence.evidence_id), "member": member.name},
                    )
                    continue

                # Never trust TarInfo.size (a malicious/GNU-sparse archive
                # can report far less than what actually reads back out) --
                # bound the actual read instead, exactly mirroring
                # ZipArchiveParser's ZipInfo.file_size distrust.
                member_fp = tf.extractfile(member)
                if member_fp is None:
                    continue
                with member_fp:
                    data = member_fp.read(MAX_PER_FILE_UNCOMPRESSED_BYTES + 1)
                if len(data) > MAX_PER_FILE_UNCOMPRESSED_BYTES:
                    logger.warning(
                        "tar_member_too_large_skipped",
                        extra={"evidence_id": str(evidence.evidence_id), "member": member.name},
                    )
                    continue

                budget.charge(
                    len(data),
                    evidence,
                    max_member_count=MAX_MEMBER_COUNT,
                    max_total_bytes=MAX_TOTAL_UNCOMPRESSED_BYTES,
                )

                async for record in self._dispatch_member(member.name, data, evidence, tenant):
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
            # Same "recognised container member, no parser yet" precedent
            # ZipArchiveParser already established (zip_member_no_parser):
            # log and move on, never raise. This is exactly the case
            # `memory.dmp` hits today (Volatility support is a separate,
            # not-yet-built roadmap item, E5) -- it must not crash the
            # recursive extraction or silently vanish without a trace.
            logger.info(
                "tar_member_no_parser",
                extra={"evidence_id": str(evidence.evidence_id), "member": member_path},
            )
            return

        async def _one_shot() -> AsyncIterator[bytes]:
            yield data

        async for record in parser.parse(_one_shot(), evidence, tenant):
            yield stamp_source_path(record, member_path, evidence)
