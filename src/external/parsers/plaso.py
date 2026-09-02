"""PlasoParser: heavy forensic parser using Plaso in a Firecracker microVM.

Supports: Windows Registry (REGF), Prefetch, SRUM, SQLite artifacts,
Amcache, systemd journald, EML email archives, EWF (E01/Ex01) disk images,
and raw/unwrapped disk images (ext2/3/4, NTFS, FAT12/16/32) -- all via
Plaso's own dfVFS-based whole-image auto-detection, no separate
DiskImageExtractor needed.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext

logger = logging.getLogger(__name__)

# Magic bytes for formats Plaso specialises in.
_REGF_MAGIC = b"regf"
_PREFETCH_MAM_MAGIC = b"MAM"  # MAM-compressed prefetch: starts with MAM\x04 or MAM\x08
# Uncompressed prefetch: a 4-byte format-version field followed directly by
# the "SCCA" signature at offset 4 (e.g. Windows 10 version 17 files are
# \x11\x00\x00\x00SCCA...). Real-world prefetch is frequently *not*
# MAM-compressed — e.g. compression disabled, or already decompressed by
# whatever forensic tool extracted it — and MAM-only detection rejected
# those files outright ("No parser found for this evidence file"); verified
# against a real Windows 10 prefetch sample (see
# tests/fixtures/samples/real/, sourced from Plaso's own test corpus).
_PREFETCH_SCCA_MAGIC = b"SCCA"
_SQLITE_MAGIC = b"SQLite format 3"
_EVTX_MAGIC = b"ElfFile\x00"  # Windows Event Log -- see supports() docstring
# (Gap Audit Milestone VVVV) for why this is now claimed here directly
# rather than deferred to FastEvtxParser.
# EWF (E01/Ex01) disk image signature. Verified against a real image built
# with ewfacquirestream 20140816 (see tests/fixtures/samples/real/kape/
# NOTICE.md): log2timeline auto-detects an EWF path argument as a "storage
# media image" via dfVFS (already a real Plaso dependency, confirmed present
# in docker/Dockerfile.plaso-worker's venv) and walks every partition/
# filesystem inside it directly -- no separate DiskImageExtractor needed,
# same subprocess invocation as every other PlasoParser artifact.
_EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"

# Raw (unwrapped) disk image signatures -- no EWF/E01 container, a bare
# filesystem directly on the file (e.g. `image.dd`, `image.img`, `image.raw`).
# Real, reproduced gap (roadmap E1): a forensic2.E01-named evidence file was
# actually a tar archive containing exactly this shape (image.dd + a
# memory.dmp Plaso doesn't parse). Before this fix PlasoParser had no path
# for a bare raw image at all -- only EWF's own magic was recognised -- so
# even after TarArchiveParser correctly unwraps the tar, image.dd would
# still hit "no parser found" and silently vanish, reproducing the same
# zero-events failure one layer deeper.
#
# Verified for real (poc/tar_container_unwrapping/): a real log2timeline/
# psort run (plaso==20260512, the exact version pinned in
# docker/Dockerfile.plaso-worker) against real synthetic raw ext4, NTFS, and
# FAT16 images built on this host auto-detects each one as a "storage media
# image" via dfVFS with zero extra flags/config -- the exact same subprocess
# invocation this class already uses for EWF -- and emits real fs:stat
# events carrying the filesystem's own dfVFS type-indicator prefix
# (EXT:/NTFS:/FAT:, all three already present in
# src/external/sandbox/firecracker.py's _DFVFS_TYPE_PREFIXES). No separate
# DiskImageExtractor or dfVFS "RAW" type-indicator flag was needed; dfVFS's
# own source-analyzer signature scan already recognises these filesystem
# superblocks unprompted. Magic offsets below match validation.py's
# _MAGIC_TABLE entries exactly (same verification, not a second guess).
_EXT_FS_MAGIC = b"\x53\xef"  # ext2/3/4 superblock magic, fixed offset 1080
_NTFS_MAGIC = b"NTFS    "  # NTFS boot sector, fixed offset 3
_FAT16_MAGIC = b"FAT16   "  # FAT16 boot sector, fixed offset 54
_FAT12_MAGIC = b"FAT12   "  # FAT12 boot sector, fixed offset 54
_FAT32_MAGIC = b"FAT32   "  # FAT32 boot sector, fixed offset 82


class PlasoParser(ForensicParser):
    """Heavy forensic parser delegating to Plaso via Firecracker sandbox.

    Plaso can handle: Windows Registry, Prefetch, SRUM, SQLite, Amcache,
    journald, EML, and Windows Event Log (EVTX) -- including both a loose
    .evtx file and one embedded inside a disk image (E01/raw/etc).

    Gap Audit Milestone VVVV: EVTX used to be explicitly excluded here (a
    separate, faster `FastEvtxParser` handled loose .evtx uploads while any
    .evtx found *inside* a disk image still had to come through this class,
    since Plaso is the only parser that opens a whole image). That split
    meant the exact same artifact type -- a Windows Event Log -- produced
    two incompatible field shapes depending only on which container it
    happened to arrive in, a real, reported point of confusion when a KAPE
    zip (fast path) and its E01 twin (Plaso path) were compared side by
    side. `src/external/dependencies.py.get_parser_registry()` no longer
    registers `FastEvtxParser` at all, so this class's own `supports()` is
    now the sole EVTX claimant -- confirmed for real
    (`poc/plaso_evtx_direct/`) that plaso==20260512's log2timeline handles
    a standalone .evtx path exactly the same way it already handled one
    embedded in an image, no extra flags needed.
    """

    # Extensions that Plaso handles better than generic parsers.
    _SUPPORTED_EXTENSIONS: frozenset[str] = frozenset(
        {
            "dat",  # Windows SRUM / Amcache / Shimcache
            "db",
            "sqlite",
            "sqlite3",
            "hve",
            "hiv",  # Registry hives
        }
    )

    @property
    def parser_name(self) -> str:
        return "plaso"

    @property
    def parser_version(self) -> str:
        return "20260512"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Return True for formats Plaso handles."""
        # Windows Event Log -- see class docstring (Gap Audit Milestone
        # VVVV) for why this is claimed here and not by FastEvtxParser.
        if header_bytes.startswith(_EVTX_MAGIC):
            return True

        # Registry hive
        if header_bytes.startswith(_REGF_MAGIC):
            return True

        # Prefetch files: MAM-compressed container, or uncompressed SCCA.
        if header_bytes[:3] == _PREFETCH_MAM_MAGIC:
            return True
        if header_bytes[4:8] == _PREFETCH_SCCA_MAGIC:
            return True

        # SQLite databases (SRUM, Amcache, browser history, etc.)
        if header_bytes.startswith(_SQLITE_MAGIC):
            return True

        # journald binary journals
        if header_bytes.startswith(b"\xbe\xb9\xb0\xd9\x70\x14\x1e\x2d"):
            return True

        # EWF disk image (E01/Ex01) -- whole-image fallback, see _EWF_MAGIC.
        if header_bytes.startswith(_EWF_MAGIC):
            return True

        # Raw (unwrapped) disk image -- ext2/3/4, NTFS, or FAT filesystem
        # magic at their real, fixed, non-zero offsets (see the magic
        # constants' own comments above for verification detail).
        if header_bytes[1080:1082] == _EXT_FS_MAGIC:
            return True
        if header_bytes[3:11] == _NTFS_MAGIC:
            return True
        if header_bytes[54:62] in (_FAT16_MAGIC, _FAT12_MAGIC):
            return True
        if header_bytes[82:90] == _FAT32_MAGIC:
            return True

        ext = Path(filename).suffix.lstrip(".").lower()
        return ext in self._SUPPORTED_EXTENSIONS

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Write evidence to a temp file and invoke Plaso via FirecrackerLauncher."""
        from src.external.sandbox.firecracker import FirecrackerLauncher  # noqa: PLC0415

        with tempfile.NamedTemporaryFile(
            suffix=Path(evidence.metadata.original_filename).suffix,
            delete=False,
        ) as tmp:
            async for chunk in stream:
                tmp.write(chunk)
            tmp_path = tmp.name

        logger.info(
            "plaso_temp_file_ready",
            extra={"evidence_id": str(evidence.evidence_id), "path": tmp_path},
        )

        from src.config import Settings  # noqa: PLC0415

        settings = Settings()
        worker_path = Path(settings.plaso_worker_path) if settings.plaso_worker_path else None
        launcher = FirecrackerLauncher(worker_path=worker_path)

        # Gap Audit Milestone OO: previously the cleanup below ran only
        # after the `async for` loop completed normally -- any exception
        # during Plaso parsing (a Firecracker VM crash, a worker timeout)
        # or the consumer aborting early (e.g. a downstream enrichment/
        # ingest failure triggering this generator's own GeneratorExit)
        # propagated straight out, skipping the unlink entirely and
        # leaking the raw evidence bytes (potentially a whole disk image,
        # or a registry hive with real credentials) in the worker's local
        # /tmp indefinitely -- unlike ZipArchiveParser/TarArchiveParser,
        # which already wrap their own equivalent cleanup in try/finally.
        # FirecrackerLauncher.run() never touches evidence_path itself
        # (confirmed by reading firecracker.py -- it only ever reads from
        # the path, never unlinks it), so this parser is the sole owner of
        # this temp file's lifecycle.
        try:
            records = await launcher.run(
                evidence_path=tmp_path,
                evidence_id=str(evidence.evidence_id),
                case_id=str(evidence.metadata.case_id),
                org_id=str(evidence.metadata.org_id),
                org_alias=evidence.metadata.org_alias,
                sha256=evidence.sha256 or "",
                parser_name=self.parser_name,
                parser_version=self.parser_version,
            )
            async for record in records:
                yield record
        finally:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass
