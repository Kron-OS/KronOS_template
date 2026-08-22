"""Evidence validators: magic-byte, file-size, and chain composition."""

from __future__ import annotations

import io
import zipfile
from abc import ABC, abstractmethod

from src.exceptions import ValidationError

# The ZIP central-directory entry every JAR is required to carry.
_JAR_MANIFEST_ENTRY = "META-INF/MANIFEST.MF"

# ---------------------------------------------------------------------------
# Blocklisted file extensions (executables / scripts)
# ---------------------------------------------------------------------------

BLOCKED_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".jar", ".msi", ".com"}
)

# ---------------------------------------------------------------------------
# Magic-byte signatures for common forensic artefact types.
# Each entry: (offset, byte sequence, human-readable label)
# ---------------------------------------------------------------------------

_MAGIC_TABLE: list[tuple[int, bytes, str]] = [
    # Windows Event Log (EVTX)
    (0, b"ElfFile\x00", "evtx"),
    # Prefetch (MAM-compressed container)
    (0, b"MAM\x04", "prefetch"),
    # Prefetch (uncompressed): 4-byte format-version field then "SCCA" at
    # offset 4 -- real-world prefetch is frequently not MAM-compressed
    # (confirmed against a real Windows 10 sample, PlasoParser already
    # accepts this exact signature; this table was missing it, silently
    # 422-rejecting a valid artefact before the parser ever saw it).
    (4, b"SCCA", "prefetch-scca"),
    # SQLite (browser artefacts)
    (0, b"SQLite format 3\x00", "sqlite"),
    # EWF disk image (E01/Ex01) -- KAPE/forensic-imaging tool output. Verified
    # against a real image built with ewfacquirestream 20140816 (see
    # tests/fixtures/samples/real/kape/NOTICE.md); PlasoParser already routes
    # this magic to Plaso's dfVFS-based whole-image parsing.
    (0, b"EVF\x09\x0d\x0a\xff\x00", "ewf"),
    # GZIP (compressed logs, journald)
    (0, b"\x1f\x8b", "gzip"),
    # ZIP (container for many log formats)
    (0, b"PK\x03\x04", "zip"),
    # tar (ustar/GNU/PAX) -- container for tar-wrapped disk-image bundles
    # (roadmap E1: a forensic2.E01-named evidence file that was actually a
    # tar of image.dd + memory.dmp) and future UAC .tar.gz-after-decompress
    # triage output. Magic is the real POSIX-mandated "ustar" 5-byte prefix
    # at the fixed header offset 257 -- verified on this host against both
    # GNU tar 1.35's own output (b"ustar  \x00") and Python's own tarfile
    # module default PAX format (b"ustar\x0000"); both share this 5-byte
    # prefix (see TarArchiveParser's module docstring for the full byte
    # dump). Pre-POSIX (V7) tar has no magic at a fixed offset and is out of
    # scope -- every tar producer a real DFIR workflow encounters on a
    # reasonably current Linux/macOS (GNU tar, BSD tar, Python tarfile, UAC)
    # defaults to ustar-compatible headers.
    (257, b"ustar", "tar"),
    # Raw (unwrapped) disk images -- no EWF/E01 container, just a bare
    # filesystem directly on the file, e.g. `image.dd` found tar-wrapped
    # inside a mislabelled forensic2.E01 (roadmap E1). Real dfVFS (a Plaso
    # dependency, plaso==20260512 pinned in docker/Dockerfile.plaso-worker)
    # auto-detects all three of these filesystem types directly -- confirmed
    # by a real log2timeline/psort run against real synthetic images built
    # on this host (poc/tar_container_unwrapping/), each producing real
    # fs:stat timeline events with the filesystem's own dfVFS type-indicator
    # prefix (EXT:/NTFS:/FAT:) in display_name -- no separate
    # DiskImageExtractor needed, same as the existing EWF entry below.
    # ext2/3/4 superblock magic 0xEF53 (little-endian bytes "53 ef"), fixed
    # at byte offset 1080 regardless of block size.
    (1080, b"\x53\xef", "ext-filesystem"),
    # NTFS boot sector "NTFS    " (8 bytes, note the 4 trailing spaces) at
    # byte offset 3.
    (3, b"NTFS    ", "ntfs-filesystem"),
    # FAT12/FAT16 boot sector "FAT12   "/"FAT16   " (8 bytes) at offset 54.
    (54, b"FAT16   ", "fat16-filesystem"),
    (54, b"FAT12   ", "fat12-filesystem"),
    # FAT32 boot sector "FAT32   " (8 bytes) at offset 82.
    (82, b"FAT32   ", "fat32-filesystem"),
    # PDF (reports)
    (0, b"%PDF", "pdf"),
    # JSON / NDJSON — no magic bytes; identified by extension only
    # CSV / TXT — no magic bytes; identified by extension only
]

# Content types that are always accepted regardless of magic bytes
# (text-based formats that have no distinctive header).
_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt", ".xml"}
)

# Raw physical memory dumps (roadmap E5, VolatilityModule) -- unlike EWF/ustar,
# these have no standard magic bytes at a fixed offset. Verified for real
# against the classic `cridex.vmem` sample (poc/volatility_memory_module/
# README.md): its first 2 KiB carry no Microsoft crash-dump magic
# (PAGEDUMP/PAGEDU64) and no LiME magic -- just raw kernel page-table bytes
# with no header at all. Extension is the only honest signal this format
# family has; do not invent a fake signature. Same bypass shape as
# _TEXT_EXTENSIONS (skips the magic-table check entirely, extension alone
# decides), not a parallel mechanism.
_MEMORY_DUMP_EXTENSIONS: frozenset[str] = frozenset({".vmem", ".mem", ".raw", ".dmp", ".lime"})


class EvidenceValidator(ABC):
    """Abstract evidence validator.  Raise ValidationError to reject a file."""

    @abstractmethod
    def validate(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        header_bytes: bytes,
    ) -> None:
        """Raise ValidationError if the file fails validation."""


class ExtensionValidator(EvidenceValidator):
    """Reject files whose extension appears on the blocklist."""

    def validate(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        header_bytes: bytes,
    ) -> None:
        ext = _extension(filename)
        if ext in BLOCKED_EXTENSIONS:
            raise ValidationError(
                f"File extension '{ext}' is not permitted",
                context={"filename": filename, "extension": ext},
            )


class MagicByteValidator(EvidenceValidator):
    """Validate file type via magic-byte signatures.

    Text-based forensic formats (.json, .log, .csv, etc.) pass automatically
    because they carry no binary header.  Binary formats must match at least
    one entry in the magic table *or* have a recognised text extension.
    """

    def validate(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        header_bytes: bytes,
    ) -> None:
        ext = _extension(filename)

        # Text-based formats: no binary magic — accept on extension alone.
        if ext in _TEXT_EXTENSIONS:
            return

        # Raw memory dumps: no verified magic bytes exist (see
        # _MEMORY_DUMP_EXTENSIONS's own comment) -- accept on extension alone,
        # same as the text-format bypass above.
        if ext in _MEMORY_DUMP_EXTENSIONS:
            return

        # Empty file is always invalid.
        if not header_bytes:
            raise ValidationError(
                "File is empty or header could not be read",
                context={"filename": filename},
            )

        # Check magic table.
        for offset, signature, _label in _MAGIC_TABLE:
            end = offset + len(signature)
            if len(header_bytes) >= end and header_bytes[offset:end] == signature:
                return

        raise ValidationError(
            "File magic bytes do not match any accepted forensic format",
            context={"filename": filename, "extension": ext},
        )


class ZipJarDisguiseValidator(EvidenceValidator):
    """Reject a ZIP-signature file whose central directory is really a JAR.

    A blocklisted ``.jar`` renamed to ``.zip`` (or any other extension)
    carries an identical ``PK\\x03\\x04`` magic signature to a generic ZIP
    (EVID-5) — extension and magic-byte checks alone cannot tell them apart.
    This inspects the ZIP central directory for ``META-INF/MANIFEST.MF``,
    the entry every JAR is required to carry, and rejects the file
    regardless of its declared extension.

    Best-effort by construction: it only sees the header buffer the caller
    supplies (bounded, not the whole object — evidence files are allowed up
    to ~1 GB and validation must not require buffering that much before the
    AV scan runs).  A ZIP whose central directory doesn't fit inside that
    buffer cannot be inspected this way and is passed through to the
    (independent, full-file) ClamAV scan as defence in depth.
    """

    def validate(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        header_bytes: bytes,
    ) -> None:
        if not header_bytes.startswith(b"PK\x03\x04") and not header_bytes.startswith(
            b"PK\x05\x06"
        ):
            return  # not a zip-signature file

        try:
            with zipfile.ZipFile(io.BytesIO(header_bytes)) as zf:
                names = zf.namelist()
        except zipfile.BadZipFile:
            # Buffer doesn't contain a complete/valid ZIP structure (either
            # truncated because the file is larger than the header buffer,
            # or genuinely corrupt) — nothing conclusive to check here.
            return

        if _JAR_MANIFEST_ENTRY in names:
            raise ValidationError(
                "File is a Java archive (JAR) disguised with a non-.jar extension",
                context={"filename": filename, "extension": _extension(filename)},
            )


class FileSizeValidator(EvidenceValidator):
    """Reject files that exceed the configured maximum size."""

    def __init__(self, max_bytes: int) -> None:
        self._max_bytes = max_bytes

    def validate(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        header_bytes: bytes,
    ) -> None:
        if size_bytes > self._max_bytes:
            raise ValidationError(
                f"File size {size_bytes} exceeds maximum of {self._max_bytes} bytes",
                context={
                    "filename": filename,
                    "size_bytes": size_bytes,
                    "max_bytes": self._max_bytes,
                },
            )
        if size_bytes < 0:
            raise ValidationError(
                "File size must be non-negative",
                context={"filename": filename, "size_bytes": size_bytes},
            )


class ValidatorChain(EvidenceValidator):
    """Run a sequence of validators; stop and raise on the first failure."""

    def __init__(self, *validators: EvidenceValidator) -> None:
        self._validators = validators

    def validate(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        header_bytes: bytes,
    ) -> None:
        for validator in self._validators:
            validator.validate(filename, content_type, size_bytes, header_bytes)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extension(filename: str) -> str:
    """Return the lowercased file extension including the leading dot."""
    dot = filename.rfind(".")
    if dot == -1:
        return ""
    return filename[dot:].lower()


def default_validator_chain(max_upload_bytes: int) -> ValidatorChain:
    """Build the standard validator chain used in production."""
    return ValidatorChain(
        ExtensionValidator(),
        FileSizeValidator(max_upload_bytes),
        MagicByteValidator(),
        ZipJarDisguiseValidator(),
    )
