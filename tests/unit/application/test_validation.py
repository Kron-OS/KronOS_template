"""Unit tests for evidence validators."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from src.application.validation import (
    BLOCKED_EXTENSIONS,
    ExtensionValidator,
    FileSizeValidator,
    MagicByteValidator,
    ValidatorChain,
    ZipJarDisguiseValidator,
    default_validator_chain,
)
from src.exceptions import ValidationError

# ---------------------------------------------------------------------------
# Magic byte fixtures
# ---------------------------------------------------------------------------

EVTX_HEADER = b"ElfFile\x00" + b"\x00" * 100
SQLITE_HEADER = b"SQLite format 3\x00" + b"\x00" * 100
PDF_HEADER = b"%PDF-1.4\n" + b"\x00" * 100
GZIP_HEADER = b"\x1f\x8b" + b"\x00" * 100
ZIP_HEADER = b"PK\x03\x04" + b"\x00" * 100
PREFETCH_HEADER = b"MAM\x04" + b"\x00" * 100
REAL_SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples" / "real"
UNKNOWN_BINARY = b"\xff\xfe\x00\x01" * 100  # unrecognised binary


def _real_tar_header(fmt: int) -> bytes:
    """Build a real tar archive via Python's own tarfile module and return
    its first 8192 bytes (matching production's real header-read window,
    src/application/evidence_intake.py's own _HEADER_BYTES=65536 truncated
    further here since a single ustar header block is only 512 bytes)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        info = tarfile.TarInfo(name="a.txt")
        data = b"hello"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()[:8192]


# Real ext2/3/4 superblock magic 0xEF53 at the real, fixed offset 1080 --
# verified on this host by building an actual ext4 filesystem
# (`mke2fs -t ext4`) and inspecting the raw bytes with `xxd` (see
# poc/tar_container_unwrapping/README.md for the full transcript).
EXT4_HEADER = b"\x00" * 1080 + b"\x53\xef" + b"\x00" * 100
# Real NTFS boot sector signature "NTFS    " at the real, fixed offset 3 --
# verified the same way with `mkntfs`.
NTFS_HEADER = b"\xeb\x52\x90" + b"NTFS    " + b"\x00" * 100
# Real FAT16/FAT32 boot sector signatures at their real, fixed offsets (54
# and 82) -- verified the same way with `mkfs.vfat -F 16`/`-F 32`.
FAT16_HEADER = b"\x00" * 54 + b"FAT16   " + b"\x00" * 100
FAT32_HEADER = b"\x00" * 82 + b"FAT32   " + b"\x00" * 100


class TestExtensionValidator:
    validator = ExtensionValidator()

    def test_allows_evtx(self) -> None:
        self.validator.validate("test.evtx", "application/octet-stream", 1024, EVTX_HEADER)

    def test_allows_log(self) -> None:
        self.validator.validate("system.log", "text/plain", 512, b"")

    def test_allows_json(self) -> None:
        self.validator.validate("cloudtrail.json", "application/json", 256, b"")

    def test_blocks_exe(self) -> None:
        with pytest.raises(ValidationError, match="extension"):
            self.validator.validate("malware.exe", "application/octet-stream", 1024, b"")

    def test_blocks_dll(self) -> None:
        with pytest.raises(ValidationError):
            self.validator.validate("evil.dll", "application/octet-stream", 1024, b"")

    def test_blocks_ps1(self) -> None:
        with pytest.raises(ValidationError):
            self.validator.validate("attack.ps1", "text/plain", 256, b"")

    def test_all_blocked_extensions(self) -> None:
        for ext in BLOCKED_EXTENSIONS:
            with pytest.raises(ValidationError):
                self.validator.validate(f"file{ext}", "application/octet-stream", 1024, b"")


class TestFileSizeValidator:
    def test_allows_file_at_limit(self) -> None:
        v = FileSizeValidator(max_bytes=1_000_000)
        v.validate("f.log", "text/plain", 1_000_000, b"")

    def test_rejects_file_over_limit(self) -> None:
        v = FileSizeValidator(max_bytes=1_000_000)
        with pytest.raises(ValidationError, match="exceeds maximum"):
            v.validate("big.log", "text/plain", 1_000_001, b"")

    def test_rejects_negative_size(self) -> None:
        v = FileSizeValidator(max_bytes=1_000_000)
        with pytest.raises(ValidationError):
            v.validate("f.log", "text/plain", -1, b"")

    def test_allows_zero_size(self) -> None:
        v = FileSizeValidator(max_bytes=1_000_000)
        v.validate("empty.log", "text/plain", 0, b"")


class TestMagicByteValidator:
    validator = MagicByteValidator()

    def test_accepts_evtx(self) -> None:
        self.validator.validate("sys.evtx", "application/octet-stream", 1024, EVTX_HEADER)

    def test_accepts_sqlite(self) -> None:
        self.validator.validate("history.db", "application/octet-stream", 1024, SQLITE_HEADER)

    def test_accepts_gzip(self) -> None:
        self.validator.validate("log.gz", "application/octet-stream", 1024, GZIP_HEADER)

    def test_accepts_mam_compressed_prefetch(self) -> None:
        self.validator.validate(
            "SVCHOST.EXE-1234.pf", "application/octet-stream", 1024, PREFETCH_HEADER
        )

    def test_accepts_uncompressed_scca_prefetch_real_sample(self) -> None:
        """Real bug found in poc/full_ingestion_test/: this validator only
        recognized MAM-compressed Prefetch, rejecting a genuine uncompressed
        Windows 10 Prefetch sample (SCCA signature at offset 4) that
        PlasoParser already supports -- finalize_upload 422'd before the
        parser ever ran. Uses the real sample, not a hand-crafted header."""
        header = (REAL_SAMPLES / "CMD.EXE-087B4001.pf").read_bytes()[:16]
        self.validator.validate("CMD.EXE-087B4001.pf", "application/octet-stream", 11986, header)

    def test_accepts_ewf_e01_real_sample(self) -> None:
        """A KAPE-style disk image (E01) must pass intake validation so it
        can reach PlasoParser's dfVFS-based whole-image routing -- uses a
        real EWF image built with ewfacquirestream (see
        tests/fixtures/samples/real/kape/NOTICE.md), not a hand-crafted
        header."""
        header = (REAL_SAMPLES / "kape" / "kape_triage.E01").read_bytes()[:16]
        self.validator.validate("kape_triage.E01", "application/octet-stream", 47764, header)

    def test_accepts_pdf(self) -> None:
        self.validator.validate("report.pdf", "application/octet-stream", 1024, PDF_HEADER)

    def test_accepts_real_gnu_tar(self) -> None:
        """A tar-wrapped disk-image bundle (roadmap E1: forensic2.E01 was
        actually a tar of image.dd + memory.dmp) must pass intake validation
        so it can reach TarArchiveParser -- uses a real tar built via
        Python's own tarfile module in GNU format, matching real GNU tar
        1.35 CLI output verified on this host (see tar_archive.py's module
        docstring for the full byte-level comparison), not a hand-crafted
        header."""
        header = _real_tar_header(tarfile.GNU_FORMAT)
        assert header[257:262] == b"ustar"
        self.validator.validate("bundle.tar", "application/x-tar", 10240, header)

    def test_accepts_real_pax_format_tar(self) -> None:
        """Python's tarfile module (and most modern tooling, incl. UAC)
        defaults to PAX format -- a distinct 8-byte magic value
        (b"ustar\\x0000") from GNU tar's, but sharing the same 5-byte
        "ustar" prefix this validator actually checks."""
        header = _real_tar_header(tarfile.PAX_FORMAT)
        assert header[257:262] == b"ustar"
        self.validator.validate("bundle.tar", "application/x-tar", 10240, header)

    def test_accepts_real_ext4_raw_disk_image(self) -> None:
        """A raw (unwrapped) disk image -- e.g. `image.dd` found tar-wrapped
        inside a mislabelled forensic2.E01 (roadmap E1) -- must pass intake
        validation so it can reach PlasoParser's dfVFS whole-image routing.
        Magic verified for real: `mke2fs -t ext4` on this host, inspected
        with `xxd` (see poc/tar_container_unwrapping/README.md)."""
        self.validator.validate(
            "image.dd", "application/octet-stream", 16 * 1024 * 1024, EXT4_HEADER
        )

    def test_accepts_real_ntfs_raw_disk_image(self) -> None:
        """Same raw-disk-image gap, NTFS variant -- verified for real with
        `mkntfs` on this host (see poc/tar_container_unwrapping/README.md)."""
        self.validator.validate(
            "image.dd", "application/octet-stream", 20 * 1024 * 1024, NTFS_HEADER
        )

    def test_accepts_real_fat16_raw_disk_image(self) -> None:
        """Same raw-disk-image gap, FAT16 variant -- verified for real with
        `mkfs.vfat -F 16` on this host."""
        self.validator.validate(
            "image.dd", "application/octet-stream", 32 * 1024 * 1024, FAT16_HEADER
        )

    def test_accepts_real_fat32_raw_disk_image(self) -> None:
        """Same raw-disk-image gap, FAT32 variant -- verified for real with
        `mkfs.vfat -F 32` on this host."""
        self.validator.validate(
            "image.dd", "application/octet-stream", 40 * 1024 * 1024, FAT32_HEADER
        )

    def test_accepts_json_by_extension_no_magic(self) -> None:
        # JSON has no magic bytes — passes on extension alone.
        self.validator.validate("cloudtrail.json", "application/json", 1024, b'{"key": "val"}')

    def test_accepts_csv_by_extension(self) -> None:
        self.validator.validate("export.csv", "text/csv", 512, b"col1,col2\n")

    def test_rejects_unknown_binary(self) -> None:
        with pytest.raises(ValidationError, match="magic bytes"):
            self.validator.validate(
                "unknown.evtx", "application/octet-stream", 1024, UNKNOWN_BINARY
            )

    def test_rejects_empty_binary(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            self.validator.validate("empty.evtx", "application/octet-stream", 0, b"")


def _build_zip_fixture(entries: dict[str, bytes]) -> bytes:
    """Build a minimal real ZIP file (in memory) with the given entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


class TestZipJarDisguiseValidator:
    validator = ZipJarDisguiseValidator()

    def test_rejects_jar_renamed_to_zip(self) -> None:
        """EVID-5: a minimal crafted JAR-like zip fixture (has the mandatory
        META-INF/MANIFEST.MF entry every JAR carries) must be rejected even
        though its declared extension is .zip and its magic bytes are the
        same PK\\x03\\x04 signature as a generic ZIP."""
        jar_bytes = _build_zip_fixture(
            {
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nMain-Class: Evil\n",
                "Evil.class": b"\xca\xfe\xba\xbe" + b"\x00" * 32,
            }
        )
        with pytest.raises(ValidationError, match="Java archive"):
            self.validator.validate(
                "totally-a-zip.zip", "application/zip", len(jar_bytes), jar_bytes
            )

    def test_rejects_jar_disguised_with_arbitrary_extension(self) -> None:
        jar_bytes = _build_zip_fixture({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
        with pytest.raises(ValidationError, match="Java archive"):
            self.validator.validate(
                "evidence.log", "application/octet-stream", len(jar_bytes), jar_bytes
            )

    def test_accepts_genuine_zip_without_manifest(self) -> None:
        zip_bytes = _build_zip_fixture({"logs/access.log": b"1.2.3.4 - - [x]\n"})
        self.validator.validate("archive.zip", "application/zip", len(zip_bytes), zip_bytes)

    def test_ignores_non_zip_files(self) -> None:
        self.validator.validate("sys.evtx", "application/octet-stream", 1024, EVTX_HEADER)

    def test_best_effort_passes_truncated_zip_buffer(self) -> None:
        """A ZIP whose central directory doesn't fit in the supplied buffer
        (simulating a large file where only the header was read) can't be
        inspected this way — must pass through, not raise or crash."""
        zip_bytes = _build_zip_fixture({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n"})
        truncated = zip_bytes[:10]  # keeps the PK\x03\x04 signature, drops the rest
        self.validator.validate("archive.zip", "application/zip", len(zip_bytes), truncated)


class TestValidatorChain:
    def test_passes_when_all_pass(self) -> None:
        chain = ValidatorChain(
            ExtensionValidator(),
            FileSizeValidator(10_000),
            MagicByteValidator(),
        )
        chain.validate("sys.evtx", "application/octet-stream", 512, EVTX_HEADER)

    def test_stops_at_first_failure(self) -> None:
        failures: list[str] = []

        class RecordingValidator(MagicByteValidator):
            def validate(
                self, filename: str, content_type: str, size_bytes: int, header_bytes: bytes
            ) -> None:
                failures.append("second")

        chain = ValidatorChain(ExtensionValidator(), RecordingValidator())
        with pytest.raises(ValidationError):
            chain.validate("evil.exe", "application/octet-stream", 100, b"")

        # RecordingValidator should never be reached.
        assert not failures


class TestDefaultValidatorChain:
    def test_chain_is_built(self) -> None:
        chain = default_validator_chain(max_upload_bytes=1_073_741_824)
        assert chain is not None

    def test_rejects_oversized_file(self) -> None:
        chain = default_validator_chain(max_upload_bytes=100)
        with pytest.raises(ValidationError):
            chain.validate("big.log", "text/plain", 101, b"")
