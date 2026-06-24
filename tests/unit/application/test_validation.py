"""Unit tests for evidence validators."""

from __future__ import annotations

import pytest

from src.application.validation import (
    BLOCKED_EXTENSIONS,
    ExtensionValidator,
    FileSizeValidator,
    MagicByteValidator,
    ValidatorChain,
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
UNKNOWN_BINARY = b"\xff\xfe\x00\x01" * 100  # unrecognised binary


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

    def test_accepts_pdf(self) -> None:
        self.validator.validate("report.pdf", "application/octet-stream", 1024, PDF_HEADER)

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
