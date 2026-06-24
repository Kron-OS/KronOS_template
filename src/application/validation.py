"""Evidence validators: magic-byte, file-size, and chain composition."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.exceptions import ValidationError

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
    # Prefetch
    (0, b"MAM\x04", "prefetch"),
    # SQLite (browser artefacts)
    (0, b"SQLite format 3\x00", "sqlite"),
    # GZIP (compressed logs, journald)
    (0, b"\x1f\x8b", "gzip"),
    # ZIP (container for many log formats)
    (0, b"PK\x03\x04", "zip"),
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

_MAX_HEADER_BYTES = 16  # bytes read from the start of the file for magic detection


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
    )
