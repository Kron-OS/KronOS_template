"""TextChunker: splits large evidence files into manageable chunks for parallel parsing."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

# Default chunk size: 500 000 lines (fits well within Celery task memory limits).
DEFAULT_CHUNK_LINES = 500_000
# Binary formats that must not be line-split.
_BINARY_MAGIC: tuple[bytes, ...] = (
    b"ElfFile\x00",  # EVTX
    b"REGF",  # Windows Registry
    b"SQLite format",  # SQLite
    b"PK\x03\x04",  # ZIP
    b"\x1f\x8b",  # gzip
    b"MZ",  # PE/EXE
)


class TextChunker:
    """Splits a streamed byte source into UTF-8 line chunks.

    Binary formats are passed through as a single chunk.  CSV files preserve
    the header line on every chunk so downstream parsers can reparse each
    chunk independently.
    """

    def __init__(self, chunk_lines: int = DEFAULT_CHUNK_LINES) -> None:
        self._chunk_lines = chunk_lines

    async def chunk(
        self,
        stream: AsyncIterator[bytes],
        filename: str = "",
        header_bytes: bytes = b"",
    ) -> AsyncIterator[bytes]:
        """Yield chunks suitable for independent parsing tasks.

        Binary files are yielded as one chunk.  Text/CSV files are split at
        *chunk_lines* boundaries with CSV header repeated.
        """
        if self._is_binary(filename, header_bytes):
            # Re-stream entire content as one chunk.
            buf = b"".join([chunk async for chunk in stream])
            yield buf
            return

        is_csv = filename.lower().endswith(".csv")
        csv_header: bytes | None = None
        data_lines: list[bytes] = []
        leftover = b""

        async for raw_chunk in stream:
            data = leftover + raw_chunk
            lines = data.split(b"\n")
            leftover = lines.pop()  # incomplete last line

            for line in lines:
                if is_csv and csv_header is None:
                    csv_header = line + b"\n"
                    continue

                data_lines.append(line + b"\n")
                if len(data_lines) >= self._chunk_lines:
                    prefix = [csv_header] if csv_header else []
                    yield b"".join(prefix + data_lines)
                    data_lines = []

        # Flush remaining lines + any incomplete final line.
        if leftover:
            data_lines.append(leftover)
        if data_lines or (csv_header and not data_lines):
            prefix = [csv_header] if csv_header else []
            if data_lines:
                yield b"".join(prefix + data_lines)

    @staticmethod
    def _is_binary(filename: str, header_bytes: bytes) -> bool:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext in ("evtx", "regf", "db", "sqlite", "sqlite3", "zip", "gz", "exe", "dll"):
            return True
        for magic in _BINARY_MAGIC:
            if header_bytes.startswith(magic):
                return True
        return False
