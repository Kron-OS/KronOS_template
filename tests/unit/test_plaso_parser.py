"""Unit tests for PlasoParser and TextChunker."""

from __future__ import annotations

import pytest

from src.application.text_chunker import TextChunker
from src.external.parsers.plaso import PlasoParser

# ---------------------------------------------------------------------------
# PlasoParser
# ---------------------------------------------------------------------------


class TestPlasoParser:
    def test_parser_name(self) -> None:
        assert PlasoParser().parser_name == "plaso"

    def test_parser_type_heavy(self) -> None:
        from src.application.parsing import ParserType

        assert PlasoParser().parser_type == ParserType.HEAVY

    def test_supports_regf(self) -> None:
        parser = PlasoParser()
        assert parser.supports("NTUSER.DAT", "application/octet-stream", b"regf" + b"\x00" * 60)

    def test_supports_sqlite(self) -> None:
        parser = PlasoParser()
        magic = b"SQLite format 3\x00"
        assert parser.supports("srum.db", "application/octet-stream", magic)

    def test_rejects_evtx(self) -> None:
        parser = PlasoParser()
        magic = b"ElfFile\x00" + b"\x00" * 30
        assert not parser.supports("system.evtx", "application/octet-stream", magic)

    def test_supports_by_extension(self) -> None:
        parser = PlasoParser()
        assert parser.supports("Amcache.hve", "application/octet-stream", b"\x00" * 16)
        assert parser.supports("places.sqlite", "application/octet-stream", b"\x00" * 16)

    def test_does_not_support_nginx_log(self) -> None:
        parser = PlasoParser()
        header = b'192.168.1.1 - - [25/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200'
        assert not parser.supports("access.log", "text/plain", header)

    # -----------------------------------------------------------------
    # Raw (unwrapped) disk image detection -- roadmap E1's real,
    # verified sub-gap: before this, PlasoParser had NO path for a bare
    # `image.dd`/`.img`/`.raw` at all, only real EWF (E01) magic. Magic
    # offsets/bytes below are the same real, verified values used by
    # validation.py's _MAGIC_TABLE (mke2fs/mkntfs/mkfs.vfat on this host,
    # see poc/tar_container_unwrapping/README.md for the full transcript,
    # including a real log2timeline/psort run against each that produced
    # real fs:stat events).
    # -----------------------------------------------------------------

    def test_supports_raw_ext4_disk_image(self) -> None:
        parser = PlasoParser()
        header = b"\x00" * 1080 + b"\x53\xef" + b"\x00" * 100
        assert parser.supports("image.dd", "application/octet-stream", header)

    def test_supports_raw_ntfs_disk_image(self) -> None:
        parser = PlasoParser()
        header = b"\xeb\x52\x90" + b"NTFS    " + b"\x00" * 100
        assert parser.supports("image.dd", "application/octet-stream", header)

    def test_supports_raw_fat16_disk_image(self) -> None:
        parser = PlasoParser()
        header = b"\x00" * 54 + b"FAT16   " + b"\x00" * 100
        assert parser.supports("image.dd", "application/octet-stream", header)

    def test_supports_raw_fat12_disk_image(self) -> None:
        parser = PlasoParser()
        header = b"\x00" * 54 + b"FAT12   " + b"\x00" * 100
        assert parser.supports("image.dd", "application/octet-stream", header)

    def test_supports_raw_fat32_disk_image(self) -> None:
        parser = PlasoParser()
        header = b"\x00" * 82 + b"FAT32   " + b"\x00" * 100
        assert parser.supports("image.dd", "application/octet-stream", header)

    def test_does_not_falsely_claim_short_header_as_raw_image(self) -> None:
        # A short header (e.g. from a small file, or a truncated read) must
        # not out-of-range-slice its way into a false positive.
        parser = PlasoParser()
        assert not parser.supports("small.bin", "application/octet-stream", b"\x00" * 20)


# ---------------------------------------------------------------------------
# TextChunker
# ---------------------------------------------------------------------------


class TestTextChunker:
    @pytest.mark.asyncio
    async def test_empty_stream_yields_nothing(self) -> None:
        async def _empty():
            return
            yield  # type: ignore[misc]

        chunks = []
        async for chunk in TextChunker().chunk(_empty()):
            chunks.append(chunk)
        assert chunks == []

    @pytest.mark.asyncio
    async def test_small_text_single_chunk(self) -> None:
        lines = b"line1\nline2\nline3\n"

        async def _stream():
            yield lines

        chunks = []
        async for chunk in TextChunker(chunk_lines=100).chunk(_stream(), "test.log"):
            chunks.append(chunk)
        assert len(chunks) == 1
        assert b"line1" in chunks[0]

    @pytest.mark.asyncio
    async def test_split_at_chunk_boundary(self) -> None:
        n_lines = 10
        content = b"\n".join(f"line{i}".encode() for i in range(n_lines)) + b"\n"

        async def _stream():
            yield content

        chunks = []
        async for chunk in TextChunker(chunk_lines=3).chunk(_stream(), "test.log"):
            chunks.append(chunk)
        # 10 lines with chunk_size=3 → ceil(10/3) = 4 chunks
        assert len(chunks) == 4

    @pytest.mark.asyncio
    async def test_binary_file_single_chunk(self) -> None:
        binary_content = b"ElfFile\x00" + b"\xff" * 100

        async def _stream():
            yield binary_content

        chunks = []
        async for chunk in TextChunker().chunk(_stream(), "system.evtx", binary_content[:8]):
            chunks.append(chunk)
        assert len(chunks) == 1
        assert chunks[0] == binary_content

    @pytest.mark.asyncio
    async def test_csv_header_repeated(self) -> None:
        header = b"col1,col2,col3\n"
        rows = b"".join(f"v{i},v{i},v{i}\n".encode() for i in range(6))
        content = header + rows

        async def _stream():
            yield content

        chunks = []
        async for chunk in TextChunker(chunk_lines=3).chunk(_stream(), "data.csv"):
            chunks.append(chunk)
        # 6 data rows / 3 = 2 chunks, each starting with the header
        assert len(chunks) == 2
        for chunk in chunks:
            assert chunk.startswith(b"col1,col2,col3\n")

    @pytest.mark.asyncio
    async def test_binary_extension_detected(self) -> None:
        """SQLite DB extension triggers binary mode even without magic bytes match."""
        content = b"SQLite format 3\x00" + b"\x00" * 50

        async def _stream():
            yield content

        chunks = []
        async for chunk in TextChunker().chunk(_stream(), "places.sqlite"):
            chunks.append(chunk)
        assert len(chunks) == 1
