"""Unit tests for PlasoParser and TextChunker."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.application.text_chunker import TextChunker
from src.external.parsers.plaso import PlasoParser
from tests.fixtures.factories import make_evidence, make_tenant_context

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

    def test_supports_evtx(self) -> None:
        """Gap Audit Milestone VVVV: Plaso is now the sole EVTX claimant
        (see plaso.py's class docstring) -- FastEvtxParser is no longer
        registered in the production registry, so this must be True."""
        parser = PlasoParser()
        magic = b"ElfFile\x00" + b"\x00" * 30
        assert parser.supports("system.evtx", "application/octet-stream", magic)

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

    # -----------------------------------------------------------------
    # Gap Audit Milestone OO: the temp file parse() writes evidence bytes
    # into must be cleaned up even when Plaso/Firecracker fails partway
    # through -- previously the unlink only ran after the `async for`
    # loop completed normally, silently leaking the raw evidence (a whole
    # disk image, or a registry hive with real credentials) into the
    # worker's local /tmp on any real failure.
    # -----------------------------------------------------------------

    @staticmethod
    def _fake_settings() -> MagicMock:
        settings = MagicMock()
        settings.plaso_worker_path = None
        return settings

    @pytest.mark.asyncio
    async def test_temp_file_is_cleaned_up_when_firecracker_run_raises(self) -> None:
        class _FakeFailingLauncher:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            async def run(self, **kwargs: object) -> None:
                raise RuntimeError("real, deliberate Firecracker failure for this test")

        parser = PlasoParser()
        evidence = make_evidence()
        tenant = make_tenant_context()

        async def _stream():
            yield b"regf" + b"\x00" * 60

        created_paths: list[Path] = []
        real_unlink = Path.unlink

        def _spy_unlink(self: Path, *args: object, **kwargs: object) -> None:
            created_paths.append(self)
            return real_unlink(self, *args, **kwargs)

        with (
            patch("src.config.Settings", return_value=self._fake_settings()),
            patch("src.external.sandbox.firecracker.FirecrackerLauncher", _FakeFailingLauncher),
            patch("pathlib.Path.unlink", _spy_unlink, autospec=False),
            pytest.raises(RuntimeError, match="real, deliberate Firecracker failure"),
        ):
            async for _ in parser.parse(_stream(), evidence, tenant):
                pass

        assert len(created_paths) == 1
        assert not created_paths[0].exists()

    @pytest.mark.asyncio
    async def test_temp_file_is_cleaned_up_when_consumer_stops_iterating_early(self) -> None:
        """A downstream consumer (e.g. enrichment/timeline-ingest) that
        raises partway through consuming this generator triggers a
        GeneratorExit inside parse() -- the temp file must still be
        cleaned up, not just on the happy path."""

        class _FakeLauncherYieldingForever:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            async def run(self, **kwargs: object):
                async def _records():
                    while True:
                        yield None

                return _records()

        parser = PlasoParser()
        evidence = make_evidence()
        tenant = make_tenant_context()

        async def _stream():
            yield b"regf" + b"\x00" * 60

        created_paths: list[Path] = []
        real_unlink = Path.unlink

        def _spy_unlink(self: Path, *args: object, **kwargs: object) -> None:
            created_paths.append(self)
            return real_unlink(self, *args, **kwargs)

        with (
            patch("src.config.Settings", return_value=self._fake_settings()),
            patch(
                "src.external.sandbox.firecracker.FirecrackerLauncher",
                _FakeLauncherYieldingForever,
            ),
            patch("pathlib.Path.unlink", _spy_unlink, autospec=False),
        ):
            gen = parser.parse(_stream(), evidence, tenant)
            await gen.__anext__()  # consume exactly one record, then abandon it
            await gen.aclose()  # simulate the consumer stopping early

        assert len(created_paths) == 1
        assert not created_paths[0].exists()


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
