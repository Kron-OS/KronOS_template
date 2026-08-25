"""Unit tests for ClamAVScanner with mocked TCP socket."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.application.scanning import ClamAVScanner
from src.exceptions import StorageError


def _stream(data: bytes):  # type: ignore[no-untyped-def]
    async def _gen():  # type: ignore[no-untyped-def]
        yield data

    return _gen()


def _make_mock_connection(response: bytes):  # type: ignore[no-untyped-def]
    """Return (reader_mock, writer_mock) simulating a clamd TCP connection."""
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=response)

    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    return reader, writer


class TestClamAVScanner:
    @pytest.mark.asyncio
    async def test_clean_file_returns_clean(self) -> None:
        reader, writer = _make_mock_connection(b"stream: OK\0")
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            scanner = ClamAVScanner(host="localhost", port=3310)
            result = await scanner.scan_stream(_stream(b"harmless content"))
        assert result.is_clean
        assert result.threat_name is None

    @pytest.mark.asyncio
    async def test_infected_file_returns_threat(self) -> None:
        reader, writer = _make_mock_connection(b"stream: Win.Eicar-Test FOUND\0")
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            scanner = ClamAVScanner()
            result = await scanner.scan_stream(_stream(b"X5O!P%@AP...EICAR"))
        assert not result.is_clean
        assert result.threat_name == "Win.Eicar-Test"

    @pytest.mark.asyncio
    async def test_connection_failure_raises_storage_error(self) -> None:
        with patch("asyncio.open_connection", side_effect=OSError("connection refused")):
            scanner = ClamAVScanner(host="nowhere", port=9999)
            with pytest.raises(StorageError, match="clamd"):
                await scanner.scan_stream(_stream(b"data"))

    @pytest.mark.asyncio
    async def test_unexpected_response_raises_storage_error(self) -> None:
        reader, writer = _make_mock_connection(b"UNKNOWN RESPONSE\0")
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            scanner = ClamAVScanner()
            with pytest.raises(StorageError, match="Unexpected"):
                await scanner.scan_stream(_stream(b"data"))

    @pytest.mark.asyncio
    async def test_broken_pipe_during_write_raises_clear_storage_error(self) -> None:
        """Real, reproduced bug (poc/clamav/run_poc_large_file.py): clamd
        closes the connection the instant a stream exceeds its configured
        StreamMaxLength/MaxFileSize, and the raw write loop used to let a
        bare BrokenPipeError propagate uncaught -- a real 239 MB upload hit
        exactly this. Must now surface as a StorageError with a clear,
        actionable message instead."""
        reader, writer = _make_mock_connection(b"INSTREAM: Size limit reached.\0")
        writer.write = MagicMock(side_effect=[None, BrokenPipeError("[Errno 32] Broken pipe")])
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            scanner = ClamAVScanner()
            with pytest.raises(StorageError, match="exceeds clamd's configured"):
                await scanner.scan_stream(_stream(b"x" * 100))

    @pytest.mark.asyncio
    async def test_connection_reset_during_write_raises_clear_storage_error(self) -> None:
        reader, writer = _make_mock_connection(b"")
        writer.write = MagicMock(side_effect=[None, ConnectionResetError("reset")])
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            scanner = ClamAVScanner()
            with pytest.raises(StorageError, match="exceeds clamd's configured"):
                await scanner.scan_stream(_stream(b"x" * 100))

    @pytest.mark.asyncio
    async def test_instream_protocol_sent(self) -> None:
        reader, writer = _make_mock_connection(b"stream: OK\0")
        with patch("asyncio.open_connection", return_value=(reader, writer)):
            scanner = ClamAVScanner()
            await scanner.scan_stream(_stream(b"test data"))
        # First write must be the INSTREAM command.
        first_call = writer.write.call_args_list[0]
        assert first_call[0][0] == b"zINSTREAM\0"
