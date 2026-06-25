"""Antivirus scanning: abstract interface + ClamAV implementation."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass

from src.exceptions import StorageError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanResult:
    """Outcome of an antivirus scan."""

    is_clean: bool
    threat_name: str | None = None

    def __post_init__(self) -> None:
        if self.is_clean and self.threat_name is not None:
            raise ValueError("A clean result cannot carry a threat_name")


class AntivirusScanner(ABC):
    """Abstract antivirus scanner — implementations plug in behind this contract."""

    @abstractmethod
    async def scan_stream(self, stream: AsyncIterator[bytes]) -> ScanResult:
        """Consume the byte stream and return a ScanResult."""


class ClamAVScanner(AntivirusScanner):
    """Stream file bytes to a clamd daemon via TCP socket.

    Requires clamd to be running and accessible at the configured host:port.
    Uses the INSTREAM command which avoids writing the file to the clamd host.
    """

    CHUNK_SIZE = 65536

    def __init__(self, host: str = "localhost", port: int = 3310) -> None:
        self._host = host
        self._port = port

    async def scan_stream(self, stream: AsyncIterator[bytes]) -> ScanResult:
        """Send the stream to clamd INSTREAM and parse the response."""
        import asyncio
        import struct

        try:
            reader, writer = await asyncio.open_connection(self._host, self._port)
        except OSError as exc:
            raise StorageError(
                f"Cannot connect to clamd at {self._host}:{self._port}",
                context={"error": str(exc)},
            ) from exc

        try:
            writer.write(b"zINSTREAM\0")

            async for chunk in stream:
                for i in range(0, len(chunk), self.CHUNK_SIZE):
                    part = chunk[i : i + self.CHUNK_SIZE]
                    writer.write(struct.pack("!I", len(part)) + part)

            # Terminate the stream.
            writer.write(struct.pack("!I", 0))
            await writer.drain()

            response = await reader.read(4096)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        response_str = response.decode("utf-8", errors="replace").strip().rstrip("\0")
        logger.info("clamav_scan_response", extra={"response": response_str})

        # clamd responds with "stream: OK" or "stream: <ThreatName> FOUND"
        if response_str.endswith("OK"):
            return ScanResult(is_clean=True)

        if "FOUND" in response_str:
            threat = response_str.split(":")[1].strip().replace(" FOUND", "")
            return ScanResult(is_clean=False, threat_name=threat)

        raise StorageError(
            "Unexpected clamd response",
            context={"response": response_str},
        )


class NoOpScanner(AntivirusScanner):
    """Always reports clean — for testing and environments without ClamAV."""

    async def scan_stream(self, stream: AsyncIterator[bytes]) -> ScanResult:
        # Drain the stream so callers don't have to special-case this stub.
        async for _ in stream:
            pass
        return ScanResult(is_clean=True)
