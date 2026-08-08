"""SyslogIntegrationSink: real CEF/LEEF-over-syslog fire-and-forget
transport (KAFKA_AND_INTEGRATIONS_ROADMAP.md R1) -- the vendor-neutral
universal fallback (roadmap SS0: "no application-layer auth, fire-and-forget
-- weaker delivery guarantee than an HTTP 2xx+body ack").

**This is the honest, non-HTTP transport family the roadmap SS4 explicitly
requires be modeled as structurally distinct, not papered over as
equivalent to ``HttpJsonIntegrationSink``.** Every real, non-exceptional
``push_events()`` call here returns ``SinkAck(status=UNACKNOWLEDGED, ...)``
-- never ``ACKNOWLEDGED`` -- because there is, by construction, no
application-layer acknowledgement to observe: a real TCP write can confirm
the local kernel accepted the bytes into its send buffer (and a real
``ConnectionRefusedError`` if nobody is listening at all), and a real UDP
``sendto`` only confirms the datagram left this host -- neither is proof
the receiving SIEM parsed or stored the event.

TCP is the default because it is the only one of the two that can produce
a real, deterministic "target unreachable" failure (``ConnectionRefusedError``
on a closed port) for the "deliberate failure case" CLAUDE.md SS F/this
roadmap's proof bar requires -- a real UDP `sendto()` against a closed port
generally does not raise synchronously at all (fire-and-forget all the way
down), which is itself an honest illustration of why syslog's delivery
guarantee is weaker, not a gap in this implementation. UDP support is
included (`SyslogTransportProtocol.UDP`) since real CEF-over-syslog
deployments commonly use it, and to prove the same interface handles both.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Sequence
from enum import StrEnum

from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAck, SinkAckStatus
from src.exceptions import IntegrationSinkError


class SyslogTransportProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class SyslogIntegrationSink(IntegrationSink):
    """Real socket write of one or more already-CEF/LEEF-formatted lines to
    *host*:*port* -- no auth, no ack, exactly the real transport CEF/LEEF-
    over-syslog is (roadmap SS0).
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        protocol: SyslogTransportProtocol = SyslogTransportProtocol.TCP,
        timeout: float = 5.0,
    ) -> None:
        self._host = host
        self._port = port
        self._protocol = protocol
        self._timeout = timeout

    @property
    def max_batch_events(self) -> int | None:
        # A real syslog message IS one line/datagram -- there is no real
        # batching concept for this transport family (module docstring),
        # so DetectionSinkPushService's own chunking naturally produces
        # one push_events() call per event.
        return 1

    async def push_events(self, events: Sequence[MappedSinkEvent]) -> SinkAck:
        if not events:
            raise IntegrationSinkError("push_events called with an empty batch")

        lines: list[str] = []
        for event in events:
            if event.raw_text is None:
                raise IntegrationSinkError(
                    "SyslogIntegrationSink requires MappedSinkEvent.raw_text "
                    "(line-oriented) -- got a JSON-family payload instead",
                    context={"source_detection_id": event.source_detection_id},
                )
            lines.append(event.raw_text)

        try:
            if self._protocol is SyslogTransportProtocol.TCP:
                bytes_written = await self._send_tcp(lines)
            else:
                bytes_written = await self._send_udp(lines)
        except (OSError, TimeoutError) as exc:
            raise IntegrationSinkError(
                "Real syslog transport write failed",
                context={
                    "host": self._host,
                    "port": self._port,
                    "protocol": self._protocol.value,
                    "error": str(exc),
                },
            ) from exc

        return SinkAck(
            status=SinkAckStatus.UNACKNOWLEDGED,
            detail={
                "transport": self._protocol.value,
                "host": self._host,
                "port": self._port,
                "bytes_written": bytes_written,
                "event_count": len(lines),
            },
        )

    async def _send_tcp(self, lines: list[str]) -> int:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port), timeout=self._timeout
        )
        try:
            total = 0
            for line in lines:
                data = (line + "\n").encode("utf-8")
                writer.write(data)
                total += len(data)
            await asyncio.wait_for(writer.drain(), timeout=self._timeout)
            return total
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await asyncio.wait_for(writer.wait_closed(), timeout=self._timeout)

    async def _send_udp(self, lines: list[str]) -> int:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=(self._host, self._port)
        )
        try:
            total = 0
            for line in lines:
                data = line.encode("utf-8")
                transport.sendto(data)
                total += len(data)
            return total
        finally:
            transport.close()
