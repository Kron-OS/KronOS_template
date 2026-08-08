"""Unit tests for SyslogIntegrationSink.

Unlike HttpJsonIntegrationSink (mocked httpx, mirrors test_ticketing_system.py),
this sink's own logic IS the raw socket write -- mocking asyncio's
stream/datagram primitives would just re-describe the implementation rather
than verify it. Per CLAUDE.md SS B.5 ("mock only external dependencies"), a
real local TCP/UDP listener started in-process is the real dependency here
(no external service, no network egress) -- the same standard
poc/integration_sink_foundation/ applies at PoC scope, exercised here at
unit-test scope with a throwaway listener per test.

Full real-receiver + real-failure-mode verification (deliberate connection
refusal) lives in poc/integration_sink_foundation/ against a standalone
receiver process; this file additionally covers the same refused-connection
path in-process since it costs nothing extra to assert here too.
"""

from __future__ import annotations

import asyncio

import pytest

from src.adapter.integration_sink.syslog_sink import SyslogIntegrationSink, SyslogTransportProtocol
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAckStatus
from src.exceptions import IntegrationSinkError


class _TcpLineReceiver:
    """A real, minimal TCP listener collecting whatever lines it receives."""

    def __init__(self) -> None:
        self.received_lines: list[str] = []
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]  # type: ignore[union-attr,index]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            line = await reader.readline()
            if not line:
                break
            self.received_lines.append(line.decode("utf-8").rstrip("\n"))
        writer.close()

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()


class _UdpDatagramReceiver(asyncio.DatagramProtocol):
    """A real, minimal UDP listener collecting whatever datagrams it receives."""

    def __init__(self) -> None:
        self.received_datagrams: list[bytes] = []
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received_datagrams.append(data)

    def close(self) -> None:
        assert self._transport is not None
        self._transport.close()


def _events(*lines: str) -> list[MappedSinkEvent]:
    return [
        MappedSinkEvent(source_detection_id=str(i), raw_text=line) for i, line in enumerate(lines)
    ]


class TestSyslogIntegrationSinkTcpSuccess:
    @pytest.mark.asyncio
    async def test_real_tcp_write_returns_unacknowledged_never_acknowledged(self) -> None:
        receiver = _TcpLineReceiver()
        port = await receiver.start()
        try:
            sink = SyslogIntegrationSink("127.0.0.1", port, protocol=SyslogTransportProtocol.TCP)
            ack = await sink.push_events(_events("CEF:0|KronOS|Test|1.0|100|Test Event|5|"))
            # Real transport write succeeded -- but this must NEVER be
            # reported as ACKNOWLEDGED (the single most important property
            # of this whole abstraction).
            assert ack.status == SinkAckStatus.UNACKNOWLEDGED
            assert ack.status != SinkAckStatus.ACKNOWLEDGED
            assert ack.detail["transport"] == "tcp"
            assert ack.detail["event_count"] == 1

            # Give the receiver's event loop a beat to actually read the bytes.
            await asyncio.sleep(0.2)
            assert receiver.received_lines == ["CEF:0|KronOS|Test|1.0|100|Test Event|5|"]
        finally:
            await receiver.stop()

    @pytest.mark.asyncio
    async def test_multiple_lines_all_delivered_in_order(self) -> None:
        receiver = _TcpLineReceiver()
        port = await receiver.start()
        try:
            sink = SyslogIntegrationSink("127.0.0.1", port, protocol=SyslogTransportProtocol.TCP)
            ack = await sink.push_events(_events("line-one", "line-two", "line-three"))
            assert ack.detail["event_count"] == 3
            await asyncio.sleep(0.2)
            assert receiver.received_lines == ["line-one", "line-two", "line-three"]
        finally:
            await receiver.stop()

    def test_max_batch_events_is_one_no_real_batching_concept(self) -> None:
        sink = SyslogIntegrationSink("127.0.0.1", 1514)
        assert sink.max_batch_events == 1
        assert sink.max_batch_bytes is None


class TestSyslogIntegrationSinkUdpSuccess:
    @pytest.mark.asyncio
    async def test_real_udp_write_returns_unacknowledged(self) -> None:
        loop = asyncio.get_running_loop()
        receiver = _UdpDatagramReceiver()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: receiver, local_addr=("127.0.0.1", 0)
        )
        port = transport.get_extra_info("sockname")[1]
        try:
            sink = SyslogIntegrationSink("127.0.0.1", port, protocol=SyslogTransportProtocol.UDP)
            ack = await sink.push_events(_events("CEF:0|KronOS|Test|1.0|100|UDP Event|5|"))
            assert ack.status == SinkAckStatus.UNACKNOWLEDGED
            assert ack.detail["transport"] == "udp"

            await asyncio.sleep(0.2)
            assert receiver.received_datagrams == [b"CEF:0|KronOS|Test|1.0|100|UDP Event|5|"]
        finally:
            receiver.close()


class TestSyslogIntegrationSinkFailure:
    @pytest.mark.asyncio
    async def test_empty_batch_raises(self) -> None:
        sink = SyslogIntegrationSink("127.0.0.1", 1514)
        with pytest.raises(IntegrationSinkError):
            await sink.push_events([])

    @pytest.mark.asyncio
    async def test_json_payload_event_raises_wrong_transport_family(self) -> None:
        sink = SyslogIntegrationSink("127.0.0.1", 1514)
        with pytest.raises(IntegrationSinkError):
            await sink.push_events([MappedSinkEvent(source_detection_id="1", payload={"a": 1})])

    @pytest.mark.asyncio
    async def test_tcp_connection_refused_raises_integration_sink_error(self) -> None:
        # Real, deterministic "nobody is listening" -- port 1 is privileged
        # and nothing in this test environment binds it (mirrors
        # detection_ticket_integration's own "127.0.0.1:1" unreachable-target
        # idiom), so this is a REAL ConnectionRefusedError, not a mock.
        sink = SyslogIntegrationSink(
            "127.0.0.1", 1, protocol=SyslogTransportProtocol.TCP, timeout=3.0
        )
        with pytest.raises(IntegrationSinkError) as exc_info:
            await sink.push_events(_events("CEF:0|KronOS|Test|1.0|100|Unreachable|5|"))
        assert "127.0.0.1" in str(exc_info.value.context.get("host", ""))

    @pytest.mark.asyncio
    async def test_tcp_connect_timeout_raises_integration_sink_error(self) -> None:
        # A real, non-routable TEST-NET-1 address (RFC 5737, 192.0.2.0/24)
        # -- guaranteed to never answer, exercising the real timeout path
        # distinct from the immediate real ConnectionRefusedError above.
        sink = SyslogIntegrationSink(
            "192.0.2.1", 514, protocol=SyslogTransportProtocol.TCP, timeout=0.5
        )
        with pytest.raises(IntegrationSinkError):
            await sink.push_events(_events("CEF:0|KronOS|Test|1.0|100|Timeout|5|"))
