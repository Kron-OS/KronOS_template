#!/usr/bin/env python3
"""Real local UDP syslog receiver -- PoC L1/L2 evidence for P1-5 (fluent-bit
severity-mapping fix).

Structurally mirrors the real local TCP/UDP receiver pattern already
established in poc/integration_sink_cef_syslog/run_poc.py (R1/R3's own real
syslog receivers): a real asyncio DatagramProtocol bound to 127.0.0.1, no
mocked socket. Decodes the real RFC 5424 PRI header
(``<PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID [SD] MSG``) from each real
datagram fluent-bit's ``syslog`` output plugin sends, and prints the
recovered facility/severity for independent, non-eyeballed verification.

Usage: python3 udp_syslog_receiver.py <listen_port> <seconds_to_listen>
"""

from __future__ import annotations

import asyncio
import re
import sys

PRI_RE = re.compile(r"^<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$", re.DOTALL)

# RFC 5424 section 6.2.1 -- the real, canonical numeric severity table this
# PoC verifies fluent-bit's OUTPUT actually sends, independently re-derived
# here (not imported from src/ or docker/fluent-bit config) so the check is
# a genuine external verification, not the same mapping checking itself.
RFC5424_SEVERITY_NAMES = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


class UdpSyslogReceiver(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received: list[bytes] = []
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received.append(data)
        line = data.decode("utf-8", errors="replace")
        print(f"[RAW] {line!r}")
        m = PRI_RE.match(line)
        if not m:
            print("    -> DID NOT MATCH real RFC 5424 PRI-header shape")
            return
        pri_str, timestamp, host, appname, procid, msgid, rest = m.groups()
        pri = int(pri_str)
        facility = pri // 8
        severity = pri % 8
        severity_name = RFC5424_SEVERITY_NAMES.get(severity, "UNKNOWN")
        print(
            f"    -> PRI={pri} facility={facility} severity={severity} "
            f"({severity_name}) appname={appname} timestamp={timestamp} host={host}"
        )

    def close(self) -> None:
        assert self._transport is not None
        self._transport.close()


async def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5514
    listen_seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

    loop = asyncio.get_running_loop()
    receiver = UdpSyslogReceiver()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: receiver, local_addr=("127.0.0.1", port)
    )
    print(f"=== real local UDP syslog receiver listening on 127.0.0.1:{port} ===")
    print(f"=== waiting up to {listen_seconds}s for real fluent-bit syslog OUTPUT datagrams ===")
    await asyncio.sleep(listen_seconds)
    print(f"\n[SUMMARY] real datagrams received: {len(receiver.received)}")
    receiver.close()


if __name__ == "__main__":
    asyncio.run(main())
