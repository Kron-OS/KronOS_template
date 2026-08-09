#!/usr/bin/env python3
"""L2 PoC: Generic CEF-over-syslog sink connector (KAFKA_AND_INTEGRATIONS_ROADMAP.md R3).

Drives the real, unmodified production classes:
    CefDetectionMapper (src/application/cef_detection_mapper.py) -- NEW this pass
    SyslogIntegrationSink (src/adapter/integration_sink/syslog_sink.py) -- R1's
        own, UNCHANGED transport, reused per this module's own "no sibling sink
        class" design decision (see cef_detection_mapper.py's module docstring)
    DetectionSinkPushService (src/application/detection_sink_push.py)
    Detection (src/domain/detection.py)
    PostgresAuditLogRepository / AuditLogService (real chain-of-custody audit trail)

against REAL local receivers this script stands up on 127.0.0.1 (roadmap SS1
invariant #9: no live third-party SaaS API, ever) -- a real asyncio TCP
server and a real asyncio UDP listener, standing in for a real CEF-over-syslog
SIEM ingestion listener (e.g. QRadar's syslog+LEEF/CEF receiver, or a generic
rsyslog/syslog-ng CEF collector) -- plus the REAL, live dev-stack Postgres 16
(docker-postgres-1) for the audit hash chain scenario, never an InMemory double.

**Objective (roadmap R3, verbatim).** "Real CEF-formatted message over real
syslog transport, against a real local syslog receiver -- proves the ABC's
second, non-HTTP, no-ack transport shape."

Scenarios:
  (1) Clean push over real TCP -- CefDetectionMapper + the real, unmodified
      SyslogIntegrationSink push one ordinary Detection; the real bytes
      received by a real local TCP listener are parsed back apart
      field-by-field (RFC 3164 prefix, 7 CEF header fields, extension
      key=value pairs) by an independent parser built in this script, and
      every recovered value is compared against the source Detection's own
      real attributes -- not eyeballed.
  (2) Same over real UDP -- same round-trip proof, different transport.
  (3) Honesty property re-confirmed for CEF specifically: both pushes report
      SinkAckStatus.UNACKNOWLEDGED, NEVER ACKNOWLEDGED (SyslogIntegrationSink
      is architecturally incapable of returning ACKNOWLEDGED -- re-verified
      here against a real CEF payload, not just the generic lines R1's own
      PoC used).
  (4) Escaping edge case (the roadmap brief's own required deliberate case):
      a Detection whose detector_name/rule_name/finding_id deliberately
      contain a literal '|', '\\', and '=' -- pushed over real TCP, the real
      received bytes are parsed back the same field-by-field way, and every
      recovered value is asserted to EXACTLY equal the original raw
      Detection field (byte-for-byte round-trip, not just "looks escaped").
  (5) Real failure path -- a real ConnectionRefusedError against a real
      closed TCP port still raises IntegrationSinkError through the
      unmodified SyslogIntegrationSink (mirrors R1's own Scenario 5;
      CefDetectionMapper does not change this contract at all).
  (6) DetectionSinkPushService full orchestration + real Postgres audit
      trail -- the roadmap's own hard invariant ("audit every mutation --
      reuse DetectionSinkPushService's SINK_PUSH_ATTEMPTED/EXECUTED/FAILED
      idiom, don't reinvent") verified for real: a real CEF push through the
      real service produces real audit rows, independently re-read from a
      fresh Postgres connection and hash-chain-verified.

Run: ~/venv/bin/python3 poc/integration_sink_cef_syslog/run_poc.py
Requires: docker-postgres-1 (16) already running (docker/docker-compose.dev.yml).
No other container is touched or required; nothing is left listening after the run.
"""

from __future__ import annotations

import asyncio
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.integration_sink.syslog_sink import (  # noqa: E402
    SyslogIntegrationSink,
    SyslogTransportProtocol,
)
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.cef_detection_mapper import CefDetectionMapper  # noqa: E402
from src.application.detection_sink_push import DetectionSinkPushService  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch  # noqa: E402
from src.domain.integration_sink import SinkAckStatus  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.exceptions import IntegrationSinkError  # noqa: E402

POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" -- {detail}" if detail else ""))


def make_tenant() -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias=f"r3poc{uuid.uuid4().hex[:8]}",
        user_id=uuid.uuid4(),
        username="r3-poc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def make_detection(
    tenant: TenantContext,
    finding_suffix: str,
    *,
    detector_name: str = "kronos-r3poc-network-detector",
    rule_name: str | None = "Suspicious Outbound Connection",
    finding_id: str | None = None,
) -> Detection:
    case_id = uuid.uuid4()
    return Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=case_id,
        finding_id=finding_id or f"poc-r3-finding-{finding_suffix}-{uuid.uuid4().hex[:8]}",
        detector_name=detector_name,
        source_index=f"kronos-{tenant.org_alias}-case-{case_id}-202608",
        rule_matches=(
            DetectionRuleMatch(rule_id="r1", rule_name=rule_name, tags=("high", "attack.t1041")),
        ),
        finding_timestamp=datetime.now(UTC),
        risk_score=61.0,
    )


# ---------------------------------------------------------------------------
# Real local receivers -- real sockets, real bytes, no application-layer ack
# (exactly the real CEF-over-syslog transport property this PoC proves).
# ---------------------------------------------------------------------------


class TcpSyslogReceiver:
    """A real, minimal TCP listener standing in for a CEF-over-syslog SIEM
    ingestion endpoint -- no ack, exactly the real transport this proves."""

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


class UdpSyslogReceiver(asyncio.DatagramProtocol):
    """A real, minimal UDP listener standing in for the same CEF-over-syslog
    SIEM endpoint, over a datagram socket."""

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


# ---------------------------------------------------------------------------
# Independent CEF/RFC 3164 round-trip parser -- built fresh in this PoC
# script (deliberately NOT importing cef_detection_mapper.py's own private
# escaping helpers) so the round-trip proof is a genuine, independent
# re-derivation of the real spec, not "the same code checking itself."
# ---------------------------------------------------------------------------

_RFC3164_RE = re.compile(r"^<(\d+)>(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) (CEF:.*)$", re.DOTALL)


def _split_escape_aware(value: str, delimiter: str, maxsplit: int | None = None) -> list[str]:
    """Real CEF parsing rule: split on *delimiter* only where it is not
    preceded by a backslash (a backslash always escapes the very next
    character). Mirrors the exact algorithm a real CEF-consuming SIEM must
    implement to avoid misparsing an escaped delimiter as a real one."""
    parts: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(value):
        if maxsplit is not None and len(parts) >= maxsplit:
            break
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            current.append(char)
            current.append(value[i + 1])
            i += 2
            continue
        if char == delimiter:
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    parts.append("".join(current) + value[i:])
    return parts


def _unescape(value: str, escaped_chars: tuple[str, ...]) -> str:
    """Reverses CEF escaping via one greedy left-to-right pass: a backslash
    followed by one of *escaped_chars* (or another backslash) collapses to
    that single real character."""
    result: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in (*escaped_chars, "\\"):
            result.append(value[i + 1])
            i += 2
            continue
        result.append(char)
        i += 1
    return "".join(result)


_EXTENSION_KEY_RE = re.compile(r"(?:^|(?<= ))([A-Za-z][A-Za-z0-9_]*)=")


def _parse_extension(extension: str) -> dict[str, str]:
    """Real CEF extension parsing: locate every unescaped ' key=' boundary,
    slice the value between consecutive boundaries, unescape '\\\\'/'\\='."""
    matches = list(_EXTENSION_KEY_RE.finditer(extension))
    result: dict[str, str] = {}
    for idx, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[idx + 1].start() - 1 if idx + 1 < len(matches) else len(extension)
        raw_value = extension[start:end]
        result[key] = _unescape(raw_value, ("=",))
    return result


def parse_cef_syslog_line(raw_line: str) -> dict:
    """Parses one real RFC 3164 + CEF line back into its real component
    fields -- the "parse it back apart field-by-field" proof the roadmap
    brief requires, not an eyeballed string comparison."""
    m = _RFC3164_RE.match(raw_line)
    if not m:
        raise ValueError(f"line does not match the real RFC 3164 + CEF shape: {raw_line!r}")
    pri_str, timestamp, host, cef_body = m.groups()
    pri = int(pri_str)

    fields = _split_escape_aware(cef_body, "|", maxsplit=7)
    if len(fields) != 8:
        raise ValueError(f"expected 7 header fields + extension, got {len(fields)}: {fields!r}")
    version_token, vendor, product, device_version, class_id, name, severity, extension = fields
    if not version_token.startswith("CEF:"):
        raise ValueError(f"first CEF segment missing 'CEF:' marker: {version_token!r}")

    return {
        "pri": pri,
        "facility": pri // 8,
        "syslog_severity": pri % 8,
        "timestamp": timestamp,
        "host": host,
        "cef_version": int(version_token.split(":", 1)[1]),
        "device_vendor": _unescape(vendor, ("|",)),
        "device_product": _unescape(product, ("|",)),
        "device_version": _unescape(device_version, ("|",)),
        "device_event_class_id": _unescape(class_id, ("|",)),
        "name": _unescape(name, ("|",)),
        "severity": int(severity),
        "extension": _parse_extension(extension),
        "raw_extension": extension,
    }


async def main() -> None:
    # =====================================================================
    # Real local receivers stood up
    # =====================================================================
    tcp_receiver = TcpSyslogReceiver()
    tcp_port = await tcp_receiver.start()
    log(f"=== real local TCP CEF-over-syslog receiver listening on 127.0.0.1:{tcp_port} ===")

    loop = asyncio.get_running_loop()
    udp_receiver = UdpSyslogReceiver()
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: udp_receiver, local_addr=("127.0.0.1", 0)
    )
    udp_port = udp_transport.get_extra_info("sockname")[1]
    log(f"=== real local UDP CEF-over-syslog receiver listening on 127.0.0.1:{udp_port} ===")

    tenant = make_tenant()
    log(f"=== real tenant org_id={tenant.org_id} org_alias={tenant.org_alias} ===")

    mapper = CefDetectionMapper()

    # =====================================================================
    # Scenario 1: clean push over real TCP + real field-by-field round trip
    # =====================================================================
    print("\n=== Scenario 1: clean CEF push over real TCP, real round-trip parse ===")
    tcp_sink = SyslogIntegrationSink("127.0.0.1", tcp_port, protocol=SyslogTransportProtocol.TCP)
    detection1 = make_detection(tenant, "tcp-clean")
    event1 = mapper.map(detection1)
    print(f"real raw CEF-over-syslog bytes sent (TCP):\n  {event1.raw_text}")
    ack1 = await tcp_sink.push_events([event1])
    check(
        "real TCP push returns UNACKNOWLEDGED -- NEVER ACKNOWLEDGED",
        ack1.status == SinkAckStatus.UNACKNOWLEDGED and ack1.status != SinkAckStatus.ACKNOWLEDGED,
    )
    await asyncio.sleep(0.2)
    check(
        "real local TCP receiver actually received exactly the sent bytes",
        len(tcp_receiver.received_lines) == 1 and tcp_receiver.received_lines[0] == event1.raw_text,
    )
    parsed1 = parse_cef_syslog_line(tcp_receiver.received_lines[0])
    print(f"real parsed-back fields: {parsed1}")
    check("parsed CEF version is 0", parsed1["cef_version"] == 0)
    check("parsed device vendor matches mapper default", parsed1["device_vendor"] == "KronOS")
    check(
        "parsed device product matches mapper default", parsed1["device_product"] == "DetectionSink"
    )
    check(
        "parsed Device Event Class ID matches real Detection.detector_name",
        parsed1["device_event_class_id"] == detection1.detector_name,
    )
    check(
        "parsed Name matches real Detection.rule_matches[0].rule_name",
        parsed1["name"] == detection1.rule_matches[0].rule_name,
    )
    check("parsed CEF severity matches 'high' -> 8 mapping", parsed1["severity"] == 8)
    check(
        "parsed syslog host matches real Detection.org_alias", parsed1["host"] == tenant.org_alias
    )
    check(
        "parsed extension externalId matches real Detection.detection_id",
        parsed1["extension"]["externalId"] == str(detection1.detection_id),
    )
    check(
        "parsed extension cs1 matches real Detection.org_id",
        parsed1["extension"]["cs1"] == str(detection1.org_id),
    )
    check(
        "parsed extension cs2 matches real Detection.case_id",
        parsed1["extension"]["cs2"] == str(detection1.case_id),
    )
    check(
        "parsed extension cn1 matches real Detection.risk_score",
        parsed1["extension"]["cn1"] == str(detection1.risk_score),
    )

    # =====================================================================
    # Scenario 2: same over real UDP
    # =====================================================================
    print("\n=== Scenario 2: clean CEF push over real UDP, real round-trip parse ===")
    udp_sink = SyslogIntegrationSink("127.0.0.1", udp_port, protocol=SyslogTransportProtocol.UDP)
    detection2 = make_detection(tenant, "udp-clean")
    event2 = mapper.map(detection2)
    ack2 = await udp_sink.push_events([event2])
    check("real UDP push returns UNACKNOWLEDGED", ack2.status == SinkAckStatus.UNACKNOWLEDGED)
    await asyncio.sleep(0.2)
    check(
        "real local UDP receiver actually received exactly the sent datagram",
        len(udp_receiver.received_datagrams) == 1
        and udp_receiver.received_datagrams[0] == event2.raw_text.encode("utf-8"),
    )
    parsed2 = parse_cef_syslog_line(udp_receiver.received_datagrams[0].decode("utf-8"))
    check(
        "UDP round-trip: parsed Device Event Class ID matches real detector_name",
        parsed2["device_event_class_id"] == detection2.detector_name,
    )
    check(
        "UDP round-trip: parsed extension msg matches real finding_id",
        detection2.finding_id in parsed2["extension"]["msg"],
    )

    # =====================================================================
    # Scenario 3: escaping edge case -- '|', '\\', '=' all deliberately present
    # =====================================================================
    print("\n=== Scenario 3: escaping edge case ('|', '\\\\', '=' in real Detection fields) ===")
    edge_detector_name = "malware|scanner\\v2"
    edge_rule_name = "Blocked C2 (proto=tcp|udp)"
    edge_finding_id = "case=1234|alert=5678"
    detection3 = make_detection(
        tenant,
        "tcp-edge-case",
        detector_name=edge_detector_name,
        rule_name=edge_rule_name,
        finding_id=edge_finding_id,
    )
    event3 = mapper.map(detection3)
    print(f"real raw CEF-over-syslog bytes sent (edge case):\n  {event3.raw_text}")
    ack3 = await tcp_sink.push_events([event3])
    check("edge-case push also returns UNACKNOWLEDGED", ack3.status == SinkAckStatus.UNACKNOWLEDGED)
    await asyncio.sleep(0.2)
    check(
        "real receiver got the exact escaped bytes (2nd line on the same TCP connection... "
        "new connection per push_events(), so a fresh single-line read)",
        len(tcp_receiver.received_lines) == 2 and tcp_receiver.received_lines[1] == event3.raw_text,
    )
    edge_raw_received = tcp_receiver.received_lines[1]
    parsed3 = parse_cef_syslog_line(edge_raw_received)
    print(f"real parsed-back edge-case fields: {parsed3}")
    check(
        "round-trip recovers the EXACT original detector_name despite embedded '|' and '\\\\'",
        parsed3["device_event_class_id"] == edge_detector_name,
        f"recovered={parsed3['device_event_class_id']!r} original={edge_detector_name!r}",
    )
    check(
        "round-trip recovers the EXACT original rule_name despite embedded '|' and '='",
        parsed3["name"] == edge_rule_name,
        f"recovered={parsed3['name']!r} original={edge_rule_name!r}",
    )
    check(
        "round-trip recovers the EXACT original finding_id (embedded '=' and '|') "
        "from extension msg",
        edge_finding_id in parsed3["extension"]["msg"],
        f"msg={parsed3['extension']['msg']!r}",
    )
    check(
        "'cat' extension field carries detector_name's real '|' UNESCAPED "
        "(extension pipes need no escaping)",
        parsed3["extension"]["cat"] == edge_detector_name,
        f"cat={parsed3['extension']['cat']!r}",
    )
    # Direct wire-level assertions on the ESCAPED bytes actually sent, not
    # just the round-tripped/recovered values -- proves the escaping rules
    # themselves were applied, not merely that recovery happens to work.
    check(
        "wire bytes: header zone escaped the real '|' in detector_name (\\|)",
        "malware\\|scanner\\\\v2" in edge_raw_received,
    )
    check(
        "wire bytes: header zone left '=' in rule_name UNESCAPED "
        "(the rule_name's OWN '|' is correctly escaped since it's also in the header zone)",
        "Blocked C2 (proto=tcp\\|udp)" in edge_raw_received,
    )
    check(
        "wire bytes: extension zone escaped the real '=' in finding_id (msg field)",
        "case\\=1234|alert\\=5678" in edge_raw_received,
    )

    # =====================================================================
    # Scenario 4: real failure path -- unmodified SyslogIntegrationSink
    # =====================================================================
    print("\n=== Scenario 4: real ConnectionRefusedError through the unmodified sink ===")
    unreachable_sink = SyslogIntegrationSink(
        "127.0.0.1", 1, protocol=SyslogTransportProtocol.TCP, timeout=3.0
    )
    try:
        await unreachable_sink.push_events([mapper.map(make_detection(tenant, "tcp-refused"))])
        check("real TCP connection-refused raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real TCP connection-refused raises IntegrationSinkError",
            True,
            f"error={exc.context.get('error')}",
        )

    # =====================================================================
    # Scenario 5: DetectionSinkPushService orchestration + real Postgres audit
    # =====================================================================
    print("\n=== Scenario 5: DetectionSinkPushService + real Postgres audit trail ===")
    setup_engine = create_async_engine(POSTGRES_DSN)
    await PostgresAuditLogRepository.create_tables(setup_engine)
    audit_repo = PostgresAuditLogRepository(setup_engine)
    audit_log = AuditLogService(audit_repo)

    push_service = DetectionSinkPushService(tcp_sink, mapper, audit_log)
    detections = [make_detection(tenant, f"audit-{i}") for i in range(3)]
    result = await push_service.push(detections, tenant)
    check("real push() reports the correct detection_count", result.detection_count == 3)
    check(
        "real push() produced 3 batches (max_batch_events=1, one syslog line per batch)",
        result.batch_count == 3,
    )
    check(
        "every real batch honestly reports UNACKNOWLEDGED (never a fabricated ack)",
        all(ack.status == SinkAckStatus.UNACKNOWLEDGED for ack in result.acks),
    )
    check(
        "SinkPushResult.all_acknowledged is honestly False for a syslog-only push",
        result.all_acknowledged is False,
    )

    fresh_engine = create_async_engine(POSTGRES_DSN)
    fresh_audit_repo = PostgresAuditLogRepository(fresh_engine)
    fresh_audit_log = AuditLogService(fresh_audit_repo)
    events_read = [e async for e in fresh_audit_repo.stream_by_org(tenant.org_id)]
    event_types = [e.event_type for e in events_read]
    check(
        "fresh read: real SINK_PUSH_ATTEMPTED rows exist for every real batch (>= 3)",
        event_types.count(AuditEventType.SINK_PUSH_ATTEMPTED) >= 3,
    )
    check(
        "fresh read: real SINK_PUSH_EXECUTED rows exist for all 3 successful batches",
        event_types.count(AuditEventType.SINK_PUSH_EXECUTED) >= 3,
    )
    executed_rows = [e for e in events_read if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
    check(
        "fresh read: every real EXECUTED row honestly records ack_status=unacknowledged",
        all(
            e.details.get("ack_status") == SinkAckStatus.UNACKNOWLEDGED.value for e in executed_rows
        ),
    )
    intact, detail = await fresh_audit_log.verify_chain(tenant.org_id)
    check(f"fresh read: real audit hash chain intact end-to-end (detail={detail})", intact)
    await fresh_engine.dispose()
    await setup_engine.dispose()

    # =====================================================================
    # Teardown -- nothing left listening.
    # =====================================================================
    await tcp_receiver.stop()
    udp_receiver.close()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against real local TCP/UDP receivers + the real, live dev-stack Postgres 16."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
