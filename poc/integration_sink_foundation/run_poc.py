#!/usr/bin/env python3
"""L2 PoC: IntegrationSink foundation (KAFKA_AND_INTEGRATIONS_ROADMAP.md R1).

Drives the real, unmodified production classes:
    HttpJsonIntegrationSink / SyslogIntegrationSink (src/adapter/integration_sink/)
    StaticTokenAuthenticator / OAuth2ClientCredentialsAuthenticator (sink_authenticator.py)
    chunk_events (src/adapter/integration_sink/batching.py)
    DetectionSinkPushService (src/application/detection_sink_push.py)
    DetectionEventMapper / MappedSinkEvent (src/application/detection_sink_mapper.py)
    Detection (src/domain/detection.py)
    PostgresAuditLogRepository / AuditLogService (real chain-of-custody audit trail)

against REAL local stand-in receivers this script itself stands up on
127.0.0.1 (roadmap SS1 invariant #9: no live third-party SaaS API, ever):
a real stdlib http.server acting as a generic HEC-shaped JSON receiver, a
real stdlib http.server acting as an OAuth2 client-credentials token
endpoint, a real asyncio TCP server, and a real asyncio UDP listener acting
as CEF-over-syslog receivers -- plus the REAL, live dev-stack Postgres 16
(docker-postgres-1) for the audit hash chain, never an InMemory double.

**Honesty note (mirrors H4/detection_ticket_integration's own precedent
exactly).** No real named-vendor SIEM/SOAR product (Splunk, Sentinel,
QRadar, ...) is deployed anywhere in this dev stack, and reaching a live
third-party SaaS API is explicitly out of scope for R1 (R2/R3/R4's own
scope). This PoC verifies the two REAL, vendor-neutral transport shapes
(generic HTTP-JSON push-with-ack, CEF-over-syslog fire-and-forget) against
real local receivers -- real bytes over real sockets, real status
codes/response bodies inspected on both sides -- never a live vendor
account. See README.md for the full reasoning.

Scenarios:
  (1) HTTP-JSON ACK path -- a real local HEC-shaped receiver returns a real
      2xx + {"accepted": N} body; HttpJsonIntegrationSink reports a real,
      confirmed SinkAckStatus.ACKNOWLEDGED.
  (2) HTTP-JSON failure paths -- a real 500 response, and a real 2xx with a
      mismatched accepted count, both raise IntegrationSinkError (never a
      fabricated ack).
  (3) Syslog fire-and-forget path (TCP) -- a real local TCP listener
      receives the real bytes; SyslogIntegrationSink reports
      SinkAckStatus.UNACKNOWLEDGED -- NEVER ACKNOWLEDGED, honestly modeling
      "the socket write succeeded" as strictly weaker than an HTTP ack.
  (4) Syslog fire-and-forget path (UDP) -- same honesty property, over UDP.
  (5) Syslog failure path -- a real ConnectionRefusedError against a real
      closed TCP port raises IntegrationSinkError (the deterministic
      failure case the syslog_sink.py module docstring calls out: UDP
      sendto() does not reliably raise synchronously, which is itself an
      honest illustration of syslog's weaker guarantee, not a gap here).
  (6) OAuth2ClientCredentialsAuthenticator real token caching -- a real
      local OAuth2 token endpoint is hit exactly ONCE across TWO real
      pushes (proving prepare()'s own real cache/expiry logic, not a
      per-call reauthentication) -- this is the exact claim
      sink_authenticator.py's own docstring makes; verified for real here.
  (7) DetectionSinkPushService full orchestration -- real Detections mapped
      via two deliberately generic, non-vendor-specific stand-in mappers
      (JSON-family, CEF-family), batched via the real max_batch_events
      ceiling, pushed to both real receivers, with a real
      SINK_PUSH_ATTEMPTED/EXECUTED/FAILED audit trail written to the real,
      live Postgres and independently re-verified (fresh connection,
      AuditLogService.verify_chain()) afterward.

Run: ~/venv/bin/python3 poc/integration_sink_foundation/run_poc.py
Requires: docker-postgres-1 (16) already running (docker/docker-compose.dev.yml).
No other container is touched or required; nothing is left listening after the run.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.integration_sink.batching import chunk_events  # noqa: E402
from src.adapter.integration_sink.http_json_sink import HttpJsonIntegrationSink  # noqa: E402
from src.adapter.integration_sink.sink_authenticator import (  # noqa: E402
    NullAuthenticator,
    OAuth2ClientCredentialsAuthenticator,
    StaticTokenAuthenticator,
)
from src.adapter.integration_sink.syslog_sink import (  # noqa: E402
    SyslogIntegrationSink,
    SyslogTransportProtocol,
)
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sink_mapper import (  # noqa: E402
    DetectionEventMapper,
    MappedSinkEvent,
)
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


def make_tenant(org_alias_prefix: str = "r1poc") -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias=f"{org_alias_prefix}{uuid.uuid4().hex[:8]}",
        user_id=uuid.uuid4(),
        username="r1-poc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def make_detection(tenant: TenantContext, finding_suffix: str) -> Detection:
    case_id = uuid.uuid4()
    return Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=case_id,
        finding_id=f"poc-r1-finding-{finding_suffix}-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-r1poc-network-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{case_id}-202608",
        rule_matches=(DetectionRuleMatch(rule_id="r1", tags=("high", "attack.t1021.001")),),
        finding_timestamp=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Two deliberately generic, non-vendor-specific stand-in DetectionEventMapper
# implementations -- proves the ABC is genuinely pluggable across the two
# structurally different transport families (roadmap SS4). Named-vendor
# mappers (Splunk/CEF/Sentinel) are explicitly R2/R3/R4's own scope.
# ---------------------------------------------------------------------------


class GenericJsonStandInMapper(DetectionEventMapper):
    """A generic-envelope JSON mapper, for the HTTP-JSON transport family."""

    def map(self, detection: Detection) -> MappedSinkEvent:
        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            payload={
                "finding_id": detection.finding_id,
                "detector_name": detection.detector_name,
                "severity": detection.rule_severity,
                "attack_tags": list(detection.attack_tags),
                "org_alias": detection.org_alias,
            },
            mapper_metadata={"target": "generic-json-stand-in"},
        )


class GenericCefLikeStandInMapper(DetectionEventMapper):
    """A generic CEF-shaped line mapper, for the syslog fire-and-forget family."""

    def map(self, detection: Detection) -> MappedSinkEvent:
        line = (
            f"CEF:0|KronOS|R1PoC|1.0|{detection.finding_id}|{detection.detector_name}|"
            f"{detection.rule_severity or 'unknown'}|"
            f"cs1Label=orgAlias cs1={detection.org_alias}"
        )
        return MappedSinkEvent(source_detection_id=str(detection.detection_id), raw_text=line)


# ---------------------------------------------------------------------------
# Real local receivers -- real sockets, real bytes, real status codes.
# ---------------------------------------------------------------------------


class HecJsonHandler(BaseHTTPRequestHandler):
    """A real, generic HEC-shaped JSON receiver: real 2xx + a real
    {"accepted": N} confirmation body -- proves the push-with-ack path."""

    received: list[dict] = []
    force_status: int | None = None
    force_accepted_mismatch = False

    def do_POST(self) -> None:  # noqa: N802 -- stdlib API name
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        body = json.loads(raw)
        HecJsonHandler.received.append({"body": body, "headers": dict(self.headers)})

        if HecJsonHandler.force_status is not None:
            self._send_json(HecJsonHandler.force_status, {"error": "deliberate PoC failure"})
            return

        accepted = len(body["events"])
        if HecJsonHandler.force_accepted_mismatch:
            accepted = max(0, accepted - 1)
        self._send_json(200, {"text": "Success", "code": 0, "accepted": accepted})

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature
        pass


class OAuth2TokenHandler(BaseHTTPRequestHandler):
    """A real local OAuth2 client-credentials token endpoint -- issues a
    real access_token with a long real expires_in, counting real fetches
    server-side so caching can be independently confirmed on both sides."""

    fetch_count = 0

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)  # form-encoded body, not needed for this stand-in
        OAuth2TokenHandler.fetch_count += 1
        data = json.dumps(
            {"access_token": f"real-token-{OAuth2TokenHandler.fetch_count}", "expires_in": 3600}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


class TcpSyslogReceiver:
    """A real, minimal TCP listener standing in for a CEF-over-syslog
    receiver -- no ack, exactly the real transport this proves."""

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
    """A real, minimal UDP listener standing in for a CEF-over-syslog
    receiver over UDP -- same no-ack transport, over a datagram socket."""

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


def start_http_server(handler: type) -> tuple[HTTPServer, threading.Thread, int]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


async def main() -> None:
    # =====================================================================
    # Real local receivers stood up
    # =====================================================================
    hec_server, hec_thread, hec_port = start_http_server(HecJsonHandler)
    hec_url = f"http://127.0.0.1:{hec_port}/hec"
    log(f"=== real local HEC-shaped JSON receiver listening on {hec_url} ===")

    oauth_server, oauth_thread, oauth_port = start_http_server(OAuth2TokenHandler)
    oauth_token_url = f"http://127.0.0.1:{oauth_port}/token"
    log(f"=== real local OAuth2 token endpoint listening on {oauth_token_url} ===")

    tcp_receiver = TcpSyslogReceiver()
    tcp_port = await tcp_receiver.start()
    log(f"=== real local TCP syslog receiver listening on 127.0.0.1:{tcp_port} ===")

    loop = asyncio.get_running_loop()
    udp_receiver = UdpSyslogReceiver()
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: udp_receiver, local_addr=("127.0.0.1", 0)
    )
    udp_port = udp_transport.get_extra_info("sockname")[1]
    log(f"=== real local UDP syslog receiver listening on 127.0.0.1:{udp_port} ===")

    setup_engine = create_async_engine(POSTGRES_DSN)
    await PostgresAuditLogRepository.create_tables(setup_engine)
    audit_repo = PostgresAuditLogRepository(setup_engine)
    audit_log = AuditLogService(audit_repo)

    tenant = make_tenant()
    log(f"=== real tenant org_id={tenant.org_id} org_alias={tenant.org_alias} ===")

    # =====================================================================
    # Scenario 1: HTTP-JSON ACK path -- real 2xx + real accepted count
    # =====================================================================
    print("\n=== Scenario 1: HTTP-JSON push-with-ack (real 2xx + accepted body) ===")
    http_sink = HttpJsonIntegrationSink(hec_url, StaticTokenAuthenticator("poc-static-token"))
    mapper = GenericJsonStandInMapper()
    detection1 = make_detection(tenant, "http-ack")
    event1 = mapper.map(detection1)
    ack1 = await http_sink.push_events([event1])
    check(
        "real HTTP push returns ACKNOWLEDGED (real 2xx + accepted body)",
        ack1.status == SinkAckStatus.ACKNOWLEDGED,
    )
    check("ack.detail carries the real status_code", ack1.detail.get("status_code") == 200)
    check("ack.detail carries the real accepted count", ack1.detail.get("accepted") == 1)
    check(
        "real receiver actually saw the real StaticTokenAuthenticator header",
        HecJsonHandler.received[0]["headers"].get("Authorization") == "Bearer poc-static-token",
    )
    check(
        "real receiver's own request body carries the real mapped payload",
        HecJsonHandler.received[0]["body"]["events"][0]["finding_id"] == detection1.finding_id,
    )

    # =====================================================================
    # Scenario 2: HTTP-JSON failure paths -- real error status + mismatch
    # =====================================================================
    print("\n=== Scenario 2: HTTP-JSON failure paths (real 500, real accepted-count mismatch) ===")
    HecJsonHandler.force_status = 500
    try:
        await http_sink.push_events([mapper.map(make_detection(tenant, "http-500"))])
        check("real 500 response raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real 500 response raises IntegrationSinkError",
            True,
            f"status_code={exc.context.get('status_code')}",
        )
    HecJsonHandler.force_status = None

    HecJsonHandler.force_accepted_mismatch = True
    try:
        await http_sink.push_events([mapper.map(make_detection(tenant, "http-mismatch"))])
        check(
            "real accepted-count mismatch raises IntegrationSinkError (never a partial ack)", False
        )
    except IntegrationSinkError as exc:
        check(
            "real accepted-count mismatch raises IntegrationSinkError (never a partial ack)",
            True,
            f"sent={exc.context.get('sent')} accepted={exc.context.get('accepted')}",
        )
    HecJsonHandler.force_accepted_mismatch = False

    # =====================================================================
    # Scenario 3/4: Syslog fire-and-forget -- TCP and UDP, honest UNACKNOWLEDGED
    # =====================================================================
    print("\n=== Scenario 3: syslog fire-and-forget over real TCP ===")
    tcp_sink = SyslogIntegrationSink("127.0.0.1", tcp_port, protocol=SyslogTransportProtocol.TCP)
    cef_mapper = GenericCefLikeStandInMapper()
    detection2 = make_detection(tenant, "tcp-syslog")
    event2 = cef_mapper.map(detection2)
    ack2 = await tcp_sink.push_events([event2])
    check(
        "real TCP syslog write returns UNACKNOWLEDGED -- NEVER ACKNOWLEDGED",
        ack2.status == SinkAckStatus.UNACKNOWLEDGED and ack2.status != SinkAckStatus.ACKNOWLEDGED,
    )
    await asyncio.sleep(0.2)
    check(
        "real local TCP receiver actually received the real CEF-shaped line",
        len(tcp_receiver.received_lines) == 1 and tcp_receiver.received_lines[0] == event2.raw_text,
    )

    print("\n=== Scenario 4: syslog fire-and-forget over real UDP ===")
    udp_sink = SyslogIntegrationSink("127.0.0.1", udp_port, protocol=SyslogTransportProtocol.UDP)
    detection3 = make_detection(tenant, "udp-syslog")
    event3 = cef_mapper.map(detection3)
    ack3 = await udp_sink.push_events([event3])
    check(
        "real UDP syslog write returns UNACKNOWLEDGED", ack3.status == SinkAckStatus.UNACKNOWLEDGED
    )
    await asyncio.sleep(0.2)
    check(
        "real local UDP receiver actually received the real datagram",
        len(udp_receiver.received_datagrams) == 1
        and udp_receiver.received_datagrams[0] == event3.raw_text.encode("utf-8"),
    )

    # =====================================================================
    # Scenario 5: syslog failure path -- real connection refused
    # =====================================================================
    print("\n=== Scenario 5: syslog fail loudly -- real ConnectionRefusedError (invariant #8) ===")
    unreachable_sink = SyslogIntegrationSink(
        "127.0.0.1", 1, protocol=SyslogTransportProtocol.TCP, timeout=3.0
    )
    try:
        await unreachable_sink.push_events([cef_mapper.map(make_detection(tenant, "tcp-refused"))])
        check("real TCP connection-refused raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real TCP connection-refused raises IntegrationSinkError",
            True,
            f"error={exc.context.get('error')}",
        )

    # =====================================================================
    # Scenario 6: OAuth2 real token caching -- one real fetch, two real pushes
    # =====================================================================
    print("\n=== Scenario 6: OAuth2 real caching (2 pushes, 1 fetch) ===")
    oauth_authenticator = OAuth2ClientCredentialsAuthenticator(
        oauth_token_url, "poc-client-id", "poc-client-secret"
    )
    oauth_sink = HttpJsonIntegrationSink(hec_url, oauth_authenticator)
    await oauth_sink.push_events([mapper.map(make_detection(tenant, "oauth-1"))])
    await oauth_sink.push_events([mapper.map(make_detection(tenant, "oauth-2"))])
    check(
        "real local OAuth2 token endpoint was hit exactly ONCE across two real pushes",
        OAuth2TokenHandler.fetch_count == 1,
        f"server-observed fetch_count={OAuth2TokenHandler.fetch_count}",
    )
    check(
        "authenticator's own real_token_fetch_count agrees with the server",
        oauth_authenticator.real_token_fetch_count == 1,
    )
    last_two_auth_headers = [
        r["headers"].get("Authorization") for r in HecJsonHandler.received[-2:]
    ]
    check(
        "both real pushes used the SAME real cached token (no silent per-call reauthentication)",
        last_two_auth_headers[0] == last_two_auth_headers[1] == "Bearer real-token-1",
    )

    # =====================================================================
    # Scenario 7: DetectionSinkPushService full orchestration + real audit trail
    # =====================================================================
    print(
        "\n=== Scenario 7: DetectionSinkPushService orchestration + real Postgres audit trail ==="
    )
    http_sink_batched = HttpJsonIntegrationSink(hec_url, NullAuthenticator(), max_batch_events=2)
    push_service = DetectionSinkPushService(
        http_sink_batched, GenericJsonStandInMapper(), audit_log
    )
    detections = [make_detection(tenant, f"batch-{i}") for i in range(5)]
    result = await push_service.push(detections, tenant)
    check("real push() reports the correct detection_count", result.detection_count == 5)
    check(
        "real push() batched 5 events into 3 real HTTP calls (max_batch_events=2)",
        result.batch_count == 3,
    )
    check(
        "real push() result is all_acknowledged (every batch got a real ACKNOWLEDGED ack)",
        result.all_acknowledged,
    )

    print("--- real push() against a failing sink, audited then re-raised ---")

    class _AlwaysFailsSink(HttpJsonIntegrationSink):
        async def push_events(self, events):  # type: ignore[override]
            raise IntegrationSinkError("real, deliberate PoC failure for audit verification")

    failing_service = DetectionSinkPushService(
        _AlwaysFailsSink(hec_url, NullAuthenticator()), GenericJsonStandInMapper(), audit_log
    )
    try:
        await failing_service.push([make_detection(tenant, "audit-fail")], tenant)
        check("real failing push raises IntegrationSinkError", False)
    except IntegrationSinkError:
        check("real failing push raises IntegrationSinkError", True)

    print("--- independent fresh-connection audit re-verification ---")
    fresh_engine = create_async_engine(POSTGRES_DSN)
    fresh_audit_repo = PostgresAuditLogRepository(fresh_engine)
    fresh_audit_log = AuditLogService(fresh_audit_repo)
    events_read = [e async for e in fresh_audit_repo.stream_by_org(tenant.org_id)]
    event_types = [e.event_type for e in events_read]
    check(
        "fresh read: real SINK_PUSH_ATTEMPTED rows exist for every real batch (>= 3 + 1 fail)",
        event_types.count(AuditEventType.SINK_PUSH_ATTEMPTED) >= 4,
    )
    check(
        "fresh read: real SINK_PUSH_EXECUTED rows exist for the 3 successful batches",
        event_types.count(AuditEventType.SINK_PUSH_EXECUTED) == 3,
    )
    check(
        "fresh read: real SINK_PUSH_FAILED row exists for the deliberately-failing push",
        AuditEventType.SINK_PUSH_FAILED in event_types,
    )
    executed_with_ack = [
        e for e in events_read if e.event_type == AuditEventType.SINK_PUSH_EXECUTED
    ]
    check(
        "fresh read: every real EXECUTED row's own ack_status is honestly ACKNOWLEDGED",
        all(
            e.details.get("ack_status") == SinkAckStatus.ACKNOWLEDGED.value
            for e in executed_with_ack
        ),
    )
    intact, detail = await fresh_audit_log.verify_chain(tenant.org_id)
    check(f"fresh read: real audit hash chain intact end-to-end (detail={detail})", intact)
    await fresh_engine.dispose()

    # =====================================================================
    # Also independently verify chunk_events() directly against the real
    # event stream this scenario just produced -- confirms the batching
    # helper's own contract matches what DetectionSinkPushService actually
    # did above.
    # =====================================================================
    standalone_mapper = GenericJsonStandInMapper()
    standalone_events = [standalone_mapper.map(d) for d in detections]
    chunks = list(chunk_events(standalone_events, max_batch_events=2, max_batch_bytes=None))
    check(
        "chunk_events() independently reproduces the same [2, 2, 1] batching",
        [len(c) for c in chunks] == [2, 2, 1],
    )

    # =====================================================================
    # Teardown -- nothing left listening.
    # =====================================================================
    await setup_engine.dispose()
    hec_server.shutdown()
    hec_thread.join(timeout=5)
    oauth_server.shutdown()
    oauth_thread.join(timeout=5)
    await tcp_receiver.stop()
    udp_receiver.close()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against real local HTTP/TCP/UDP receivers + the real, live dev-stack Postgres 16."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
