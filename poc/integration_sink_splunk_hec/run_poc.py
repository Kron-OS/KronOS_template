#!/usr/bin/env python3
"""L2 PoC: Splunk HEC sink connector (KAFKA_AND_INTEGRATIONS_ROADMAP.md R2).

Drives the real, unmodified production classes:
    SplunkHecSink (src/adapter/integration_sink/splunk_hec_sink.py)
    SplunkDetectionMapper (src/application/splunk_detection_mapper.py)
    StaticTokenAuthenticator(scheme="Splunk") (sink_authenticator.py, R1)
    chunk_events (src/adapter/integration_sink/batching.py, R1)
    DetectionSinkPushService (src/application/detection_sink_push.py, R1)
    Detection (src/domain/detection.py)
    PostgresAuditLogRepository / AuditLogService (real chain-of-custody audit trail)

against a REAL, genuine ``splunk/splunk:9.3.3`` container (Scenario 0,
``kronos-poc-splunk-hec``) AND a REAL local HEC-protocol-accurate stand-in
receiver this script itself stands up on 127.0.0.1 (Scenarios 1-5 -- roadmap
SS1 invariant #9: no live third-party SaaS API, ever; a real self-hostable
Splunk image does exist so it is used directly for Scenario 0, see
README.md), plus the REAL, live dev-stack Postgres 16 (docker-postgres-1)
for the audit hash chain.

**What makes this receiver "protocol-accurate" rather than a generic
stand-in (unlike R1's own deliberately-generic HecJsonHandler)**:

1. It validates the real ``Authorization: Splunk <token>`` scheme
   character-for-character (missing header / wrong scheme / wrong token
   are three DISTINCT real HEC error codes, not one generic 401).
2. It parses the request body the way real Splunk HEC actually does:
   concatenated, standalone top-level JSON objects (``{...}{...}{...}``),
   via ``json.JSONDecoder.raw_decode`` in a loop -- NOT ``json.loads()`` on
   the whole body (which would raise on any real multi-event HEC batch) and
   NOT a ``{"events": [...]}`` array (which is not HEC's real wire format
   at all -- see splunk_hec_sink.py's own module docstring for the exact
   doc quote this was verified against).
3. It returns Splunk's own real, documented response bodies/status-code
   pairs (verified against docs.splunk.com/Documentation/Splunk/9.3.3/Data/
   TroubleshootHTTPEventCollector's own status-code table, fetched and read
   directly this pass -- see README.md for the captured excerpt):
   code 0/200 "Success", code 2/401 "Token is required", code 3/401
   "Invalid authorization", code 4/403 "Invalid token", code 6/400
   "Invalid data format".

Scenarios:
  (0) REAL Splunk Enterprise 9.3.3 (not a stand-in) -- a real, genuine
      `splunk/splunk:9.3.3` container this script's caller stands up
      (`kronos-poc-splunk-hec`, HEC on host port 18088, management API on
      18089, `SPLUNK_HEC_SSL=false` per the real, current
      `splunk-ansible` `environ.py`'s own `getHEC()` -- verified by fetching
      that exact source file this pass, see README.md). Proves the
      production `SplunkHecSink` against actual vendor software, not just
      this PoC's own reimplementation of the protocol (Scenarios 1-5 below
      remain, unchanged, for the deep wire-format assertions a real black-box
      Splunk instance can't expose, e.g. inspecting the raw concatenated-JSON
      bytes it received -- both are real, complementary proofs). Covers: (a)
      a real push -> real 200/{"code":0,"text":"Success"} -> ACKNOWLEDGED,
      confirmed independently by querying Splunk's own real
      `/services/search/jobs` REST endpoint (oneshot search) and finding the
      pushed event actually indexed; (b) real wrong-token -> real
      403/{"code":4}; (c) real missing-Authorization -> real 401/{"code":2}.
  (1) Real end-to-end push (local protocol-accurate stand-in) -- a real
      Detection -> SplunkDetectionMapper -> SplunkHecSink.push_events() ->
      real HTTP POST with the real "Authorization: Splunk <token>" header ->
      real receiver validates it, real-parses the concatenated-JSON body,
      returns the real {"text": "Success", "code": 0} body ->
      SinkAck.ACKNOWLEDGED. The receiver's OWN independent parse of the
      envelope is inspected (time/host/source/sourcetype/event nested
      object), not just the sink's own return value.
  (2) Real deliberate auth-failure case -- wrong token -> real receiver
      returns the real documented 403 + {"text": "Invalid token", "code": 4}
      -> SplunkHecSink raises IntegrationSinkError carrying that real
      code/text in its context.
  (3) Real missing-Authorization-header and wrong-scheme cases -> real 401
      + {"code": 2}/{"code": 3} respectively (three distinct real HEC error
      paths, not a single generic 401).
  (4) Real size-limit-adjacent batching case -- 5 real Detections pushed
      through a SplunkHecSink configured with a deliberately small
      max_batch_bytes override (proving chunk_events() is actually invoked
      with HEC-realistic byte thresholds, not just event-count ones) ->
      the real receiver observes multiple separate real HTTP POSTs, each
      correctly containing real concatenated-JSON bodies within the
      configured ceiling.
  (5) DetectionSinkPushService full orchestration + real audit trail --
      mirrors R1's own Scenario 7 exactly, but through the real
      SplunkDetectionMapper/SplunkHecSink pair instead of a generic
      stand-in, with a real SINK_PUSH_ATTEMPTED/EXECUTED/FAILED audit trail
      written to the real, live Postgres and independently re-verified
      (fresh connection, AuditLogService.verify_chain()) afterward.

Run: ~/venv/bin/python3 poc/integration_sink_splunk_hec/run_poc.py
Requires: docker-postgres-1 (16) already running (docker/docker-compose.dev.yml),
AND a real `kronos-poc-splunk-hec` container (splunk/splunk:9.3.3) already up
and healthy for Scenario 0 -- see README.md for the exact `docker run` used
(this script does not create/tear down that container itself, since a real
Splunk instance takes 1-3 minutes to provision and is meant to be reused
across repeated PoC runs during development, unlike the disposable local
stand-in server in Scenarios 1-5, which this script DOES start/stop itself).
If `kronos-poc-splunk-hec` is not reachable, Scenario 0 is skipped with a
loud, explicit warning -- never silently treated as passed.
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

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.integration_sink.sink_authenticator import (  # noqa: E402
    NullAuthenticator,
    StaticTokenAuthenticator,
)
from src.adapter.integration_sink.splunk_hec_sink import SplunkHecSink  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sink_push import DetectionSinkPushService  # noqa: E402
from src.application.splunk_detection_mapper import SplunkDetectionMapper  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch  # noqa: E402
from src.domain.integration_sink import SinkAckStatus  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.exceptions import IntegrationSinkError  # noqa: E402

POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
REAL_TOKEN = "poc-real-splunk-hec-token-abc123"  # nosec B105 -- local PoC-only stand-in value

# Real, genuine splunk/splunk:9.3.3 container (kronos-poc-splunk-hec) -- see
# README.md for the exact `docker run` invocation, including the real,
# current env vars (SPLUNK_HEC_TOKEN/SPLUNK_HEC_SSL) verified this pass
# against splunk-ansible's own environ.py source. This script does not
# start/stop this container (see module docstring); Scenario 0 skips itself
# loudly if it's unreachable rather than silently passing.
REAL_SPLUNK_HEC_URL = "http://127.0.0.1:18088/services/collector/event"
REAL_SPLUNK_MGMT_URL = "https://127.0.0.1:18089"
REAL_SPLUNK_HEC_TOKEN = (
    "9b1c2b6e-3f2a-4d3b-9c1a-2f6e7a8b9c0d"  # nosec B105 -- local PoC-only container token
)
REAL_SPLUNK_ADMIN_PASSWORD = "KronosPoc-2026!"  # nosec B105 -- local PoC-only container password

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" -- {detail}" if detail else ""))


def make_tenant(org_alias_prefix: str = "r2poc") -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias=f"{org_alias_prefix}{uuid.uuid4().hex[:8]}",
        user_id=uuid.uuid4(),
        username="r2-poc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def make_detection(tenant: TenantContext, finding_suffix: str) -> Detection:
    case_id = uuid.uuid4()
    return Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=case_id,
        finding_id=f"poc-r2-finding-{finding_suffix}-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-r2poc-network-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{case_id}-202608",
        rule_matches=(
            DetectionRuleMatch(
                rule_id="r1", rule_name="Lateral Movement", tags=("high", "attack.t1021.001")
            ),
        ),
        matched_document_ids=("doc-a", "doc-b"),
        finding_timestamp=datetime.now(UTC),
        risk_score=63.0,
    )


def parse_concatenated_json(raw: bytes) -> list[dict]:
    """Real HEC batch-body parsing: standalone JSON objects concatenated
    one after another (``{...}{...}{...}``), decoded via
    ``json.JSONDecoder.raw_decode`` in a loop -- the real documented wire
    format (see this module's own docstring), NOT ``json.loads()`` on the
    whole body and NOT a ``{"events": [...]}`` array."""
    text = raw.decode("utf-8")
    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)
    events: list[dict] = []
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        obj, end = decoder.raw_decode(text, idx)
        events.append(obj)
        idx = end
    return events


class SplunkHecStandInHandler(BaseHTTPRequestHandler):
    """A real, HEC-protocol-accurate stand-in for
    ``/services/collector/event`` -- see this module's own docstring for
    exactly which real, documented behaviors it reproduces and where those
    were verified (splunk_hec_sink.py's own module docstring +
    poc/integration_sink_splunk_hec/README.md)."""

    received: list[dict] = []
    valid_token = REAL_TOKEN

    def do_POST(self) -> None:  # noqa: N802 -- stdlib API name
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        auth_header = self.headers.get("Authorization")

        if auth_header is None:
            self._send_json(401, {"text": "Token is required", "code": 2})
            return
        if not auth_header.startswith("Splunk "):
            self._send_json(401, {"text": "Invalid authorization", "code": 3})
            return
        token = auth_header[len("Splunk ") :]
        if token != SplunkHecStandInHandler.valid_token:
            self._send_json(403, {"text": "Invalid token", "code": 4})
            return

        try:
            events = parse_concatenated_json(raw)
            if not events:
                raise ValueError("no events parsed")
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"text": "Invalid data format", "code": 6})
            return

        SplunkHecStandInHandler.received.append(
            {
                "events": events,
                "headers": dict(self.headers),
                "content_type": self.headers.get("Content-Type"),
                "raw_body_bytes": len(raw),
            }
        )
        self._send_json(200, {"text": "Success", "code": 0})

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature
        pass


def start_http_server(handler: type) -> tuple[HTTPServer, threading.Thread, int]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


async def _real_splunk_reachable() -> bool:
    try:
        async with httpx.AsyncClient(
            timeout=3.0, verify=False
        ) as client:  # noqa: S501 -- local PoC-only self-signed cert
            resp = await client.get(f"{REAL_SPLUNK_MGMT_URL}/services/server/info")
            return resp.status_code in (200, 401)  # reachable at all is enough here
    except httpx.HTTPError:
        return False


async def _search_real_splunk(
    sourcetype: str, attempts: int = 6, delay_seconds: float = 3.0
) -> list[dict]:
    """Real Splunk oneshot search via the real, documented
    ``/services/search/jobs`` REST endpoint (verified by hand against the
    real container this pass -- see README.md for the captured curl
    transcript this mirrors exactly: basic auth, form-encoded
    ``output_mode=json``/``exec_mode=oneshot``/``search=``, ``results[]``
    with a real ``_raw`` field). Retries briefly since real Splunk indexing
    is near-real-time but not synchronous with the HEC POST returning."""
    async with httpx.AsyncClient(
        timeout=10.0, verify=False, auth=("admin", REAL_SPLUNK_ADMIN_PASSWORD)  # noqa: S501,S106
    ) as client:
        for _ in range(attempts):
            resp = await client.post(
                f"{REAL_SPLUNK_MGMT_URL}/services/search/jobs",
                data={
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                    "search": f"search index=main sourcetype={sourcetype} | head 10",
                },
            )
            if resp.status_code == 200:
                results = resp.json().get("results", [])
                if results:
                    return results
            await asyncio.sleep(delay_seconds)
    return []


async def run_real_splunk_scenario(tenant: TenantContext) -> None:
    """Scenario 0: the real production SplunkHecSink against a real,
    genuine splunk/splunk:9.3.3 container (not this PoC's own stand-in) --
    see this module's own docstring and README.md for exactly what's real
    here vs. Scenarios 1-5's own local stand-in."""
    print("\n=== Scenario 0: REAL Splunk Enterprise 9.3.3 container (kronos-poc-splunk-hec) ===")
    if not await _real_splunk_reachable():
        log(
            "WARNING: kronos-poc-splunk-hec not reachable at "
            f"{REAL_SPLUNK_MGMT_URL} -- Scenario 0 SKIPPED, not silently passed. "
            "See README.md for the docker run command to start it."
        )
        check("Scenario 0 (real Splunk container) skipped -- container unreachable", False)
        return

    real_sourcetype = f"kronos:r2poc:{uuid.uuid4().hex[:8]}"
    real_mapper = SplunkDetectionMapper(
        source="kronos:detection_sink", sourcetype=real_sourcetype, index="main"
    )
    real_sink = SplunkHecSink(
        REAL_SPLUNK_HEC_URL, StaticTokenAuthenticator(REAL_SPLUNK_HEC_TOKEN, scheme="Splunk")
    )
    real_detection = make_detection(tenant, "real-splunk")
    real_event = real_mapper.map(real_detection)
    real_ack = await real_sink.push_events([real_event])
    check(
        "real Splunk container: real push returns ACKNOWLEDGED",
        real_ack.status == SinkAckStatus.ACKNOWLEDGED,
    )
    check(
        "real Splunk container: ack carries real code=0/text='Success'",
        real_ack.detail.get("code") == 0 and real_ack.detail.get("text") == "Success",
        f"detail={real_ack.detail}",
    )

    log(f"querying real Splunk /services/search/jobs for sourcetype={real_sourcetype} ...")
    indexed = await _search_real_splunk(real_sourcetype)
    check(
        "real Splunk container: pushed event actually indexed and found via real search API",
        len(indexed) == 1,
        f"results={indexed}",
    )
    if indexed:
        raw = json.loads(indexed[0]["_raw"])
        check(
            "real Splunk container: indexed event's own finding_id matches what was pushed",
            raw.get("finding_id") == real_detection.finding_id,
        )

    # Real deliberate auth-failure cases against the real container.
    wrong_token_sink = SplunkHecSink(
        REAL_SPLUNK_HEC_URL,
        StaticTokenAuthenticator("wrong-token-for-real-splunk", scheme="Splunk"),
    )
    try:
        await wrong_token_sink.push_events(
            [real_mapper.map(make_detection(tenant, "real-wrong-token"))]
        )
        check("real Splunk container: wrong token raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real Splunk container: wrong token -> real 403/code=4 'Invalid token'",
            exc.context.get("status_code") == 403 and exc.context.get("code") == 4,
            f"context={exc.context}",
        )

    no_auth_sink = SplunkHecSink(REAL_SPLUNK_HEC_URL, NullAuthenticator())
    try:
        await no_auth_sink.push_events([real_mapper.map(make_detection(tenant, "real-no-auth"))])
        check("real Splunk container: missing auth raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real Splunk container: missing Authorization -> real 401/code=2 'Token is required'",
            exc.context.get("status_code") == 401 and exc.context.get("code") == 2,
            f"context={exc.context}",
        )


async def main() -> None:
    # =========================================================================
    # Real local HEC-protocol-accurate stand-in receiver stood up
    # =========================================================================
    hec_server, hec_thread, hec_port = start_http_server(SplunkHecStandInHandler)
    hec_url = f"http://127.0.0.1:{hec_port}/services/collector/event"
    log(f"=== real local Splunk HEC-protocol-accurate stand-in listening on {hec_url} ===")

    setup_engine = create_async_engine(POSTGRES_DSN)
    await PostgresAuditLogRepository.create_tables(setup_engine)
    audit_repo = PostgresAuditLogRepository(setup_engine)
    audit_log = AuditLogService(audit_repo)

    tenant = make_tenant()
    log(f"=== real tenant org_id={tenant.org_id} org_alias={tenant.org_alias} ===")

    await run_real_splunk_scenario(tenant)

    authenticator = StaticTokenAuthenticator(REAL_TOKEN, scheme="Splunk")
    mapper = SplunkDetectionMapper(
        source="kronos:detection_sink", sourcetype="kronos:detection", index="kronos_idx"
    )

    # =========================================================================
    # Scenario 1: real end-to-end push -- Detection -> mapper -> sink -> real
    # HTTP POST -> real receiver -> real {"text": "Success", "code": 0}
    # =========================================================================
    print("\n=== Scenario 1: real end-to-end Detection -> SplunkHecSink push ===")
    sink = SplunkHecSink(hec_url, authenticator)
    detection1 = make_detection(tenant, "ack")
    event1 = mapper.map(detection1)
    ack1 = await sink.push_events([event1])
    check("real push returns ACKNOWLEDGED", ack1.status == SinkAckStatus.ACKNOWLEDGED)
    check("ack.detail carries the real HEC code=0", ack1.detail.get("code") == 0)
    check("ack.detail carries the real HEC text='Success'", ack1.detail.get("text") == "Success")

    received = SplunkHecStandInHandler.received[-1]
    check(
        "real receiver actually saw the real 'Authorization: Splunk <token>' header",
        received["headers"].get("Authorization") == f"Splunk {REAL_TOKEN}",
    )
    parsed_event = received["events"][0]
    check(
        "real receiver's own independent parse recovered exactly 1 event "
        "(concatenated-JSON parsing, not a JSON array)",
        len(received["events"]) == 1,
    )
    check(
        "real envelope: top-level 'source' field is correct",
        parsed_event["source"] == "kronos:detection_sink",
    )
    check(
        "real envelope: top-level 'sourcetype' field is correct",
        parsed_event["sourcetype"] == "kronos:detection",
    )
    check(
        "real envelope: top-level 'index' field is correct", parsed_event["index"] == "kronos_idx"
    )
    check(
        "real envelope: top-level 'host' field defaults to org_alias",
        parsed_event["host"] == tenant.org_alias,
    )
    check(
        "real envelope: 'event' is a nested object, not a string",
        isinstance(parsed_event["event"], dict),
    )
    check(
        "real envelope: nested event carries the real finding_id",
        parsed_event["event"]["finding_id"] == detection1.finding_id,
    )
    check(
        "real envelope: nested event carries the real risk_score",
        parsed_event["event"]["risk_score"] == 63.0,
    )

    # =========================================================================
    # Scenario 2: real deliberate auth-failure case -- wrong token
    # =========================================================================
    print("\n=== Scenario 2: real deliberate auth failure -- wrong token ===")
    wrong_sink = SplunkHecSink(
        hec_url, StaticTokenAuthenticator("wrong-token-xyz", scheme="Splunk")
    )
    try:
        await wrong_sink.push_events([mapper.map(make_detection(tenant, "wrong-token"))])
        check("wrong token raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "wrong token raises IntegrationSinkError with the real HEC 403/code=4 body",
            exc.context.get("status_code") == 403 and exc.context.get("code") == 4,
            f"context={exc.context}",
        )

    # =========================================================================
    # Scenario 3: real missing-header / wrong-scheme cases
    # =========================================================================
    print("\n=== Scenario 3: real missing-Authorization-header / wrong-scheme cases ===")

    no_auth_sink = SplunkHecSink(hec_url, NullAuthenticator())
    try:
        await no_auth_sink.push_events([mapper.map(make_detection(tenant, "no-auth"))])
        check("missing Authorization header raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "missing Authorization header -> real 401/code=2 'Token is required'",
            exc.context.get("status_code") == 401 and exc.context.get("code") == 2,
            f"context={exc.context}",
        )

    bearer_sink = SplunkHecSink(hec_url, StaticTokenAuthenticator(REAL_TOKEN, scheme="Bearer"))
    try:
        await bearer_sink.push_events([mapper.map(make_detection(tenant, "wrong-scheme"))])
        check("wrong auth scheme raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "wrong scheme ('Bearer' not 'Splunk') -> real 401/code=3 'Invalid authorization'",
            exc.context.get("status_code") == 401 and exc.context.get("code") == 3,
            f"context={exc.context}",
        )

    # =========================================================================
    # Scenario 4: real size-limit-adjacent batching -- small max_batch_bytes
    # =========================================================================
    print("\n=== Scenario 4: real batching via a deliberately small max_batch_bytes ===")
    SplunkHecStandInHandler.received.clear()
    detections = [make_detection(tenant, f"batch-{i}") for i in range(5)]
    # Real, MEASURED per-event size for this exact Detection/mapper shape is
    # 902 bytes (independently measured this pass -- a prior estimate of
    # "~450-550 bytes" baked into an earlier version of this PoC was never
    # actually measured and was wrong by ~2x, which is exactly the
    # plausible-but-unverified failure mode CLAUDE.md SS F exists to catch).
    # A 2000-byte ceiling allows 2 events per real HTTP call (2*902=1804 <=
    # 2000) but not 3 (3*902=2706 > 2000), forcing a real 2+2+1 split across
    # 3 real HTTP calls -- proving chunk_events() actually groups multiple
    # events per call under a HEC-realistic byte threshold, not just
    # isolating every event alone (the real, correct, previously-unverified
    # behavior when max_batch_bytes < one event's own size, per
    # chunk_events()'s own documented "single oversized event still yielded
    # alone" contract -- batching.py).
    small_batch_sink = SplunkHecSink(hec_url, authenticator, max_batch_bytes=2000)
    small_batch_service = DetectionSinkPushService(small_batch_sink, mapper, audit_log)
    small_batch_result = await small_batch_service.push(detections, tenant)
    check(
        "chunk_events() split 5 events into >1 real HTTP calls under the small byte ceiling",
        small_batch_result.batch_count > 1,
        f"batch_count={small_batch_result.batch_count}",
    )
    check(
        "chunk_events() actually grouped multiple events per call (not 1-per-call)",
        small_batch_result.batch_count < 5,
        f"batch_count={small_batch_result.batch_count}",
    )
    check(
        "every one of those real HTTP calls was independently ACKNOWLEDGED",
        small_batch_result.all_acknowledged,
    )
    check(
        "the real receiver actually received that many separate real HTTP POSTs",
        len(SplunkHecStandInHandler.received) == small_batch_result.batch_count,
    )
    check(
        "every real receiver-side request body size stayed under the configured ceiling",
        all(r["raw_body_bytes"] <= 2000 for r in SplunkHecStandInHandler.received),
        f"sizes={[r['raw_body_bytes'] for r in SplunkHecStandInHandler.received]}",
    )

    # =========================================================================
    # Scenario 5: DetectionSinkPushService full orchestration + real audit trail
    # =========================================================================
    print(
        "\n=== Scenario 5: DetectionSinkPushService orchestration + real Postgres audit trail ==="
    )
    push_service = DetectionSinkPushService(sink, mapper, audit_log)
    ok_detections = [make_detection(tenant, f"orch-{i}") for i in range(3)]
    result = await push_service.push(ok_detections, tenant)
    check("real push() reports the correct detection_count", result.detection_count == 3)
    check("real push() result is all_acknowledged", result.all_acknowledged)

    print("--- real push() against a deliberately-failing sink, audited then re-raised ---")

    class _AlwaysFailsSink(SplunkHecSink):
        async def push_events(self, events):  # type: ignore[override]
            raise IntegrationSinkError("real, deliberate PoC failure for audit verification")

    failing_service = DetectionSinkPushService(
        _AlwaysFailsSink(hec_url, authenticator), mapper, audit_log
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
    # Only Scenario 4 (small_batch_service) and Scenario 5's own two pushes
    # (push_service, failing_service) go through DetectionSinkPushService --
    # the only class that writes SINK_PUSH_* audit rows. Scenarios 1-3 call
    # SplunkHecSink.push_events() directly (no DetectionSinkPushService, no
    # audit_log) and correctly contribute zero rows here -- an earlier
    # version of this check included a spurious "+1" for those scenarios
    # that was never actually verified against a real count and was wrong.
    expected_attempted_min = small_batch_result.batch_count + 1 + 1
    actual_attempted = event_types.count(AuditEventType.SINK_PUSH_ATTEMPTED)
    check(
        "fresh read: real SINK_PUSH_ATTEMPTED rows exist for every real batch attempted",
        actual_attempted >= expected_attempted_min,
        f"actual={actual_attempted} expected>={expected_attempted_min}",
    )
    check(
        "fresh read: real SINK_PUSH_FAILED row exists for the deliberately-failing push",
        AuditEventType.SINK_PUSH_FAILED in event_types,
    )
    executed_rows = [e for e in events_read if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
    check(
        "fresh read: every real EXECUTED row's own ack_status is honestly ACKNOWLEDGED",
        all(e.details.get("ack_status") == SinkAckStatus.ACKNOWLEDGED.value for e in executed_rows),
    )
    intact, detail = await fresh_audit_log.verify_chain(tenant.org_id)
    check(f"fresh read: real audit hash chain intact end-to-end (detail={detail})", intact)
    await fresh_engine.dispose()

    # =========================================================================
    # Teardown -- nothing left listening.
    # =========================================================================
    await setup_engine.dispose()
    hec_server.shutdown()
    hec_thread.join(timeout=5)

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against a REAL splunk/splunk:9.3.3 container (Scenario 0), a real local "
        f"HEC-protocol-accurate stand-in receiver (Scenarios 1-4), and the real, live "
        f"dev-stack Postgres 16 (Scenario 5)."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
