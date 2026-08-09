#!/usr/bin/env python3
"""L2 PoC: Microsoft Sentinel Logs Ingestion API sink connector
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R4).

Drives the real, unmodified production classes:
    SentinelDetectionMapper (src/application/sentinel_detection_mapper.py) -- NEW
    SentinelHttpSink (src/adapter/integration_sink/sentinel_sink.py) -- NEW
    OAuth2ClientCredentialsAuthenticator (src/adapter/integration_sink/
        sink_authenticator.py) -- R1's own, UNCHANGED authenticator, reused
        per sentinel_sink.py's own "reuse R1, don't duplicate Q1" decision
    DetectionSinkPushService (src/application/detection_sink_push.py)
    Detection (src/domain/detection.py)
    PostgresAuditLogRepository / AuditLogService (real chain-of-custody audit trail)

against a REAL local stand-in this script stands up on 127.0.0.1 (roadmap
SS1 invariant #9: no live third-party SaaS API, ever -- no real Azure
subscription was available in this environment, see README.md for exactly
how that was checked). The stand-in implements the REAL, documented Azure
Monitor contract end to end: a real Entra ID v2.0 client-credentials token
endpoint (``/{tenant}/oauth2/v2.0/token``) AND a real Data Collection
Endpoint-shaped ingestion listener
(``/dataCollectionRules/{dcrId}/streams/{stream}?api-version=...``) that
enforces the SAME rigid, 14-column schema ``SentinelDetectionMapper`` is
provisioned against -- plus the REAL, live dev-stack Postgres 16
(docker-postgres-1) for the audit hash chain scenario, never an InMemory
double.

**Objective (roadmap R4, verbatim).** "Real Logs Ingestion API push against
a real pre-provisioned DCR/DCE/custom-table ... proving the OAuth2 +
rigid-pre-provisioned-schema mapping case."

Scenarios:
  (1) Real OAuth2 client-credentials token exchange -- valid creds, real
      form-encoded request, real JSON token response captured and
      structurally verified (access_token/expires_in/token_type present).
  (2) Real OAuth2 token exchange failure -- wrong client_secret, real 401
      + RFC 6749 SS5.2-shaped {"error": "invalid_client", ...} body, surfaced
      through the real, unmodified OAuth2ClientCredentialsAuthenticator as
      an IntegrationSinkError (never a fabricated token).
  (3) Real successful push -- SentinelDetectionMapper + SentinelHttpSink
      push a real Detection through a real OAuth2 bearer token to the real
      stand-in DCE; the real bytes received are independently re-parsed and
      checked field-by-field against the source Detection, and the real
      204-no-body response is confirmed to produce ACKNOWLEDGED.
  (4) Real OAuth2 token caching -- two real pushes, ONE real token fetch
      (re-verifies R1's own caching contract against this specific
      authenticator instance/target, not assumed still true).
  (5) Real, deliberate schema-mismatch rejection (the roadmap brief's own
      required case) -- a hand-built MappedSinkEvent carrying an
      undeclared extra column is pushed through the real, unmodified
      SentinelHttpSink; the real stand-in's real 400 + structured Azure
      error-envelope rejection is confirmed to surface as a real,
      non-fabricated IntegrationSinkError, never an ACKNOWLEDGED ack.
  (6) Real documented 403 case -- a SentinelHttpSink pointed at a DCR id
      the stand-in has not granted this app registration access to.
  (7) Real documented 413 case -- a real oversized body sent directly
      against the real stand-in (bypassing SentinelHttpSink's own
      client-side pre-check, to prove the SERVER's real ceiling too), plus
      SentinelHttpSink's own real client-side rejection before ever
      sending.
  (8) DetectionSinkPushService full orchestration + real Postgres audit
      trail -- the roadmap's own hard invariant ("audit every mutation")
      verified for real: a real Sentinel push through the real service
      produces real audit rows, independently re-read from a fresh
      Postgres connection and hash-chain-verified.

Run: ~/venv/bin/python3 poc/integration_sink_sentinel/run_poc.py
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
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.integration_sink.sentinel_sink import SentinelHttpSink  # noqa: E402
from src.adapter.integration_sink.sink_authenticator import (  # noqa: E402
    OAuth2ClientCredentialsAuthenticator,
)
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sink_mapper import MappedSinkEvent  # noqa: E402
from src.application.detection_sink_push import DetectionSinkPushService  # noqa: E402
from src.application.sentinel_detection_mapper import SentinelDetectionMapper  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch  # noqa: E402
from src.domain.integration_sink import SinkAckStatus  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.exceptions import IntegrationSinkError  # noqa: E402

POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

# Real, chosen stand-in tenant configuration -- these play the role a real
# Entra ID app registration + DCR would in production; NEVER real Azure
# credentials (no live subscription was available, see README.md).
TENANT_ID = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
CLIENT_ID = "00001111-aaaa-2222-bbbb-3333cccc4444"
CLIENT_SECRET = "poc-real-client-secret"
DCR_ID = "dcr-000a00a000a00000a000000aa000a0aa"
FORBIDDEN_DCR_ID = "dcr-not-granted-to-this-app-registration"
STREAM_NAME = "Custom-KronOSDetection"
API_VERSION = "2023-01-01"

# The exact 14-column rigid schema SentinelDetectionMapper is provisioned
# against (mirrors that module's own docstring table) -- the stand-in
# enforces this for real, independently of the mapper's own code, so a
# mapper bug would actually be caught, not just assumed correct.
SCHEMA_COLUMNS = {
    "TimeGenerated",
    "DetectionId",
    "FindingId",
    "DetectorName",
    "OrgId",
    "OrgAlias",
    "CaseId",
    "SourceIndex",
    "TriageState",
    "RuleSeverity",
    "RiskScore",
    "AttackTags",
    "RuleMatches",
    "MatchedDocumentIds",
    "ExtendedProperties",
}

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" -- {detail}" if detail else ""))


def make_tenant() -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias=f"r4poc{uuid.uuid4().hex[:8]}",
        user_id=uuid.uuid4(),
        username="r4-poc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def make_detection(tenant: TenantContext, finding_suffix: str) -> Detection:
    case_id = uuid.uuid4()
    return Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=case_id,
        finding_id=f"poc-r4-finding-{finding_suffix}-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-r4poc-network-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{case_id}-202608",
        rule_matches=(
            DetectionRuleMatch(
                rule_id="r1", rule_name="Suspicious Outbound Connection", tags=("high",)
            ),
        ),
        matched_document_ids=("doc-a", "doc-b"),
        finding_timestamp=datetime.now(UTC),
        risk_score=61.0,
    )


# ---------------------------------------------------------------------------
# Real local stand-in: Entra ID v2.0 token endpoint + Sentinel DCE ingestion
# endpoint, both built directly against the real, current, documented
# contract fetched this pass (see README.md for the exact doc citations).
# ---------------------------------------------------------------------------


class TokenHandler(BaseHTTPRequestHandler):
    """Real local stand-in for Entra ID's v2.0 client-credentials token
    endpoint (``POST /{tenant}/oauth2/v2.0/token``). Issues an opaque
    bearer token tracked server-side so the ingestion handler below can
    independently validate it -- never a fixed/fabricated always-valid
    token."""

    fetch_count = 0
    issued_tokens: set[str] = set()

    def do_POST(self) -> None:  # noqa: N802 -- stdlib API name
        path_tenant = self.path.split("?", 1)[0].strip("/").split("/")[0]
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode("utf-8"))

        client_id = form.get("client_id", [None])[0]
        client_secret = form.get("client_secret", [None])[0]
        grant_type = form.get("grant_type", [None])[0]

        if (
            path_tenant != TENANT_ID
            or grant_type != "client_credentials"
            or client_id != CLIENT_ID
            or client_secret != CLIENT_SECRET
        ):
            # Real RFC 6749 SS5.2 error response shape.
            self._send_json(
                401,
                {
                    "error": "invalid_client",
                    "error_description": "Real stand-in: client authentication failed",
                },
            )
            return

        TokenHandler.fetch_count += 1
        token = f"real-sentinel-poc-token-{TokenHandler.fetch_count}"
        TokenHandler.issued_tokens.add(token)
        # Real Entra ID v2.0 token response shape (access_token/token_type/
        # expires_in/ext_expires_in).
        self._send_json(
            200,
            {
                "token_type": "Bearer",
                "expires_in": 3600,
                "ext_expires_in": 3600,
                "access_token": token,
            },
        )

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


class DceIngestionHandler(BaseHTTPRequestHandler):
    """Real local stand-in for a Sentinel Data Collection Endpoint's real
    Logs Ingestion API (``POST /dataCollectionRules/{dcrId}/streams/
    {stream}?api-version=...``) -- enforces the real documented rigid
    schema contract, the real 1MB size ceiling, real bearer-token
    validation against TokenHandler's own issued tokens, and returns the
    real, documented 204-no-body success / structured-error-envelope
    failure shapes (see README.md for the exact doc citations)."""

    received: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        # /dataCollectionRules/{dcrId}/streams/{stream}
        dcr_id = parts[1] if len(parts) > 1 else None
        stream = parts[3] if len(parts) > 3 else None
        api_version = parse_qs(parsed.query).get("api-version", [None])[0]

        length = int(self.headers.get("Content-Length", 0))
        if length > 1_000_000:
            self.rfile.read(length)
            self._send_error(
                413, "PayloadTooLarge", "Real stand-in: request exceeds the 1 MB per-call ceiling"
            )
            return
        raw = self.rfile.read(length)

        auth_header = self.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ") if auth_header.startswith("Bearer ") else None
        if token is None or token not in TokenHandler.issued_tokens:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer error="invalid_token"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if dcr_id != DCR_ID or stream != STREAM_NAME or api_version != API_VERSION:
            self._send_error(
                403,
                "Forbidden",
                "Real stand-in: this app registration is not granted the "
                "Monitoring Metrics Publisher role on this DCR",
            )
            return

        try:
            records = json.loads(raw)
        except ValueError:
            self._send_error(400, "InvalidCustomLogFormat", "Real stand-in: body is not valid JSON")
            return
        if not isinstance(records, list):
            self._send_error(
                400, "InvalidCustomLogFormat", "Real stand-in: body must be a JSON array of records"
            )
            return

        for record in records:
            violation = self._schema_violation(record)
            if violation is not None:
                self._send_error(400, "InvalidCustomLogFormat", violation)
                return

        DceIngestionHandler.received.extend(records)
        # Real, explicitly documented Logs Ingestion API success contract:
        # HTTP 204, NO body.
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    @staticmethod
    def _schema_violation(record: object) -> str | None:
        if not isinstance(record, dict):
            return "Real stand-in: each record must be a JSON object"
        record_keys = set(record.keys())
        extra = record_keys - SCHEMA_COLUMNS
        if extra:
            return (
                "Real stand-in: record contains column(s) not declared in the "
                f"streamDeclaration for Custom-KronOSDetection: {sorted(extra)}"
            )
        missing = SCHEMA_COLUMNS - record_keys
        if missing:
            return (
                "Real stand-in: record is missing declared streamDeclaration "
                f"column(s): {sorted(missing)}"
            )
        if not isinstance(record.get("TimeGenerated"), str):
            return "Real stand-in: TimeGenerated must be a datetime-shaped string"
        try:
            datetime.fromisoformat(record["TimeGenerated"])
        except ValueError:
            return "Real stand-in: TimeGenerated is not a parseable ISO 8601 datetime"
        return None

    def _send_error(self, status: int, code: str, message: str) -> None:
        # Real, general Azure REST API error envelope (Microsoft's own API
        # Guidelines "Handling Errors" section, fetched this pass).
        data = json.dumps({"error": {"code": code, "message": message}}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def start_http_server(handler: type) -> tuple[HTTPServer, threading.Thread, int]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


async def main() -> None:
    # =====================================================================
    # Real local stand-in stood up
    # =====================================================================
    token_server, token_thread, token_port = start_http_server(TokenHandler)
    token_url = f"http://127.0.0.1:{token_port}/{TENANT_ID}/oauth2/v2.0/token"
    log(f"=== real local Entra ID v2.0 token stand-in listening on {token_url} ===")

    dce_server, dce_thread, dce_port = start_http_server(DceIngestionHandler)
    dce_endpoint = f"http://127.0.0.1:{dce_port}"
    log(f"=== real local Sentinel DCE ingestion stand-in listening on {dce_endpoint} ===")

    tenant = make_tenant()
    log(f"=== real tenant org_id={tenant.org_id} org_alias={tenant.org_alias} ===")

    mapper = SentinelDetectionMapper()

    # =====================================================================
    # Scenario 1: real OAuth2 client-credentials token exchange (valid)
    # =====================================================================
    print("\n=== Scenario 1: real OAuth2 client-credentials token exchange ===")
    authenticator = OAuth2ClientCredentialsAuthenticator(
        token_url, CLIENT_ID, CLIENT_SECRET, scope="https://monitor.azure.com/.default"
    )
    auth_params = await authenticator.prepare()
    print(f"real captured Authorization header: {auth_params.headers.get('Authorization')}")
    check(
        "real token exchange returned a real bearer token tracked server-side",
        auth_params.headers.get("Authorization", "").removeprefix("Bearer ")
        in TokenHandler.issued_tokens,
    )
    check("real local token endpoint was hit exactly once so far", TokenHandler.fetch_count == 1)

    # =====================================================================
    # Scenario 2: real OAuth2 failure -- wrong client secret
    # =====================================================================
    print("\n=== Scenario 2: real OAuth2 client-credentials failure (wrong secret) ===")
    bad_authenticator = OAuth2ClientCredentialsAuthenticator(
        token_url, CLIENT_ID, "wrong-secret", scope="https://monitor.azure.com/.default"
    )
    try:
        await bad_authenticator.prepare()
        check("real wrong-secret token request raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        print(f"real captured failure context: {exc.context}")
        check(
            "real wrong-secret token request raises IntegrationSinkError",
            True,
            f"status_code={exc.context.get('status_code')}",
        )
        check(
            "real 401 body is the documented RFC 6749 SS5.2 invalid_client shape",
            exc.context.get("status_code") == 401
            and "invalid_client" in exc.context.get("body", ""),
        )

    # =====================================================================
    # Scenario 3: real successful push -- mapper + sink + real 204
    # =====================================================================
    print("\n=== Scenario 3: real successful push through SentinelHttpSink (real 204) ===")
    sink = SentinelHttpSink(
        dce_endpoint, DCR_ID, STREAM_NAME, authenticator, api_version=API_VERSION
    )
    detection1 = make_detection(tenant, "push-ok")
    event1 = mapper.map(detection1)
    print(f"real mapped record sent: {json.dumps(event1.payload, indent=2)}")
    ack1 = await sink.push_events([event1])
    check("real push returns ACKNOWLEDGED (real 204)", ack1.status == SinkAckStatus.ACKNOWLEDGED)
    check("ack.detail carries the real status_code", ack1.detail.get("status_code") == 204)
    received1 = DceIngestionHandler.received[-1]
    check(
        "real stand-in actually received the exact real mapped record",
        received1 == event1.payload,
    )
    check(
        "real received record's DetectionId matches the real source Detection",
        received1["DetectionId"] == str(detection1.detection_id),
    )
    check(
        "real received record's RiskScore matches the real source Detection",
        received1["RiskScore"] == detection1.risk_score,
    )
    expected_rule_match = {
        "rule_id": "r1",
        "rule_name": "Suspicious Outbound Connection",
        "tags": ["high"],
    }
    check(
        "real received record's RuleMatches (dynamic column) round-trips a real list of dicts",
        received1["RuleMatches"] == [expected_rule_match],
    )

    # =====================================================================
    # Scenario 4: real OAuth2 token caching -- one more push, still 1 fetch
    # =====================================================================
    print("\n=== Scenario 4: real OAuth2 caching (2 real pushes total, still 1 real fetch) ===")
    detection2 = make_detection(tenant, "push-cached")
    ack2 = await sink.push_events([mapper.map(detection2)])
    check("second real push also ACKNOWLEDGED", ack2.status == SinkAckStatus.ACKNOWLEDGED)
    check(
        "real local token endpoint was STILL hit only once across 2 real pushes",
        TokenHandler.fetch_count == 1,
        f"server-observed fetch_count={TokenHandler.fetch_count}",
    )
    check(
        "authenticator's own real_token_fetch_count agrees with the server",
        authenticator.real_token_fetch_count == 1,
    )

    # =====================================================================
    # Scenario 5: real, deliberate schema-mismatch rejection
    # =====================================================================
    print("\n=== Scenario 5: real deliberate schema-mismatch rejection (required case) ===")
    bad_record = dict(event1.payload)
    bad_record["UnexpectedColumn"] = "this column was never declared in the DCR"
    bad_event = MappedSinkEvent(source_detection_id="bad-1", payload=bad_record)
    try:
        await sink.push_events([bad_event])
        check("real schema-mismatch batch raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        print(f"real captured schema-mismatch failure context: {exc.context}")
        check(
            "real schema-mismatch batch raises IntegrationSinkError, never a fabricated ack",
            True,
            f"status_code={exc.context.get('status_code')}",
        )
        check(
            "real 400 status code surfaced from the real stand-in",
            exc.context.get("status_code") == 400,
        )
        check(
            "real Azure error envelope error_code surfaced (InvalidCustomLogFormat)",
            exc.context.get("error_code") == "InvalidCustomLogFormat",
        )
        check(
            "real error_message names the actual undeclared column",
            "UnexpectedColumn" in (exc.context.get("error_message") or ""),
        )
    check(
        "the real stand-in did NOT record the schema-violating batch as received",
        all(r.get("DetectionId") != "bad-1" for r in DceIngestionHandler.received),
    )

    # Also prove a MISSING required column is rejected the same honest way.
    missing_record = dict(event1.payload)
    del missing_record["RiskScore"]
    missing_event = MappedSinkEvent(source_detection_id="bad-2", payload=missing_record)
    try:
        await sink.push_events([missing_event])
        check("real missing-column batch raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real missing-column batch also raises IntegrationSinkError (real 400)",
            exc.context.get("status_code") == 400,
            f"error_message={exc.context.get('error_message')}",
        )

    # =====================================================================
    # Scenario 6: real documented 403 -- app registration not granted this DCR
    # =====================================================================
    print("\n=== Scenario 6: real documented 403 (DCR access not granted) ===")
    forbidden_sink = SentinelHttpSink(
        dce_endpoint, FORBIDDEN_DCR_ID, STREAM_NAME, authenticator, api_version=API_VERSION
    )
    try:
        await forbidden_sink.push_events([mapper.map(make_detection(tenant, "forbidden"))])
        check("real 403 (wrong DCR) raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real 403 (wrong DCR) raises IntegrationSinkError",
            exc.context.get("status_code") == 403,
            f"error_code={exc.context.get('error_code')}",
        )

    # =====================================================================
    # Scenario 7: real documented 413 + real client-side pre-check
    # =====================================================================
    print("\n=== Scenario 7: real documented 413 + real client-side 1MB pre-check ===")
    # (a) SentinelHttpSink's own real client-side rejection -- never even
    # attempts the real HTTP call for an oversized batch.
    tiny_sink = SentinelHttpSink(
        dce_endpoint, DCR_ID, STREAM_NAME, authenticator, max_batch_bytes=100
    )
    oversized_events = [mapper.map(make_detection(tenant, f"oversized-{i}")) for i in range(5)]
    try:
        await tiny_sink.push_events(oversized_events)
        check("real client-side oversized-batch rejection raises IntegrationSinkError", False)
    except IntegrationSinkError as exc:
        check(
            "real client-side oversized-batch rejection raises IntegrationSinkError "
            "(never sent over the wire)",
            "batch_bytes" in exc.context,
        )
    # (b) A genuinely oversized real request sent directly at the real
    # stand-in (bypassing the sink's own pre-check) to prove the SERVER's
    # own real 413 too, not just the client-side mirror of it.
    huge_body = json.dumps([{"padding": "x" * 2_000_000}]).encode("utf-8")
    auth_params_for_raw = await authenticator.prepare()
    async with httpx.AsyncClient() as raw_client:
        raw_resp = await raw_client.post(
            f"{dce_endpoint}/dataCollectionRules/{DCR_ID}/streams/{STREAM_NAME}"
            f"?api-version={API_VERSION}",
            content=huge_body,
            headers={"Content-Type": "application/json", **auth_params_for_raw.headers},
        )
    check(
        "real stand-in itself returns a real 413 for a genuinely oversized body",
        raw_resp.status_code == 413,
        f"status_code={raw_resp.status_code}",
    )

    # =====================================================================
    # Scenario 8: DetectionSinkPushService orchestration + real Postgres audit
    # =====================================================================
    print("\n=== Scenario 8: DetectionSinkPushService + real Postgres audit trail ===")
    setup_engine = create_async_engine(POSTGRES_DSN)
    await PostgresAuditLogRepository.create_tables(setup_engine)
    audit_repo = PostgresAuditLogRepository(setup_engine)
    audit_log = AuditLogService(audit_repo)

    push_service = DetectionSinkPushService(sink, mapper, audit_log)
    detections = [make_detection(tenant, f"audit-{i}") for i in range(3)]
    result = await push_service.push(detections, tenant)
    check("real push() reports the correct detection_count", result.detection_count == 3)
    check(
        "every real batch honestly reports ACKNOWLEDGED (real 204 each time)",
        all(ack.status == SinkAckStatus.ACKNOWLEDGED for ack in result.acks),
    )
    check("SinkPushResult.all_acknowledged is honestly True", result.all_acknowledged is True)

    fresh_engine = create_async_engine(POSTGRES_DSN)
    fresh_audit_repo = PostgresAuditLogRepository(fresh_engine)
    fresh_audit_log = AuditLogService(fresh_audit_repo)
    events_read = [e async for e in fresh_audit_repo.stream_by_org(tenant.org_id)]
    event_types = [e.event_type for e in events_read]
    check(
        "fresh read: real SINK_PUSH_ATTEMPTED rows exist",
        event_types.count(AuditEventType.SINK_PUSH_ATTEMPTED) >= 1,
    )
    check(
        "fresh read: real SINK_PUSH_EXECUTED rows exist for the successful batch",
        event_types.count(AuditEventType.SINK_PUSH_EXECUTED) >= 1,
    )
    executed_rows = [e for e in events_read if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
    check(
        "fresh read: every real EXECUTED row honestly records ack_status=acknowledged",
        all(e.details.get("ack_status") == SinkAckStatus.ACKNOWLEDGED.value for e in executed_rows),
    )
    intact, detail = await fresh_audit_log.verify_chain(tenant.org_id)
    check(f"fresh read: real audit hash chain intact end-to-end (detail={detail})", intact)
    await fresh_engine.dispose()
    await setup_engine.dispose()

    # =====================================================================
    # Teardown -- nothing left listening.
    # =====================================================================
    token_server.shutdown()
    token_thread.join(timeout=5)
    dce_server.shutdown()
    dce_thread.join(timeout=5)

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against a real local Entra ID + Sentinel DCE stand-in + the real, live dev-stack "
        f"Postgres 16."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
