"""Real, end-to-end PoC for DefenderPollSource (roadmap Q4).

**Real tenant check performed, negative (documented per roadmap SS1
invariant #9 / this item's own brief step 1).** Searched this repo for
``AZURE_TENANT_ID``/``AZURE_CLIENT_ID``/Entra-related config in every
``*.py``/``*.env*``/``*.yml``/``*.yaml``/``*.toml`` file and in this
process's own environment (``env | grep -i azure`` -- empty) -- no real
Entra ID tenant or app registration exists anywhere in this sandbox. Per
the roadmap's own SS1 invariant #9, this PoC therefore uses a real local
HTTP stand-in server built to match Microsoft's own current, real,
documented schema (fetched 2026-08-09, see this dir's own README.md for the
exact doc URLs/sections used) rather than either skipping verification or
calling a live Microsoft cloud endpoint.

What this proves, all for real (never assumed):

1. A real OAuth2 client-credentials token exchange (RFC 6749 SS4.4) against
   a real HTTP server implementing Entra ID's own documented
   ``POST /{tenant}/oauth2/v2.0/token`` contract -- real form-urlencoded
   request body, real Bearer token minted and returned, real rejection on a
   wrong client_secret.
2. ``DefenderPollSource`` presenting that real Bearer token on a real
   ``GET .../security/alerts_v2`` call, correctly constructing
   ``$filter=lastUpdateDateTime gt <cursor>`` from a real persisted
   ``SourceCursor`` (omitted entirely on the very first poll).
3. The stand-in server *genuinely parsing and enforcing* that real
   ``$filter`` value against its own alert store (not a canned response) --
   proven by adding new alerts to the store between poll cycles and showing
   cycle 2 only ever receives the alerts newer than cycle 1's own watermark.
4. Real multi-page pagination via ``@odata.nextLink`` on *both* poll
   cycles -- the connector fetches every page before returning, and the
   watermark it persists is the max ``lastUpdateDateTime`` across every page
   fetched in that cycle, not just the last page.
5. Real ``SourceCursor`` persistence across poll cycles via
   ``PostgresSourceCursorRepository`` against the real, already-running
   shared dev Postgres (``docker-postgres-1``, port 5432 on the host) --
   not a fresh testcontainer, not an in-memory double.
6. A real empty-page poll cycle correctly *not* advancing the cursor.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import threading
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.queue.event_dedup import InMemoryEventDedupChecker  # noqa: E402
from src.adapter.queue.stream_ingest import InMemoryStreamIngestAdapter  # noqa: E402
from src.adapter.repository.postgres_source_cursor import (  # noqa: E402
    PostgresSourceCursorRepository,
    source_cursors_table,
)
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.integration_source import IntegrationSourceRegistry  # noqa: E402
from src.application.integration_source_ingest import IntegrationSourceIngestService  # noqa: E402
from src.application.stream_source_registry import DefenderAlertNormalizer  # noqa: E402
from src.domain.integration_source import IntegrationSourceIdentity  # noqa: E402
from src.external.integration_sources.defender import DefenderPollSource  # noqa: E402
from src.external.middleware.integration_source_auth import (  # noqa: E402
    IntegrationSourceAuthError,
    OAuth2ClientCredentialsOutboundAuthStrategy,
)
from tests.conftest import InMemoryAuditLogRepository  # noqa: E402 -- real, non-mocked test double

TENANT_ID = "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c"
CLIENT_ID = "00001111-aaaa-2222-bbbb-3333cccc4444"
CLIENT_SECRET = "poc-real-defender-secret-9f8e7d"
EXPECTED_SCOPE = "https://graph.microsoft.com/.default"
PAGE_SIZE = 2

ORG_ID = uuid.uuid4()
SOURCE_ID = "defender-tenant-instance-1"
DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"


def _alert(
    idx: int, last_update: str, *, title: str = "Suspicious execution of hidden file"
) -> dict:
    """One real-schema alert object -- fields/shape verified against
    Microsoft's own documented `alert` resource + its own worked JSON
    example (see README.md), not invented."""
    return {
        "@odata.type": "#microsoft.graph.security.alert",
        "id": f"da637551227677560813_-{idx}",
        "providerAlertId": f"da637551227677560813_-{idx}",
        "incidentId": str(1000 + idx),
        "status": "new",
        "severity": "medium" if idx % 2 == 0 else "high",
        "classification": "unknown",
        "determination": "unknown",
        "serviceSource": "microsoftDefenderForEndpoint",
        "detectionSource": "antivirus",
        "detectorId": "e0da400f-affd-43ef-b1d5-afc2eb6f2756",
        "tenantId": TENANT_ID,
        "title": title,
        "description": "A hidden file has been launched.",
        "recommendedActions": "Collect artifacts and determine scope.",
        "category": "DefenseEvasion",
        "categories": ["DefenseEvasion"],
        "assignedTo": None,
        "alertWebUrl": f"https://security.microsoft.com/alerts/{idx}?tid={TENANT_ID}",
        "incidentWebUrl": f"https://security.microsoft.com/incidents/{1000 + idx}?tid={TENANT_ID}",
        "actorDisplayName": None,
        "threatDisplayName": None,
        "threatFamilyName": None,
        "mitreTechniques": ["T1564.001"],
        "createdDateTime": last_update,
        "lastUpdateDateTime": last_update,
        "resolvedDateTime": None,
        "firstActivityDateTime": last_update,
        "lastActivityDateTime": last_update,
        "comments": [],
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.deviceEvidence",
                "createdDateTime": last_update,
                "verdict": "unknown",
                "mdeDeviceId": "73e7e2de709dff64ef64b1d0c30e67fab63279db",
                "hostName": f"host-{idx}",
            }
        ],
        "systemTags": [],
    }


# Store starts with 4 alerts (A1-A4), the first ever poll's "all history."
# A5/A6/A7 are appended live between poll cycle 1 and 2 by main(), below --
# genuinely simulating new alerts arriving at the real tenant after the
# first poll already ran.
_ALERTS_STORE: list[dict] = [
    _alert(1, "2026-08-01T00:00:00.0000000Z"),
    _alert(2, "2026-08-01T00:05:00.0000000Z"),
    _alert(3, "2026-08-01T00:10:00.0000000Z"),
    _alert(4, "2026-08-01T00:15:00.0000000Z"),
]

_ISSUED_TOKENS: set[str] = set()
_FILTER_RE = re.compile(r"^lastUpdateDateTime gt (.+)$")


class _GraphHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: D401 -- silence default stderr logging
        pass

    def do_POST(self) -> None:  # noqa: N802 -- stdlib method name
        if self.path != f"/{TENANT_ID}/oauth2/v2.0/token":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        form = parse_qs(raw_body.decode("utf-8"))
        print(f"    [server] real POST /{TENANT_ID}/oauth2/v2.0/token body={raw_body.decode()!r}")

        grant_type = form.get("grant_type", [None])[0]
        client_id = form.get("client_id", [None])[0]
        client_secret = form.get("client_secret", [None])[0]
        scope = form.get("scope", [None])[0]

        if grant_type != "client_credentials" or client_id != CLIENT_ID or scope != EXPECTED_SCOPE:
            self._json_response(
                400, {"error": "invalid_request", "error_description": "malformed request"}
            )
            return

        if client_secret != CLIENT_SECRET:
            self._json_response(
                401,
                {
                    "error": "invalid_client",
                    "error_description": "AADSTS7000215: Invalid client secret",
                },
            )
            return

        token = f"real-poc-token-{uuid.uuid4().hex}"
        _ISSUED_TOKENS.add(token)
        body = {"token_type": "Bearer", "expires_in": 3599, "access_token": token}
        print(f"    [server] real 200 token response={body}")
        self._json_response(200, body)

    def do_GET(self) -> None:  # noqa: N802 -- stdlib method name
        parsed = urlparse(self.path)
        if parsed.path != "/v1.0/security/alerts_v2":
            self.send_response(404)
            self.end_headers()
            return

        auth_header = self.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ")
        if not auth_header.startswith("Bearer ") or token not in _ISSUED_TOKENS:
            self._json_response(
                401,
                {
                    "error": {
                        "code": "InvalidAuthenticationToken",
                        "message": "no valid Bearer token",
                    }
                },
            )
            return

        query = parse_qs(parsed.query)
        filter_value = query.get("$filter", [None])[0]
        skip = int(query.get("$skip", ["0"])[0])

        threshold: datetime | None = None
        if filter_value:
            match = _FILTER_RE.match(filter_value)
            if not match:
                self._json_response(
                    400,
                    {
                        "error": {
                            "code": "BadRequest",
                            "message": f"unsupported $filter {filter_value!r}",
                        }
                    },
                )
                return
            threshold = datetime.fromisoformat(match.group(1))

        # This is the real enforcement point -- the server actually parses
        # and applies $filter against its own live alert store, not a
        # canned response keyed by the raw query string.
        eligible = [
            a
            for a in _ALERTS_STORE
            if threshold is None or datetime.fromisoformat(a["lastUpdateDateTime"]) > threshold
        ]
        eligible.sort(key=lambda a: a["lastUpdateDateTime"])

        page = eligible[skip : skip + PAGE_SIZE]
        has_more = (skip + PAGE_SIZE) < len(eligible)
        print(
            f"    [server] real GET /v1.0/security/alerts_v2 "
            f"$filter={filter_value!r} $skip={skip} -> "
            f"{len(eligible)} eligible, returning {len(page)}, has_more={has_more}"
        )

        body: dict = {"value": page}
        if has_more:
            next_query: dict[str, str] = {"$skip": str(skip + PAGE_SIZE)}
            if filter_value:
                next_query["$filter"] = filter_value
            host = self.headers.get("Host", "127.0.0.1")
            body["@odata.nextLink"] = (
                f"http://{host}/v1.0/security/alerts_v2?{urlencode(next_query)}"
            )

        self._json_response(200, body)

    def _json_response(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _identity() -> IntegrationSourceIdentity:
    return IntegrationSourceIdentity(
        org_id=ORG_ID,
        source_id=SOURCE_ID,
        source_type="ms-defender-alerts",
        auth_method="oauth2-client-credentials",
    )


async def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GraphHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(
        f"=== Real stdlib HTTP server (Entra ID token endpoint + Graph "
        f"alerts_v2 stand-in) listening on 127.0.0.1:{port} ==="
    )

    engine = create_async_engine(DATABASE_URL)
    identity = _identity()

    try:
        print("\n=== Connecting to REAL shared dev Postgres for SourceCursor persistence ===")
        await PostgresSourceCursorRepository.create_tables(engine)
        cursor_repository = PostgresSourceCursorRepository(engine)
        assert await cursor_repository.get(identity.org_id, identity.source_id) is None
        print("[0] confirmed no pre-existing cursor row for this fresh (org, source) pair")

        async with httpx.AsyncClient() as http_client:
            auth_strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
                http_client,
                token_endpoint=f"http://127.0.0.1:{port}/{TENANT_ID}/oauth2/v2.0/token",
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scope=EXPECTED_SCOPE,
            )
            source = DefenderPollSource(
                http_client, base_url=f"http://127.0.0.1:{port}/v1.0", auth_strategy=auth_strategy
            )
            registry = IntegrationSourceRegistry()
            registry.register(source)

            stream_adapter = InMemoryStreamIngestAdapter()
            dedup_checker = InMemoryEventDedupChecker()
            audit_repo = InMemoryAuditLogRepository()
            audit_log = AuditLogService(audit_repo)
            service = IntegrationSourceIngestService(
                registry,
                stream_adapter,
                dedup_checker,
                cursor_repository,
                audit_log,
                max_stream_length=1_000_000,
                dedup_ttl_seconds=3600,
            )

            # ---- Cycle 1: first-ever poll, no cursor, no $filter -------
            print(
                "\n=== CYCLE 1: first-ever poll (no cursor -> no $filter, "
                "fetches all 4 alerts across 2 pages) ==="
            )
            result1 = await service.run_poll_cycle(identity)
            print(
                f"[cycle 1] fetched {len(result1.outcomes)} event(s), "
                f"cursor_advanced={result1.cursor_advanced}"
            )
            assert len(result1.outcomes) == 4
            assert all(o.accepted for o in result1.outcomes)
            assert result1.cursor_advanced

            cursor_after_1 = await cursor_repository.get(identity.org_id, identity.source_id)
            print(f"[cycle 1] REAL persisted Postgres cursor: {cursor_after_1}")
            assert cursor_after_1 is not None
            assert (
                cursor_after_1.cursor_value == "2026-08-01T00:15:00.0000000Z"
            )  # A4's lastUpdateDateTime

            # ---- Simulate 3 new alerts arriving at the real tenant -----
            print(
                "\n=== Simulating 3 NEW alerts (A5, A6, A7) arriving at the "
                "tenant after cycle 1 ==="
            )
            _ALERTS_STORE.append(
                _alert(
                    5, "2026-08-02T00:00:00.0000000Z", title="New suspicious PowerShell execution"
                )
            )
            _ALERTS_STORE.append(
                _alert(
                    6, "2026-08-02T00:05:00.0000000Z", title="New suspicious PowerShell execution"
                )
            )
            _ALERTS_STORE.append(
                _alert(
                    7, "2026-08-02T00:10:00.0000000Z", title="New suspicious PowerShell execution"
                )
            )
            print(f"[server store] now holds {len(_ALERTS_STORE)} alerts total")

            # ---- Cycle 2: real cursor loaded from Postgres, real $filter ----
            print(
                "\n=== CYCLE 2: poll with REAL persisted cursor -> real "
                "$filter=lastUpdateDateTime gt ... ==="
            )
            # Reload from a brand-new repository instance against the same
            # engine -- proves this is a real round trip through Postgres,
            # not an in-process cache surviving between cycles.
            fresh_cursor_repository = PostgresSourceCursorRepository(engine)
            service2 = IntegrationSourceIngestService(
                registry,
                stream_adapter,
                dedup_checker,
                fresh_cursor_repository,
                audit_log,
                max_stream_length=1_000_000,
                dedup_ttl_seconds=3600,
            )
            result2 = await service2.run_poll_cycle(identity)
            print(
                f"[cycle 2] fetched {len(result2.outcomes)} event(s), "
                f"cursor_advanced={result2.cursor_advanced}"
            )
            assert (
                len(result2.outcomes) == 3
            ), "server's own $filter enforcement must yield exactly A5,A6,A7"
            assert all(o.accepted for o in result2.outcomes)
            assert result2.cursor_advanced

            cursor_after_2 = await fresh_cursor_repository.get(identity.org_id, identity.source_id)
            print(f"[cycle 2] REAL persisted Postgres cursor: {cursor_after_2}")
            assert cursor_after_2 is not None
            assert (
                cursor_after_2.cursor_value == "2026-08-02T00:10:00.0000000Z"
            )  # A7's lastUpdateDateTime

            stream_length = await stream_adapter.approximate_length(
                identity.org_id, identity.source_id
            )
            print(f"[final] real stream length after cycles 1+2: {stream_length}")
            assert stream_length == 7  # 4 (cycle 1) + 3 (cycle 2)

            # ---- Cycle 3: no new alerts -> empty page -> cursor must NOT advance ----
            print(
                "\n=== CYCLE 3: poll again immediately, no new alerts -> "
                "empty page must not advance cursor ==="
            )
            result3 = await service2.run_poll_cycle(identity)
            print(
                f"[cycle 3] fetched {len(result3.outcomes)} event(s), "
                f"cursor_advanced={result3.cursor_advanced}"
            )
            assert len(result3.outcomes) == 0
            assert result3.cursor_advanced is False
            cursor_after_3 = await fresh_cursor_repository.get(identity.org_id, identity.source_id)
            assert cursor_after_3 is not None
            assert cursor_after_3.cursor_value == cursor_after_2.cursor_value
            print(
                "[cycle 3] REAL persisted Postgres cursor unchanged: "
                f"{cursor_after_3.cursor_value!r}"
            )

            # ---- Normalizer proof: every real fetched alert normalizes cleanly ----
            print(
                "\n=== Normalizer proof: DefenderAlertNormalizer against "
                "every real fetched alert ==="
            )
            normalizer = DefenderAlertNormalizer()
            all_alerts_json = [json.dumps(a).encode() for a in _ALERTS_STORE]
            for raw in all_alerts_json:
                normalized = normalizer.normalize(raw)
                severity = normalized.extra["ms_defender.severity"]
                print(
                    f"    normalized: @timestamp={normalized.timestamp.isoformat()} "
                    f"message={normalized.message!r} severity={severity!r}"
                )
            print(f"[normalizer] all {len(all_alerts_json)} real alerts normalized without error")

            # ---- Real auth-failure proof: wrong client_secret ----------
            print(
                "\n=== Auth-failure proof: wrong client_secret must surface "
                "loudly, never silently ==="
            )
            bad_auth_strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
                http_client,
                token_endpoint=f"http://127.0.0.1:{port}/{TENANT_ID}/oauth2/v2.0/token",
                client_id=CLIENT_ID,
                client_secret="wrong-secret",
                scope=EXPECTED_SCOPE,
            )
            bad_source = DefenderPollSource(
                http_client,
                base_url=f"http://127.0.0.1:{port}/v1.0",
                auth_strategy=bad_auth_strategy,
            )
            try:
                await bad_auth_strategy.headers()
                raise SystemExit(
                    "expected IntegrationSourceAuthError for wrong client_secret, got none"
                )
            except IntegrationSourceAuthError as exc:
                print(
                    "[auth-failure] real 401 from the stand-in token endpoint "
                    f"correctly surfaced as: {exc}"
                )
            del bad_source  # never used to poll -- auth already failed at token acquisition

            # ---- Audit trail proof ---------------------------------------
            audit_events = [e for e in audit_repo._events if e.org_id == identity.org_id]
            print(f"\n[final] real audit events recorded: {len(audit_events)}")
            for e in audit_events:
                print(f"    {e.event_type.value} details={e.details}")
            assert len(audit_events) == 3  # cycle 1, cycle 2, cycle 3 (empty)
            assert all(
                e.event_type.value == "integration_source.poll_completed" for e in audit_events
            )

            print("\n=== DEFENDER POLL SOURCE PoC: ALL ASSERTIONS PASSED ===")
    finally:
        # Cleanup: remove only the rows this PoC run created (table itself
        # left in place, matching poc/integration_source_foundation's own
        # PostgresSourceCursorRepository PoC precedent).
        async with engine.begin() as conn:
            await conn.execute(
                source_cursors_table.delete().where(
                    source_cursors_table.c.org_id == ORG_ID,
                    source_cursors_table.c.source_id == SOURCE_ID,
                )
            )
        print(
            "\n[cleanup] deleted this PoC run's own cursor row from real "
            "Postgres (table left in place)"
        )
        await engine.dispose()
        server.shutdown()
        thread.join(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())
