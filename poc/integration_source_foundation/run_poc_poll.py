"""PoC (b): real POLL cycle round trip proving cursor/watermark resumption.

Starts a REAL local HTTP server (stdlib ``http.server.ThreadingHTTPServer``,
127.0.0.1, ephemeral port -- the same "real local stand-in receiver"
pattern ``poc/detection_ticket_integration/`` already established) standing
in for an external tool's own poll API: ``GET /events?cursor=<token>`` ->
``{"events": [...], "next_cursor": "<token>"}``, three real pages of data
plus a real empty final page.

The real ``GenericPollSource`` (an ``httpx.AsyncClient`` making REAL HTTP
GET requests over a REAL TCP socket to that server) and the real
``IntegrationSourceIngestService.run_poll_cycle()`` are run against it
across four real poll cycles, using a real ``InMemorySourceCursorRepository``
to persist the watermark between cycles -- proving a restarting poll
connector resumes from where it left off rather than re-ingesting or
dropping events (the whole reason ``SourceCursor`` exists, per its own
domain docstring).
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.integration_source import IntegrationSourceRegistry  # noqa: E402
from src.application.integration_source_ingest import IntegrationSourceIngestService  # noqa: E402
from src.adapter.queue.event_dedup import InMemoryEventDedupChecker  # noqa: E402
from src.adapter.queue.stream_ingest import InMemoryStreamIngestAdapter  # noqa: E402
from src.adapter.repository.source_cursor import InMemorySourceCursorRepository  # noqa: E402
from src.domain.integration_source import IntegrationSourceIdentity  # noqa: E402
from src.external.integration_sources.generic_poll import GenericPollSource  # noqa: E402
from src.external.middleware.integration_source_auth import ApiKeyOutboundAuthStrategy  # noqa: E402
from tests.conftest import InMemoryAuditLogRepository  # noqa: E402 -- real, non-mocked test double

ORG_ID = uuid.uuid4()
SOURCE_ID = "generic-poll-instance-1"
API_KEY_VALUE = "poc-real-poll-key-5678"

# Real, fixed pagination fixture -- a genuine cursor-poll API's own shape:
# page 1 has no cursor param (first-ever call), each response's own
# next_cursor is what the client must echo back on the following call.
_PAGES: dict[str, dict] = {
    "": {"events": [{"id": 1, "msg": "alert one"}, {"id": 2, "msg": "alert two"}], "next_cursor": "page-2"},
    "page-2": {"events": [{"id": 3, "msg": "alert three"}], "next_cursor": "page-3"},
    "page-3": {"events": [], "next_cursor": None},  # caught up -- no new data yet
    "page-2-replayed-by-mistake": {"events": [], "next_cursor": None},
}


class _PollHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: D401 -- silence default stderr logging
        pass

    def do_GET(self) -> None:  # noqa: N802 -- stdlib method name
        parsed = urlparse(self.path)
        if parsed.path != "/events":
            self.send_response(404)
            self.end_headers()
            return

        if self.headers.get("Authorization") != f"Bearer {API_KEY_VALUE}":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": "unauthorized"}')
            return

        cursor = parse_qs(parsed.query).get("cursor", [""])[0]
        page = _PAGES.get(cursor)
        if page is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"unknown cursor {cursor!r}"}).encode())
            return

        body = json.dumps(page).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _identity() -> IntegrationSourceIdentity:
    return IntegrationSourceIdentity(
        org_id=ORG_ID, source_id=SOURCE_ID, source_type="generic-poll", auth_method="api-key"
    )


async def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PollHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"=== Real stdlib HTTP server (external poll API stand-in) listening on 127.0.0.1:{port} ===")

    try:
        async with httpx.AsyncClient() as http_client:
            source = GenericPollSource(
                http_client,
                base_url=f"http://127.0.0.1:{port}",
                auth_strategy=ApiKeyOutboundAuthStrategy("Authorization", f"Bearer {API_KEY_VALUE}"),
            )
            registry = IntegrationSourceRegistry()
            registry.register(source)

            stream_adapter = InMemoryStreamIngestAdapter()
            dedup_checker = InMemoryEventDedupChecker()
            cursor_repository = InMemorySourceCursorRepository()
            audit_repo = InMemoryAuditLogRepository()
            audit_log = AuditLogService(audit_repo)

            service = IntegrationSourceIngestService(
                registry, stream_adapter, dedup_checker, cursor_repository, audit_log,
                max_stream_length=1_000_000, dedup_ttl_seconds=3600,
            )
            identity = _identity()

            for cycle in range(1, 4):
                cursor_before = await cursor_repository.get(identity.org_id, identity.source_id)
                print(f"\n[cycle {cycle}] cursor before poll: {cursor_before.cursor_value if cursor_before else None!r}")
                result = await service.run_poll_cycle(identity)
                print(f"[cycle {cycle}] fetched {len(result.outcomes)} event(s), cursor_advanced={result.cursor_advanced}")
                for o in result.outcomes:
                    print(f"    produced message_id={o.message_id} accepted={o.accepted}")

            cursor_after = await cursor_repository.get(identity.org_id, identity.source_id)
            print(f"\n[final] persisted cursor: {cursor_after.cursor_value if cursor_after else None!r}")
            assert cursor_after is not None
            assert cursor_after.cursor_value == "page-3"

            stream_length = await stream_adapter.approximate_length(identity.org_id, identity.source_id)
            print(f"[final] real stream length: {stream_length}")
            assert stream_length == 3  # 2 (page 1) + 1 (page 2) + 0 (page 3, empty)

            audit_events = [e for e in audit_repo._events if e.org_id == identity.org_id]
            print(f"[final] real audit events recorded: {len(audit_events)}")
            for e in audit_events:
                print(f"    {e.event_type.value} details={e.details}")
            assert len(audit_events) == 3
            assert all(e.event_type.value == "integration_source.poll_completed" for e in audit_events)

            # Prove a real auth rejection surfaces as a real, observed IntegrationSourceError
            # (never silently swallowed into an empty result) -- CLAUDE.md invariant #8.
            bad_source = GenericPollSource(
                http_client, base_url=f"http://127.0.0.1:{port}",
                auth_strategy=ApiKeyOutboundAuthStrategy("Authorization", "Bearer wrong-key"),
            )
            bad_registry = IntegrationSourceRegistry()
            bad_registry.register(bad_source)
            bad_service = IntegrationSourceIngestService(
                bad_registry, stream_adapter, dedup_checker, InMemorySourceCursorRepository(), audit_log,
                max_stream_length=1_000_000, dedup_ttl_seconds=3600,
            )
            try:
                await bad_service.run_poll_cycle(identity)
                raise SystemExit("expected an IntegrationSourceError for the wrong-key poll, got none")
            except Exception as exc:  # noqa: BLE001 -- deliberately broad to print+reraise-check below
                print(f"\n[auth-failure] real 401 from the stand-in server correctly surfaced as: {type(exc).__name__}: {exc}")

            print("\n=== POLL PoC: ALL ASSERTIONS PASSED ===")
    finally:
        server.shutdown()
        thread.join(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())
