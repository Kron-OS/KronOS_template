"""PoC (a): real PUSH webhook round trip through the actual KronOS route.

Starts a REAL uvicorn server (127.0.0.1, ephemeral port) hosting the real
FastAPI app (``src.external.fastapi_app.create_app``) with the real
``/api/integrations/push/generic-webhook`` route wired to the real
``GenericWebhookPushSource`` + ``IntegrationSourceIngestService`` +
``StaticApiKeyInboundAuthenticator`` + ``AuditLogService``. Only the
bottom-most storage doubles are swapped for in-memory ones (stream
transport, dedup, audit repository) -- exactly the same "real orchestration
logic, in-memory storage doubles" bar ``poc/detection_ticket_integration/``
and ``poc/collector_ingest_mtls/`` already established as a legitimate
PoC-tier verification (a real TCP socket, real HTTP bytes, real status
codes -- never mocked at the transport or route level).

A real ``httpx.AsyncClient`` then makes REAL HTTP POST requests over a REAL
TCP socket to this server -- not ASGITransport in-process dispatch, not
TestClient.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path

import httpx
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.integration_source_ingest import IntegrationSourceIngestService  # noqa: E402
from src.adapter.queue.event_dedup import InMemoryEventDedupChecker  # noqa: E402
from src.adapter.queue.stream_ingest import InMemoryStreamIngestAdapter  # noqa: E402
from src.adapter.repository.source_cursor import InMemorySourceCursorRepository  # noqa: E402
from src.external.dependencies import (  # noqa: E402
    get_audit_log_service,
    get_inbound_source_authenticator,
    get_integration_source_ingest_service,
    get_integration_source_registry,
)
from src.external.fastapi_app import create_app  # noqa: E402
from src.external.middleware.integration_source_auth import (  # noqa: E402
    StaticApiKeyInboundAuthenticator,
    StaticApiKeyProvisioning,
)
from tests.conftest import InMemoryAuditLogRepository  # noqa: E402 -- real, non-mocked test double

ORG_ID = uuid.uuid4()
SOURCE_ID = "generic-webhook-instance-1"
API_KEY = "poc-real-key-1234"
PORT = 18765


async def main() -> None:
    stream_adapter = InMemoryStreamIngestAdapter()
    dedup_checker = InMemoryEventDedupChecker()
    cursor_repository = InMemorySourceCursorRepository()
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)

    provisioning = {
        API_KEY: StaticApiKeyProvisioning(
            api_key=API_KEY, org_id=ORG_ID, source_id=SOURCE_ID, source_type="generic-webhook"
        )
    }
    authenticator = StaticApiKeyInboundAuthenticator(provisioning)

    app = create_app()
    ingest_service = IntegrationSourceIngestService(
        get_integration_source_registry(),  # real default registry, GenericWebhookPushSource pre-registered
        stream_adapter,
        dedup_checker,
        cursor_repository,
        audit_log,
        max_stream_length=1_000_000,
        dedup_ttl_seconds=3600,
    )
    app.dependency_overrides[get_inbound_source_authenticator] = lambda: authenticator
    app.dependency_overrides[get_audit_log_service] = lambda: audit_log
    app.dependency_overrides[get_integration_source_ingest_service] = lambda: ingest_service

    config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            await asyncio.sleep(0.05)

        print(f"=== Real uvicorn server listening on 127.0.0.1:{PORT} ===")

        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{PORT}") as client:
            # 1. Real POST, single bare-JSON event, real API key header.
            body1 = {"alert_id": "a-1", "severity": "high", "message": "suspicious process"}
            resp1 = await client.post(
                "/api/integrations/push/generic-webhook",
                content=json.dumps(body1),
                headers={"X-KronOS-Source-Key": API_KEY, "Content-Type": "application/json"},
            )
            print(f"\n[1] Single-event POST -> status={resp1.status_code}")
            print(f"    body: {resp1.json()}")
            assert resp1.status_code == 202
            assert resp1.json()["results"][0]["accepted"] is True

            # 2. Real POST, exact same body again -> must be deduped, not re-produced.
            resp2 = await client.post(
                "/api/integrations/push/generic-webhook",
                content=json.dumps(body1),
                headers={"X-KronOS-Source-Key": API_KEY, "Content-Type": "application/json"},
            )
            print(f"\n[2] Duplicate POST (identical body) -> status={resp2.status_code}")
            print(f"    body: {resp2.json()}")
            assert resp2.json()["results"][0]["duplicate"] is True
            assert resp2.json()["results"][0]["accepted"] is False

            # 3. Real POST, batch envelope {"events": [...]} -> must split into 3.
            body3 = {"events": [{"id": 1}, {"id": 2}, {"id": 3}]}
            resp3 = await client.post(
                "/api/integrations/push/generic-webhook",
                content=json.dumps(body3),
                headers={"X-KronOS-Source-Key": API_KEY, "Content-Type": "application/json"},
            )
            print(f"\n[3] Batch-envelope POST (3 events) -> status={resp3.status_code}")
            print(f"    body: {resp3.json()}")
            assert len(resp3.json()["results"]) == 3
            assert all(r["accepted"] for r in resp3.json()["results"])

            # 4. Real POST with a WRONG API key -> must be rejected 401, never reach the service.
            resp4 = await client.post(
                "/api/integrations/push/generic-webhook",
                content=json.dumps(body1),
                headers={"X-KronOS-Source-Key": "totally-wrong-key", "Content-Type": "application/json"},
            )
            print(f"\n[4] Wrong API key POST -> status={resp4.status_code}")
            print(f"    body: {resp4.json()}")
            assert resp4.status_code == 401

            # 5. Real POST with correct key but WRONG source_type in the path -> 403.
            resp5 = await client.post(
                "/api/integrations/push/some-other-source",
                content=json.dumps(body1),
                headers={"X-KronOS-Source-Key": API_KEY, "Content-Type": "application/json"},
            )
            print(f"\n[5] Correct key, mismatched source_type in path -> status={resp5.status_code}")
            print(f"    body: {resp5.json()}")
            assert resp5.status_code == 403

        # Verify: real stream transport actually received the events.
        stream_length = await stream_adapter.approximate_length(ORG_ID, SOURCE_ID)
        print(f"\n[6] Real InMemoryStreamIngestAdapter stream length for (org, source) = {stream_length}")
        assert stream_length == 4  # 1 (from [1]) + 0 (dup) + 3 (from [3])

        # Verify: real audit trail has one event per real accepted call, tenant scoped correctly.
        audit_events = [e for e in audit_repo._events if e.org_id == ORG_ID]
        print(f"\n[7] Real audit events recorded for this org: {len(audit_events)}")
        for e in audit_events:
            print(f"    {e.event_type.value} details={e.details}")
        assert len(audit_events) == 3  # ingest_push audits once per HTTP call that reached the service (1, 2, 3)
        assert all(e.event_type.value == "integration_source.push_ingested" for e in audit_events)

        print("\n=== PUSH PoC: ALL ASSERTIONS PASSED ===")
    finally:
        server.should_exit = True
        await server_task


if __name__ == "__main__":
    asyncio.run(main())
