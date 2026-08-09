"""PoC (L2): real end-to-end Wazuh -> KronOS push, receiver half.

Starts a REAL uvicorn server hosting the real KronOS FastAPI app
(``src.external.fastapi_app.create_app``) with the real
``POST /api/integrations/push/wazuh`` route wired to the real
``WazuhPushSource`` + ``StaticApiKeyInboundAuthenticator`` +
``IntegrationSourceIngestService`` + ``AuditLogService``. Only the
bottom-most storage doubles are in-memory (stream transport, dedup, audit
repository) -- the exact same PoC-tier bar
``poc/integration_source_foundation/run_poc_push.py`` already established
as legitimate (those real backends are independently verified elsewhere;
this PoC's own new surface is the real Wazuh wire format + WazuhPushSource,
not Redis/Postgres).

Unlike that PoC, the real caller here is not a same-process httpx client --
it is a REAL, separately running ``wazuh/wazuh-manager:4.14.7`` container
(``kronos-poc-wazuh-manager``, same ``kronos-poc-wazuh-net`` docker
network) whose real ``wazuh-integratord`` daemon execs a real
``custom-kronos`` integration script per real fired alert (see this
directory's own ``custom-kronos``/``custom-kronos.py`` and README.md for
the full trail). This process listens on 0.0.0.0:8000 under the container
name ``kronos-poc-wazuh-receiver`` -- exactly the hostname configured in
the manager's own ``<hook_url>``.

Runs for a bounded window, printing every real inbound push as it arrives,
then prints a final summary (stream contents, audit trail) and exits.
"""

from __future__ import annotations

import asyncio
import sys
import uuid

import uvicorn

sys.path.insert(0, "/app")

from collections.abc import AsyncIterator  # noqa: E402

from src.adapter.queue.event_dedup import InMemoryEventDedupChecker  # noqa: E402
from src.adapter.queue.stream_ingest import InMemoryStreamIngestAdapter  # noqa: E402
from src.adapter.repository.audit_log import AuditLogRepository, EventBuilder  # noqa: E402
from src.adapter.repository.source_cursor import InMemorySourceCursorRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.integration_source import IntegrationSourceError  # noqa: E402
from src.application.integration_source_ingest import (  # noqa: E402
    EventOutcome,
    IntegrationSourceBackpressureError,
    IntegrationSourceIngestService,
)
from src.domain.audit import AuditEvent  # noqa: E402
from src.domain.integration_source import IntegrationSourceIdentity  # noqa: E402
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


class InMemoryAuditLogRepository(AuditLogRepository):
    """In-memory audit repository -- the append/hash-chain half inlined
    verbatim from ``tests/conftest.py``'s own real, non-mocked test double
    (not reimplemented from scratch) since this PoC runs inside a container
    whose venv has only production deps installed (no ``pytest``, which
    ``tests/conftest.py`` imports at module level for its fixtures).
    ``stream_by_*`` are real, just unused by this PoC (no route here reads
    the audit trail back through those methods -- the summary below reads
    ``self._events`` directly, same as the real test double does in its own
    assertions)."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._org_locks: dict[uuid.UUID, asyncio.Lock] = {}

    async def append(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    async def get_latest_hash(self, org_id: uuid.UUID) -> str | None:
        for event in reversed(self._events):
            if event.org_id == org_id:
                return event.row_hash
        return None

    async def get_latest_sequence(self, org_id: uuid.UUID) -> int:
        for event in reversed(self._events):
            if event.org_id == org_id:
                return event.sequence_number
        return 0

    async def append_atomic(self, org_id: uuid.UUID, build_event: EventBuilder) -> AuditEvent:
        lock = self._org_locks.setdefault(org_id, asyncio.Lock())
        async with lock:
            prev_hash = await self.get_latest_hash(org_id)
            latest_seq = await self.get_latest_sequence(org_id)
            event = build_event(prev_hash, latest_seq)
            self._events.append(event)
            return event

    async def stream_by_evidence(self, evidence_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        for event in self._events:
            if event.evidence_id == evidence_id:
                yield event

    async def stream_by_case(self, case_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        for event in self._events:
            if event.case_id == case_id:
                yield event

    async def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        for event in self._events:
            if event.org_id == org_id:
                yield event


# Fixed, reproducible tenant identity for this PoC run -- matches the
# `custom-kronos` <api_key> configured in kronos-poc-wazuh-manager's
# real ossec.conf (see this dir's README.md).
ORG_ID = uuid.UUID("6c1c6b7e-0a5f-4b7c-9c1a-000000000042")
SOURCE_ID = "wazuh-poc-manager-1"
API_KEY = "kronos-poc-wazuh-demo-key"
PORT = 8000
LISTEN_SECONDS = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0


class _LoggingIngestService:
    """Thin wrapper around the real IntegrationSourceIngestService that
    prints every real inbound call as it happens, so a real Wazuh push
    landing asynchronously (on the manager's own schedule, not this
    script's) is visible in the captured stdout the moment it occurs."""

    def __init__(self, inner: IntegrationSourceIngestService) -> None:
        self._inner = inner
        self.call_count = 0

    async def ingest_push(
        self, identity: IntegrationSourceIdentity, raw_body: bytes
    ) -> list[EventOutcome]:
        self.call_count += 1
        print(
            f"\n[REAL PUSH #{self.call_count}] from org={identity.org_id} "
            f"source={identity.source_id} source_type={identity.source_type} "
            f"auth_method={identity.auth_method}"
        )
        body_preview = raw_body.decode("utf-8", errors="replace")[:2000]
        print(f"    raw_body ({len(raw_body)} bytes): {body_preview}")
        try:
            outcomes = await self._inner.ingest_push(identity, raw_body)
        except (IntegrationSourceError, IntegrationSourceBackpressureError) as exc:
            print(f"    -> REJECTED: {type(exc).__name__}: {exc}")
            raise
        for o in outcomes:
            print(f"    -> accepted={o.accepted} duplicate={o.duplicate} message_id={o.message_id}")
        return outcomes


async def main() -> None:
    stream_adapter = InMemoryStreamIngestAdapter()
    dedup_checker = InMemoryEventDedupChecker()
    cursor_repository = InMemorySourceCursorRepository()
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)

    provisioning = {
        API_KEY: StaticApiKeyProvisioning(
            api_key=API_KEY, org_id=ORG_ID, source_id=SOURCE_ID, source_type="wazuh"
        )
    }
    authenticator = StaticApiKeyInboundAuthenticator(provisioning)

    app = create_app()
    real_ingest_service = IntegrationSourceIngestService(
        get_integration_source_registry(),  # real default registry, WazuhPushSource pre-registered
        stream_adapter,
        dedup_checker,
        cursor_repository,
        audit_log,
        max_stream_length=1_000_000,
        dedup_ttl_seconds=3600,
    )
    logging_ingest_service = _LoggingIngestService(real_ingest_service)

    app.dependency_overrides[get_inbound_source_authenticator] = lambda: authenticator
    app.dependency_overrides[get_audit_log_service] = lambda: audit_log
    app.dependency_overrides[get_integration_source_ingest_service] = lambda: logging_ingest_service

    config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="info")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            await asyncio.sleep(0.05)

        print(
            f"=== Real uvicorn server listening on 0.0.0.0:{PORT} "
            "(container: kronos-poc-wazuh-receiver) ==="
        )
        print(
            f"=== Waiting up to {LISTEN_SECONDS}s for a REAL push "
            "from kronos-poc-wazuh-manager ==="
        )
        await asyncio.sleep(LISTEN_SECONDS)

        stream_length = await stream_adapter.approximate_length(ORG_ID, SOURCE_ID)
        print(f"\n[SUMMARY] Real inbound HTTP calls received: {logging_ingest_service.call_count}")
        print(
            f"[SUMMARY] Real InMemoryStreamIngestAdapter stream length for "
            f"(org={ORG_ID}, source={SOURCE_ID}): {stream_length}"
        )

        if stream_length > 0:
            # InMemoryStreamIngestAdapter has no public "read everything back"
            # method (real Redis Streams consumption is via consumer groups,
            # exercised for real elsewhere in poc/stream_ingest_redis/) --
            # reading its own internal list directly here is a PoC-tier
            # inspection, not something src/ code would do.
            key = stream_adapter._key(ORG_ID, SOURCE_ID)
            entries = stream_adapter._streams.get(key, [])
            print(f"[SUMMARY] Real stream entries ({len(entries)}):")
            for msg in entries:
                print(
                    f"    message_id={msg.message_id} "
                    f"raw={msg.payload.decode('utf-8', errors='replace')[:1500]}"
                )

        audit_events = [e for e in audit_repo._events if e.org_id == ORG_ID]
        print(f"\n[SUMMARY] Real audit events recorded for org={ORG_ID}: {len(audit_events)}")
        for e in audit_events:
            print(f"    {e.event_type.value} details={e.details}")

        if logging_ingest_service.call_count > 0 and stream_length > 0:
            print("\n=== WAZUH -> KRONOS PUSH PoC: REAL END-TO-END FLOW CONFIRMED ===")
        else:
            print("\n=== WAZUH -> KRONOS PUSH PoC: NO REAL PUSH RECEIVED WITHIN WINDOW ===")
    finally:
        server.should_exit = True
        await server_task


if __name__ == "__main__":
    asyncio.run(main())
