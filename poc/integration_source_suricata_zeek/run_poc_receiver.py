"""PoC (L2): real end-to-end fluent-bit -> KronOS push, receiver half
(roadmap Q3).

Structurally identical to ``poc/integration_source_wazuh/run_poc_receiver.py``
(same real-app / PoC-tier-in-memory-doubles bar), extended to two
provisioned (org, source) pairs -- ``suricata-eve`` and ``zeek-conn-log`` --
since this pass registers two real ``IntegrationSource``s
(``SuricataEvePushSource``, ``ZeekJsonPushSource``,
``src/external/integration_sources/suricata_zeek.py``) fed by two real
``tail``+`http` fluent-bit routes (see this directory's own
``fluent-bit.conf``).

Runs a real uvicorn server hosting the real KronOS FastAPI app with the
real ``POST /api/integrations/push/{suricata-eve,zeek-conn-log}`` routes
wired to the real push sources + ``StaticApiKeyInboundAuthenticator`` +
``IntegrationSourceIngestService`` + ``AuditLogService``. Only the
bottom-most storage doubles are in-memory (stream transport, dedup, audit
repository) -- unchanged from Q1/Q2's own established PoC-tier bar.
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
    """In-memory audit repository -- inlined verbatim from
    ``poc/integration_source_wazuh/run_poc_receiver.py``'s own real,
    non-mocked test double (not reimplemented), for the same reason: this
    PoC runs inside a container whose venv has only production deps
    installed (no ``pytest``, which ``tests/conftest.py`` imports at
    module level)."""

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


# Fixed, reproducible tenant identity for this PoC run -- matches the two
# `X-KronOS-Source-Key` headers configured in this dir's real fluent-bit.conf.
ORG_ID = uuid.UUID("6c1c6b7e-0a5f-4b7c-9c1a-000000000043")
SURICATA_SOURCE_ID = "suricata-eve"
SURICATA_API_KEY = "kronos-poc-suricata-demo-key"
ZEEK_SOURCE_ID = "zeek-conn-log"
ZEEK_API_KEY = "kronos-poc-zeek-demo-key"
PORT = 8000
LISTEN_SECONDS = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0


class _LoggingIngestService:
    """Thin wrapper around the real IntegrationSourceIngestService that
    prints every real inbound call as it happens, so a real fluent-bit push
    landing asynchronously (on its own tail/flush schedule, not this
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
        SURICATA_API_KEY: StaticApiKeyProvisioning(
            api_key=SURICATA_API_KEY,
            org_id=ORG_ID,
            source_id=SURICATA_SOURCE_ID,
            source_type="suricata-eve",
        ),
        ZEEK_API_KEY: StaticApiKeyProvisioning(
            api_key=ZEEK_API_KEY,
            org_id=ORG_ID,
            source_id=ZEEK_SOURCE_ID,
            source_type="zeek-conn-log",
        ),
    }
    authenticator = StaticApiKeyInboundAuthenticator(provisioning)

    app = create_app()
    real_ingest_service = IntegrationSourceIngestService(
        get_integration_source_registry(),  # real default registry, both Q3 sources pre-registered
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
            "(container: kronos-poc-suricatazeek-receiver) ==="
        )
        print(
            f"=== Waiting up to {LISTEN_SECONDS}s for real pushes from "
            "kronos-poc-suricatazeek-fluentbit ==="
        )
        await asyncio.sleep(LISTEN_SECONDS)

        print(f"\n[SUMMARY] Real inbound HTTP calls received: {logging_ingest_service.call_count}")

        for label, source_id in (
            ("suricata-eve", SURICATA_SOURCE_ID),
            ("zeek-conn-log", ZEEK_SOURCE_ID),
        ):
            stream_length = await stream_adapter.approximate_length(ORG_ID, source_id)
            print(
                f"[SUMMARY] Real stream length for (org={ORG_ID}, source={source_id} "
                f"[{label}]): {stream_length}"
            )
            if stream_length > 0:
                # InMemoryStreamIngestAdapter has no public "read everything
                # back" method -- real Redis Streams consumption is via
                # consumer groups, exercised for real elsewhere
                # (poc/stream_ingest_redis/) -- reading its own internal list
                # directly here is a PoC-tier inspection only.
                key = stream_adapter._key(ORG_ID, source_id)
                entries = stream_adapter._streams.get(key, [])
                print(f"    Real stream entries ({len(entries)}):")
                for msg in entries:
                    print(
                        f"      message_id={msg.message_id} "
                        f"raw={msg.payload.decode('utf-8', errors='replace')[:1500]}"
                    )

        audit_events = [e for e in audit_repo._events if e.org_id == ORG_ID]
        print(f"\n[SUMMARY] Real audit events recorded for org={ORG_ID}: {len(audit_events)}")
        for e in audit_events:
            print(f"    {e.event_type.value} details={e.details}")

        suricata_len = await stream_adapter.approximate_length(ORG_ID, SURICATA_SOURCE_ID)
        zeek_len = await stream_adapter.approximate_length(ORG_ID, ZEEK_SOURCE_ID)
        if logging_ingest_service.call_count > 0 and suricata_len > 0 and zeek_len > 0:
            print(
                "\n=== SURICATA + ZEEK -> KRONOS PUSH PoC: REAL END-TO-END FLOW "
                "CONFIRMED FOR BOTH SOURCES ==="
            )
        else:
            print(
                "\n=== SURICATA + ZEEK -> KRONOS PUSH PoC: NOT BOTH SOURCES CONFIRMED "
                f"WITHIN WINDOW (suricata_len={suricata_len}, zeek_len={zeek_len}) ==="
            )
    finally:
        server.should_exit = True
        await server_task


if __name__ == "__main__":
    asyncio.run(main())
