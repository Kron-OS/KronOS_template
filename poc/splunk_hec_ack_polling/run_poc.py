#!/usr/bin/env python3
"""L2 PoC: Splunk HEC indexer-acknowledgement (ackId) polling
(gap audit docs/GAP_AUDIT_2026-08.md P1-3, Milestone V, item V6).

Drives the real, unmodified production classes with ``enable_indexer_ack=True``:
    SplunkHecSink (src/adapter/integration_sink/splunk_hec_sink.py)
    SplunkDetectionMapper (src/application/splunk_detection_mapper.py)
    StaticTokenAuthenticator(scheme="Splunk") (sink_authenticator.py, R1)
    DetectionSinkPushService (src/application/detection_sink_push.py, R1)
    Detection (src/domain/detection.py)
    PostgresAuditLogRepository / AuditLogService (real chain-of-custody audit trail)

against a REAL, genuine ``splunk/splunk:9.3.3`` container
(``kronos-poc-splunk-hec-ack``) with a REAL HEC token that has
``useACK=1`` enabled via a real REST call against the container's own
management API (port 8089) -- see README.md for exactly how that token
was created and why no ``SPLUNK_HEC_*`` env var can do this (confirmed by
fetching ``splunk-ansible``'s own current ``getHEC()`` source this pass).

This is a REAL, timing-dependent proof, not a mocked/assumed one: Scenario
1 captures the real ``ackId`` this exact container returns, polls the real
``/services/collector/ack`` endpoint, and the real observed sequence is
FALSE (not yet indexed) followed by TRUE (indexed) some real, non-zero
number of seconds later -- both values and the real elapsed time between
them are printed from the actual run, not asserted from memory.

Requires:
  - docker-postgres-1 (16) already running (docker/docker-compose.dev.yml)
    for the DetectionSinkPushService audit-trail scenario.
  - A real ``kronos-poc-splunk-hec-ack`` container (splunk/splunk:9.3.3)
    already up and healthy, with a real ack-enabled HEC token already
    created (see README.md for the exact commands) -- this script does
    NOT create/tear down that container itself (same idiom as
    poc/integration_sink_splunk_hec/run_poc.py). If unreachable, this
    entire PoC is skipped loudly rather than silently passed.

Run: ~/venv/bin/python3 poc/splunk_hec_ack_polling/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.integration_sink.sink_authenticator import StaticTokenAuthenticator  # noqa: E402
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

# Real, genuine splunk/splunk:9.3.3 container (kronos-poc-splunk-hec-ack) --
# see README.md for the exact `docker run` + real REST-API token-creation
# commands used to get a real useACK=1 token on it.
REAL_SPLUNK_HEC_EVENT_URL = "http://127.0.0.1:18188/services/collector/event"
REAL_SPLUNK_MGMT_URL = "https://127.0.0.1:18189"
REAL_ACK_TOKEN = (
    "1a2b3c4d-5e6f-7890-abcd-ef1234567890"  # nosec B105 -- local PoC-only container token
)
REAL_SPLUNK_ADMIN_PASSWORD = "KronosPoc-2026!"  # nosec B105 -- local PoC-only container password

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" -- {detail}" if detail else ""))


def make_tenant() -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias=f"v6ackpoc{uuid.uuid4().hex[:8]}",
        user_id=uuid.uuid4(),
        username="v6-ackpoc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def make_detection(tenant: TenantContext, finding_suffix: str) -> Detection:
    case_id = uuid.uuid4()
    return Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=case_id,
        finding_id=f"poc-v6-ack-finding-{finding_suffix}-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-v6ackpoc-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{case_id}-202608",
        rule_matches=(DetectionRuleMatch(rule_id="r1", rule_name="ACK Poll Test", tags=("test",)),),
        matched_document_ids=("doc-a",),
        finding_timestamp=datetime.now(UTC),
        risk_score=42.0,
    )


async def _real_splunk_reachable() -> bool:
    try:
        async with httpx.AsyncClient(
            timeout=3.0, verify=False
        ) as client:  # noqa: S501 -- local PoC-only self-signed cert
            resp = await client.get(f"{REAL_SPLUNK_MGMT_URL}/services/server/info")
            return resp.status_code in (200, 401)
    except httpx.HTTPError:
        return False


async def main() -> None:
    if not await _real_splunk_reachable():
        log(
            "WARNING: kronos-poc-splunk-hec-ack not reachable at "
            f"{REAL_SPLUNK_MGMT_URL} -- ENTIRE PoC SKIPPED, not silently passed. "
            "See README.md for the docker run + token-creation commands to start it."
        )
        check("PoC skipped -- real Splunk container unreachable", False)
        sys.exit(1)

    setup_engine = create_async_engine(POSTGRES_DSN)
    await PostgresAuditLogRepository.create_tables(setup_engine)
    audit_repo = PostgresAuditLogRepository(setup_engine)
    audit_log = AuditLogService(audit_repo)

    tenant = make_tenant()
    log(f"=== real tenant org_id={tenant.org_id} org_alias={tenant.org_alias} ===")

    mapper = SplunkDetectionMapper(
        source="kronos:detection_sink", sourcetype="kronos:v6ackpoc", index="main"
    )

    # =========================================================================
    # Scenario 1: real push with enable_indexer_ack=True -> real ackId ->
    # real synchronous poll -> real observed FALSE then TRUE, real timing.
    # =========================================================================
    print("\n=== Scenario 1: real push_events() with enable_indexer_ack=True (default timeout) ===")
    ack_sink = SplunkHecSink(
        REAL_SPLUNK_HEC_EVENT_URL,
        StaticTokenAuthenticator(REAL_ACK_TOKEN, scheme="Splunk"),
        enable_indexer_ack=True,
        ack_poll_timeout=30.0,
        ack_poll_interval=1.0,
    )
    detection1 = make_detection(tenant, "sync-confirm")
    event1 = mapper.map(detection1)
    ack1 = await ack_sink.push_events([event1])
    check(
        "real push with indexer ack enabled returns ACKNOWLEDGED "
        "(real indexer confirmation observed within the real bounded poll)",
        ack1.status == SinkAckStatus.ACKNOWLEDGED,
        f"status={ack1.status} detail={ack1.detail}",
    )
    check("SinkAck.detail carries the real ack_id", isinstance(ack1.detail.get("ack_id"), int))
    check(
        "SinkAck.detail carries the real channel GUID used for this push",
        isinstance(ack1.detail.get("channel"), str) and len(ack1.detail["channel"]) == 36,
    )
    check(
        "SinkAck.detail honestly reports indexer_confirmed=True",
        ack1.detail.get("indexer_confirmed") is True,
    )
    check(
        "SinkAck.detail's real ack_poll_attempts is >= 2 "
        "(proves a real FALSE was observed before the real TRUE, not an instant match)",
        ack1.detail.get("ack_poll_attempts", 0) >= 2,
        f"ack_poll_attempts={ack1.detail.get('ack_poll_attempts')}",
    )
    check(
        "SinkAck.detail's real ack_poll_elapsed_seconds reflects real "
        "indexing latency (>= 1 real poll interval, not 0)",
        ack1.detail.get("ack_poll_elapsed_seconds", 0) >= 1.0,
        f"elapsed={ack1.detail.get('ack_poll_elapsed_seconds')}",
    )

    # =========================================================================
    # Scenario 2: real, independent check_ack_status() call for the SAME
    # ack_id -- real, documented "read-once" behavior: HEC already deleted
    # this ackId's status after Scenario 1 resolved it True, so a fresh
    # query for it now must observe False again (NOT a regression).
    # =========================================================================
    print("\n=== Scenario 2: real check_ack_status() re-query of an already-resolved ackId ===")
    already_resolved = await ack_sink.check_ack_status(
        ack1.detail["channel"], [ack1.detail["ack_id"]]
    )
    check(
        "real re-query of an already-True ackId returns False "
        "(HEC's own real documented one-shot-readable contract, not a bug)",
        already_resolved.get(ack1.detail["ack_id"]) is False,
        f"already_resolved={already_resolved}",
    )

    # =========================================================================
    # Scenario 3: real deliberate near-zero poll timeout -> real ACK_PENDING
    # (never fabricated ACKNOWLEDGED, never raised as an error).
    # =========================================================================
    print("\n=== Scenario 3: real near-zero timeout -> real ACK_PENDING (not an error) ===")
    pending_sink = SplunkHecSink(
        REAL_SPLUNK_HEC_EVENT_URL,
        StaticTokenAuthenticator(REAL_ACK_TOKEN, scheme="Splunk"),
        enable_indexer_ack=True,
        ack_poll_timeout=0.001,
        ack_poll_interval=1.0,
    )
    detection2 = make_detection(tenant, "timeout-pending")
    event2 = mapper.map(detection2)
    ack2 = await pending_sink.push_events([event2])
    check(
        "real push with a near-zero timeout returns ACK_PENDING, not "
        "ACKNOWLEDGED and not an exception",
        ack2.status == SinkAckStatus.ACK_PENDING,
        f"status={ack2.status} detail={ack2.detail}",
    )
    check(
        "ACK_PENDING SinkAck.detail honestly reports indexer_confirmed=False",
        ack2.detail.get("indexer_confirmed") is False,
    )
    check(
        "ACK_PENDING SinkAck.detail still carries the real ack_id/channel "
        "needed to resolve it later",
        isinstance(ack2.detail.get("ack_id"), int) and isinstance(ack2.detail.get("channel"), str),
    )

    # =========================================================================
    # Scenario 4: real "resolve later" proof -- the SEPARATE check_ack_status()
    # mechanism resolves Scenario 3's own real pending ack_id to True once
    # real indexing genuinely catches up, independent of push_events().
    # =========================================================================
    print("\n=== Scenario 4: real out-of-band check_ack_status() resolves the pending ack ===")
    await asyncio.sleep(2.0)  # real wait for real Splunk indexing to catch up
    resolved_later = await pending_sink.check_ack_status(
        ack2.detail["channel"], [ack2.detail["ack_id"]]
    )
    check(
        "real out-of-band poll (SEPARATE from push_events()) resolves the "
        "real pending ack_id to True once indexing genuinely finished",
        resolved_later.get(ack2.detail["ack_id"]) is True,
        f"resolved_later={resolved_later}",
    )

    # =========================================================================
    # Scenario 5: real negative case -- pushing WITHOUT enable_indexer_ack
    # against a token that itself requires a channel (useACK=1) -> real
    # documented 400/code=10 "Data channel is missing".
    # =========================================================================
    print("\n=== Scenario 5: real negative -- no channel header against a useACK=1 token ===")
    plain_sink = SplunkHecSink(
        REAL_SPLUNK_HEC_EVENT_URL, StaticTokenAuthenticator(REAL_ACK_TOKEN, scheme="Splunk")
    )
    try:
        await plain_sink.push_events([mapper.map(make_detection(tenant, "no-channel"))])
        check("push without a channel against a useACK=1 token raises", False)
    except IntegrationSinkError as exc:
        check(
            "real 400/code=10 'Data channel is missing' surfaced honestly, "
            "never silently accepted",
            exc.context.get("status_code") == 400 and exc.context.get("code") == 10,
            f"context={exc.context}",
        )

    # =========================================================================
    # Scenario 6: real negative case -- check_ack_status() against an
    # invalid/unknown channel -> real documented 400/code=11 "Invalid data
    # channel".
    # =========================================================================
    print("\n=== Scenario 6: real negative -- check_ack_status() with an invalid channel ===")
    try:
        await ack_sink.check_ack_status("not-a-real-channel-guid", [0])
        check("check_ack_status with an invalid channel raises", False)
    except IntegrationSinkError as exc:
        check(
            "real 400/code=11 'Invalid data channel' surfaced honestly",
            exc.context.get("status_code") == 400 and exc.context.get("code") == 11,
            f"context={exc.context}",
        )

    # =========================================================================
    # Scenario 7: DetectionSinkPushService full orchestration with indexer
    # ack enabled -- real audit trail still records the honest ack_status
    # (ACKNOWLEDGED, confirmed by real indexer polling), independently
    # re-verified from a fresh Postgres connection.
    # =========================================================================
    print("\n=== Scenario 7: DetectionSinkPushService orchestration with indexer ack enabled ===")
    orch_sink = SplunkHecSink(
        REAL_SPLUNK_HEC_EVENT_URL,
        StaticTokenAuthenticator(REAL_ACK_TOKEN, scheme="Splunk"),
        enable_indexer_ack=True,
        ack_poll_timeout=30.0,
        ack_poll_interval=1.0,
    )
    push_service = DetectionSinkPushService(orch_sink, mapper, audit_log)
    orch_detection = make_detection(tenant, "orchestrated")
    result = await push_service.push([orch_detection], tenant)
    check("real orchestrated push reports detection_count == 1", result.detection_count == 1)
    check(
        "real orchestrated push result.all_acknowledged is True "
        "(indexer genuinely confirmed within the bounded poll)",
        result.all_acknowledged,
        f"acks={[a.status for a in result.acks]}",
    )

    print("--- independent fresh-connection audit re-verification ---")
    fresh_engine = create_async_engine(POSTGRES_DSN)
    fresh_audit_repo = PostgresAuditLogRepository(fresh_engine)
    fresh_audit_log = AuditLogService(fresh_audit_repo)
    events_read = [e async for e in fresh_audit_repo.stream_by_org(tenant.org_id)]
    executed_rows = [e for e in events_read if e.event_type == AuditEventType.SINK_PUSH_EXECUTED]
    check(
        "fresh read: real SINK_PUSH_EXECUTED row's own ack_status is "
        "honestly 'acknowledged' (indexer-confirmed, not just accepted)",
        any(e.details.get("ack_status") == SinkAckStatus.ACKNOWLEDGED.value for e in executed_rows),
        f"executed_rows_ack_status={[e.details.get('ack_status') for e in executed_rows]}",
    )
    intact, detail = await fresh_audit_log.verify_chain(tenant.org_id)
    check(f"fresh read: real audit hash chain intact end-to-end (detail={detail})", intact)
    await fresh_engine.dispose()

    await setup_engine.dispose()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against a REAL splunk/splunk:9.3.3 container with a real useACK=1 HEC token "
        f"(kronos-poc-splunk-hec-ack) and the real, live dev-stack Postgres 16 (Scenario 7)."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
