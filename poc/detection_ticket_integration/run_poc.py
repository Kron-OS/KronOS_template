#!/usr/bin/env python3
"""L2/L3 PoC: Case / ticket integration (roadmap M7/H4 -- closes Milestone M7).

Drives the real, unmodified production classes:
    Detection (src/domain/detection.py)
    SyncDetectionTicketAction (src/application/ticket_sync_action.py)
    WebhookTicketingSystem / TicketingSystem (src/adapter/ticketing/ticketing_system.py)
    PlaybookActionRegistry / PlaybookExecutionService (src/application/playbook*.py)
    PostgresDetectionRepository / PostgresAuditLogRepository / AuditLogService

against the REAL, live dev-stack Postgres 16 (docker-postgres-1,
localhost:5432 -- never InMemory* doubles) for Detection/audit persistence,
and against a REAL local HTTP receiver this script itself stands up on
127.0.0.1 (an ephemeral port, stdlib http.server -- not mocked, not
respx/httpretty) standing in for an external ITSM/ticketing system.

**Honesty note (read before trusting the PASSED summary) -- mirrors H2/H3's
own precedent exactly.** No real external ITSM product (Jira, ServiceNow,
PagerDuty, ...) is deployed anywhere in this dev stack:

    $ grep -rniE "jira|servicenow|pagerduty|zendesk" src/ docker/
    (no output -- confirmed, see README.md's own captured grep)

and reaching a live third-party SaaS ticketing API is explicitly out of
scope for this unattended pass (roadmap H4's own scope note). This PoC
therefore verifies WebhookTicketingSystem against a REAL local receiver --
real bytes over a real TCP socket, real JSON parsed, real HTTP status
codes returned and inspected on both sides -- never a live vendor account.
See README.md for the full reasoning.

Scenarios:
  (1) CREATE -- a real Detection is synced for the first time: a real HTTP
      POST reaches the real local receiver, a real ticket_id comes back,
      and Detection.external_ticket_id is persisted in real Postgres.
      Independently re-read from a FRESH Postgres connection.
  (2) UPDATE -- the SAME Detection is synced again: the real receiver gets
      an update-shaped POST referencing the SAME ticket_id (never a second,
      duplicate ticket), decided purely from external_ticket_id already
      being set -- never from a caller-supplied flag.
  (3) Invariant #3 (computed, never supplied) -- the playbook step's own
      params smuggle a different org_id/case_id; the real request the
      receiver actually received carries the REAL tenant/Detection values,
      proving the smuggled ones were never used.
  (4) Invariant #5 (derived opinions never mutate primary evidence) -- the
      Detection's triage_state is confirmed UNCHANGED (still NEW) after
      both real ticket syncs.
  (5) Fail loudly (invariant #8) -- a THIRD real Detection is synced
      against a deliberately unreachable webhook URL; the real call fails,
      a real TICKET_SYNC_FAILED audit row is written, and the Detection's
      external_ticket_id is confirmed to remain None -- never a fabricated
      ticket id.
  (6) Tenant isolation -- a second, unrelated tenant cannot sync a ticket
      for the first tenant's Detection id.
  (7) Real audit hash chain intact end-to-end after all of the above,
      independently re-verified via AuditLogService.verify_chain().

Run: ~/venv/bin/python3 poc/detection_ticket_integration/run_poc.py
Requires: docker-postgres-1 (16) already running (docker/docker-compose.dev.yml).
No other container is touched or required.
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

from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.adapter.ticketing.ticketing_system import WebhookTicketingSystem  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.playbook import PlaybookActionRegistry  # noqa: E402
from src.application.playbook_execution import PlaybookExecutionService  # noqa: E402
from src.application.ticket_sync_action import SyncDetectionTicketAction  # noqa: E402
from src.domain.audit import AuditEventType  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch  # noqa: E402
from src.domain.playbook import Playbook, PlaybookStep, PlaybookStepOutcome  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402

POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" -- {detail}" if detail else ""))


def make_tenant(org_alias_prefix: str = "h4poc") -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias=f"{org_alias_prefix}{uuid.uuid4().hex[:8]}",
        user_id=uuid.uuid4(),
        username="h4-poc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


# ---------------------------------------------------------------------------
# Real local HTTP receiver standing in for an external ITSM/ticketing
# system's inbound webhook endpoint -- real socket, real bytes, real JSON,
# real status codes. Deliberately generic-webhook-shaped (see
# src/adapter/ticketing/ticketing_system.py's own module docstring).
# ---------------------------------------------------------------------------


class TicketWebhookHandler(BaseHTTPRequestHandler):
    received: list[dict] = []
    tickets: dict[str, dict] = {}

    def do_POST(self) -> None:  # noqa: N802 -- stdlib API name
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        body = json.loads(raw)
        TicketWebhookHandler.received.append(body)
        event = body.get("event")
        port = self.server.server_address[1]

        if event == "kronos.ticket.create":
            ticket_id = f"ITSM-{uuid.uuid4().hex[:8]}"
            TicketWebhookHandler.tickets[ticket_id] = body
            self._send_json(
                201, {"ticket_id": ticket_id, "url": f"http://127.0.0.1:{port}/tickets/{ticket_id}"}
            )
        elif event == "kronos.ticket.update":
            ticket_id = body.get("ticket_id")
            if ticket_id not in TicketWebhookHandler.tickets:
                self._send_json(404, {"error": "unknown ticket_id"})
                return
            self._send_json(
                200, {"ticket_id": ticket_id, "url": f"http://127.0.0.1:{port}/tickets/{ticket_id}"}
            )
        else:
            self._send_json(400, {"error": "unrecognized event"})

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature
        pass  # silence default stderr access log; real requests are inspected via `received`


async def main() -> None:
    server = HTTPServer(("127.0.0.1", 0), TicketWebhookHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    webhook_url = f"http://127.0.0.1:{port}/webhook"
    log(f"=== real local HTTP receiver listening on {webhook_url} ===")

    setup_engine = create_async_engine(POSTGRES_DSN)
    await PostgresDetectionRepository.create_tables(setup_engine)
    await PostgresAuditLogRepository.create_tables(setup_engine)
    detection_repo = PostgresDetectionRepository(setup_engine)
    audit_repo = PostgresAuditLogRepository(setup_engine)
    audit_log = AuditLogService(audit_repo)

    ticketing = WebhookTicketingSystem(webhook_url)
    registry = PlaybookActionRegistry()
    registry.register(SyncDetectionTicketAction(detection_repo, ticketing, audit_log))
    execution_service = PlaybookExecutionService(registry, audit_log)

    tenant = make_tenant()
    log(f"=== real tenant org_id={tenant.org_id} org_alias={tenant.org_alias} ===")

    print("\n=== Step 1: real Detection row seeded in Postgres ===")
    real_case_id = uuid.uuid4()
    detection = Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=real_case_id,
        finding_id=f"poc-h4-finding-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-h4poc-network-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{real_case_id}-202608",
        rule_matches=(DetectionRuleMatch(rule_id="r1", tags=("high", "attack.t1021.001")),),
        finding_timestamp=datetime.now(UTC),
    )
    detection = await detection_repo.save(detection)
    check("real Detection row persisted", detection.detection_id is not None)
    check("real Detection starts with no external_ticket_id", detection.external_ticket_id is None)

    print("\n=== Step 2: real playbook CREATE run (sync_detection_ticket, 1st sync) ===")
    smuggled_org_id = str(uuid.uuid4())
    smuggled_case_id = str(uuid.uuid4())
    playbook_create = Playbook(
        name="detection-ticket-sync-create",
        steps=(
            PlaybookStep(
                step_id="sync-ticket-create",
                action_name="sync_detection_ticket",
                params={
                    "detection_id": str(detection.detection_id),
                    # Deliberately smuggled -- SyncDetectionTicketAction
                    # never reads org_id/case_id from params at all
                    # (roadmap invariant #3), proved for real below by
                    # checking what the real receiver actually got.
                    "org_id": smuggled_org_id,
                    "case_id": smuggled_case_id,
                },
            ),
        ),
    )
    result = await execution_service.execute(playbook_create, tenant)
    check("real CREATE playbook execution succeeded (no halt)", result.succeeded)
    create_output = result.step_results[0].output if result.step_results else None
    check(
        "real CREATE step produced a real external_ticket_id",
        bool(create_output and create_output.get("external_ticket_id")),
    )
    ticket_id = create_output["external_ticket_id"] if create_output else None
    log(f"real CREATE output: {create_output}")

    check(
        "real local receiver got exactly 1 request so far", len(TicketWebhookHandler.received) == 1
    )
    first_request = TicketWebhookHandler.received[0] if TicketWebhookHandler.received else {}
    check(
        "real request event == kronos.ticket.create",
        first_request.get("event") == "kronos.ticket.create",
    )
    check(
        "real request severity == real Detection's own rule_severity (high)",
        first_request.get("severity") == "high",
    )
    md = first_request.get("metadata", {})
    check(
        "real request metadata.org_id is the REAL tenant org_id, NOT the smuggled one",
        md.get("org_id") == str(tenant.org_id) and md.get("org_id") != smuggled_org_id,
    )
    check(
        "real request metadata.case_id is the REAL Detection.case_id, NOT the smuggled one",
        md.get("case_id") == str(real_case_id) and md.get("case_id") != smuggled_case_id,
    )

    print("\n=== Step 3: independent fresh-connection re-read after CREATE ===")
    fresh_engine_1 = create_async_engine(POSTGRES_DSN)
    fresh_detection_repo_1 = PostgresDetectionRepository(fresh_engine_1)
    fresh_after_create = await fresh_detection_repo_1.get_by_id(
        detection.detection_id, tenant.org_id
    )
    check(
        "fresh read: Detection.external_ticket_id persisted",
        fresh_after_create is not None and fresh_after_create.external_ticket_id == ticket_id,
    )
    check(
        "fresh read: Detection.triage_state UNCHANGED (invariant #5 -- still NEW)",
        fresh_after_create is not None and fresh_after_create.triage_state.value == "NEW",
    )
    await fresh_engine_1.dispose()

    print("\n=== Step 4: real playbook UPDATE run (sync_detection_ticket, 2nd sync) ===")
    playbook_update = Playbook(
        name="detection-ticket-sync-update",
        steps=(
            PlaybookStep(
                step_id="sync-ticket-update",
                action_name="sync_detection_ticket",
                params={
                    "detection_id": str(detection.detection_id),
                    "note": "Escalated during real H4 PoC run",
                },
            ),
        ),
    )
    result2 = await execution_service.execute(playbook_update, tenant)
    check("real UPDATE playbook execution succeeded (no halt)", result2.succeeded)
    update_output = result2.step_results[0].output if result2.step_results else None
    log(f"real UPDATE output: {update_output}")
    check(
        "real UPDATE reuses the SAME ticket_id -- never a second, duplicate ticket",
        update_output is not None and update_output.get("external_ticket_id") == ticket_id,
    )
    check(
        "real local receiver now has exactly 2 requests total",
        len(TicketWebhookHandler.received) == 2,
    )
    second_request = (
        TicketWebhookHandler.received[1] if len(TicketWebhookHandler.received) > 1 else {}
    )
    check(
        "real 2nd request event == kronos.ticket.update",
        second_request.get("event") == "kronos.ticket.update",
    )
    check(
        "real 2nd request carries the real note",
        second_request.get("note") == "Escalated during real H4 PoC run",
    )
    check(
        "real 2nd request references the SAME real ticket_id",
        second_request.get("ticket_id") == ticket_id,
    )

    print("\n=== Step 5: fail loudly -- a real unreachable webhook backend (invariant #8) ===")
    unreachable_ticketing = WebhookTicketingSystem("http://127.0.0.1:1/webhook", timeout=3.0)
    registry_unreachable = PlaybookActionRegistry()
    registry_unreachable.register(
        SyncDetectionTicketAction(detection_repo, unreachable_ticketing, audit_log)
    )
    execution_service_unreachable = PlaybookExecutionService(registry_unreachable, audit_log)

    other_case_id = uuid.uuid4()
    unreachable_detection = await detection_repo.save(
        Detection(
            org_id=tenant.org_id,
            org_alias=tenant.org_alias,
            case_id=other_case_id,
            finding_id=f"poc-h4-finding-unreachable-{uuid.uuid4().hex[:8]}",
            detector_name="kronos-h4poc-network-detector",
            source_index=f"kronos-{tenant.org_alias}-case-{other_case_id}-202608",
            finding_timestamp=datetime.now(UTC),
        )
    )
    playbook_fail = Playbook(
        name="detection-ticket-sync-fail",
        steps=(
            PlaybookStep(
                step_id="sync-ticket-fail",
                action_name="sync_detection_ticket",
                params={"detection_id": str(unreachable_detection.detection_id)},
            ),
        ),
    )
    result3 = await execution_service_unreachable.execute(playbook_fail, tenant)
    check(
        "real playbook run against an unreachable backend HALTS (does not silently succeed)",
        result3.halted_early,
    )
    last_step = result3.step_results[-1] if result3.step_results else None
    check(
        "real failed step's own recorded error is a real, non-empty error message, not swallowed",
        last_step is not None
        and last_step.outcome == PlaybookStepOutcome.FAILED
        and bool(last_step.error),
        last_step.error if last_step is not None and last_step.error else "",
    )

    fresh_engine_2 = create_async_engine(POSTGRES_DSN)
    fresh_detection_repo_2 = PostgresDetectionRepository(fresh_engine_2)
    fresh_unreachable = await fresh_detection_repo_2.get_by_id(
        unreachable_detection.detection_id, tenant.org_id
    )
    check(
        "fresh read: failed sync left external_ticket_id None -- never a fabricated ticket id",
        fresh_unreachable is not None and fresh_unreachable.external_ticket_id is None,
    )
    await fresh_engine_2.dispose()

    print("\n=== Step 6: tenant isolation -- other tenant cannot sync this Detection ===")
    other_tenant = make_tenant(org_alias_prefix="h4poc-other")
    # PlaybookExecutionService.execute() never raises -- a failed step is
    # recorded as a halted, failed PlaybookExecutionResult, not an
    # exception propagating out of execute() itself.
    cross_tenant_result = await execution_service.execute(
        Playbook(
            name="cross-tenant-attempt",
            steps=(
                PlaybookStep(
                    step_id="cross-tenant-sync",
                    action_name="sync_detection_ticket",
                    params={"detection_id": str(detection.detection_id)},
                ),
            ),
        ),
        other_tenant,
    )
    check(
        "real cross-tenant sync attempt halts with a real failed step (not found in other org)",
        cross_tenant_result.halted_early and not cross_tenant_result.succeeded,
    )

    print("\n=== Step 7: real audit hash chain intact end-to-end (fresh connection) ===")
    fresh_engine_3 = create_async_engine(POSTGRES_DSN)
    fresh_audit_repo = PostgresAuditLogRepository(fresh_engine_3)
    fresh_audit_log = AuditLogService(fresh_audit_repo)
    events = [e async for e in fresh_audit_repo.stream_by_org(tenant.org_id)]
    event_types = [e.event_type for e in events]
    check(
        "fresh read: real TICKET_SYNC_ATTEMPTED/_EXECUTED rows exist for the CREATE+UPDATE runs",
        event_types.count(AuditEventType.TICKET_SYNC_ATTEMPTED) >= 3
        and event_types.count(AuditEventType.TICKET_SYNC_EXECUTED) == 2,
    )
    check(
        "fresh read: real TICKET_SYNC_FAILED row exists for the unreachable-backend run",
        AuditEventType.TICKET_SYNC_FAILED in event_types,
    )
    intact, detail = await fresh_audit_log.verify_chain(tenant.org_id)
    check(f"fresh read: real audit hash chain intact end-to-end (detail={detail})", intact)
    await fresh_engine_3.dispose()

    await setup_engine.dispose()
    server.shutdown()
    thread.join(timeout=5)

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(
        f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed "
        f"against the real, live dev-stack Postgres 16 + a real local HTTP receiver."
    )
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
