#!/usr/bin/env python3
"""Findings-only IR walkthrough PoC (Task: post-Milestone-II full assessment,
"incident-response walkthrough" scenario).

Walks a real analyst scenario end to end against the real dev stack:

  detection fires -> analyst lists/filters/gets it -> triages it
  -> contains (real Keycloak session revocation) -> notifies SIEM
  -> auditor runs `kronos-attest case-report` offline

...through the REAL, unmodified HTTP routes (httpx.ASGITransport against
the real create_app(), the same in-process idiom poc/revoke_session_route/
and poc/evidence_download/ already established), a REAL live Keycloak
26.2.5 session (real PKCE login + real revocation, reusing poc/auth_flow/
auth_helpers.py), a REAL local HTTP receiver standing in for a configured
SIEM sink (mirrors poc/integration_sink_foundation/'s own HecJsonHandler
pattern -- generic-envelope JSON sink, not a named vendor, since R2-R4's
own already-verified sinks (poc/integration_sink_splunk_hec/ etc.) are not
what's under test here), and finally the REAL `kronos-attest` CLI run as a
real subprocess against a real exported audit log.

THIS IS A FINDINGS-ONLY POC. It does not fix anything in src/ -- it exists
to empirically confirm (not just read-the-code-infer) a suspected gap: do
the audited outcomes of the two newest analyst-facing actions (SIEM sync,
session-revocation containment) actually show up when an auditor later
asks `kronos-attest case-report --case-id <this case>` for this case's
full story?

Uses a fresh, throwaway Postgres container (kronos-poc-ir-postgres) rather
than the shared docker-postgres-1 -- mirrors poc/evidence_download/'s own
precedent (avoids any dependency on that database's own schema-drift
history; this PoC only needs Case/Detection/AuditLog tables, freshly
created from the current, correct SQLAlchemy metadata).

Run:
  docker run -d --name kronos-poc-ir-postgres -e POSTGRES_DB=kronos \\
    -e POSTGRES_USER=kronos -e POSTGRES_PASSWORD=kronos_dev_password \\
    -p 15433:5432 postgres:16-alpine
  ~/venv/bin/python3 poc/ir_walkthrough_case_scoping/run_poc.py
  docker stop kronos-poc-ir-postgres && docker rm kronos-poc-ir-postgres

Requires: docker-keycloak-1 (26.2.5) already running and reachable via
kronos.local:8443 with a FRESH (non-expired) leaf cert -- see
docs/NEXTGEN_SOC_ROADMAP.md SS5's documented daily friction; this run hit it
(cert had expired 2026-08-19, refreshed via `docker compose -f
docker/docker-compose.dev.yml up -d tls-init && docker restart
docker-nginx-1` before this PoC ran).
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "poc" / "auth_flow"))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

import auth_helpers as ah  # noqa: E402
from src.adapter.integration_sink.http_json_sink import HttpJsonIntegrationSink  # noqa: E402
from src.adapter.integration_sink.sink_authenticator import NullAuthenticator  # noqa: E402
from src.adapter.repository.case_repository import CaseRepository  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_case import PostgresCaseRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.approval_gate import StaticPolicyApprovalGate  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent  # noqa: E402
from src.application.detection_sink_push import DetectionSinkPushService  # noqa: E402
from src.application.detection_triage import DetectionTriageService  # noqa: E402
from src.application.sync_detection_to_siem_action import SyncDetectionToSiemAction  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external import dependencies as deps  # noqa: E402
from src.external.fastapi_app import create_app  # noqa: E402
from src.external.middleware.step_up_store import InMemoryTicketStore  # noqa: E402
from src.external.middleware.tenant_context import get_tenant_context  # noqa: E402

KEYCLOAK_INTERNAL_URL = "http://localhost:8080"
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:15433/kronos"

ADMIN_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000001")  # realm role: org-admin
ANALYST_USER_ID = uuid.UUID("10000000-0000-4000-8000-000000000002")  # realm role: analyst
KRONOS_DEV_ORG_ALIAS = "kronos-dev"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


# ---------------------------------------------------------------------------
# Real local HTTP receiver standing in for a configured "test_webhook" SIEM
# sink -- mirrors poc/integration_sink_foundation/'s own HecJsonHandler.
# ---------------------------------------------------------------------------


class WebhookReceiver(BaseHTTPRequestHandler):
    received: list[dict] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        body = json.loads(raw)
        WebhookReceiver.received.append(body)
        data = json.dumps({"accepted": len(body["events"])}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


class GenericJsonStandInMapper(DetectionEventMapper):
    """Same generic, non-vendor-specific mapper poc/integration_sink_foundation/ uses."""

    def map(self, detection: Detection) -> MappedSinkEvent:
        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            payload={
                "finding_id": detection.finding_id,
                "detector_name": detection.detector_name,
                "severity": detection.rule_severity,
                "attack_tags": list(detection.attack_tags),
            },
            mapper_metadata={"target": "ir-walkthrough-test-webhook"},
        )


def get_raw_admin_token_sync(client: httpx.Client) -> str:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
            "client_secret": KEYCLOAK_ADMIN_CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def raw_get_org_id_sync(client: httpx.Client, token: str, alias: str) -> str:
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations?first=0&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    for org in resp.json():
        if org["alias"] == alias:
            return org["id"]
    raise RuntimeError(f"org alias {alias} not found")


def raw_list_sessions_sync(client: httpx.Client, token: str, user_id: uuid.UUID) -> list[dict]:
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()


def real_login_get_session(username: str, password: str, state: str) -> tuple[str, str]:
    ah.trust_dev_stack_step_ca("docker-tls-init-1")
    ah.KC = "https://kronos.local:8443"
    ah.REDIRECT_URI = "https://kronos.local/poc-ir-callback"
    tokens, _new_secret, _mfa_path = ah.real_browser_login(username, password, totp_secret=None, state=state)
    claims = ah.decode_jwt_payload(tokens["access_token"])
    return tokens["access_token"], claims["sid"]


def make_tenant(org_id: uuid.UUID, org_alias: str, user_id: uuid.UUID, username: str, *roles: Role) -> TenantContext:
    return TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=user_id,
        username=username,
        roles=frozenset(roles),
        correlation_id=str(uuid.uuid4()),
        acr="aal2",
    )


def _fake_keycloak_settings() -> SimpleNamespace:
    secret = MagicMock()
    secret.get_secret_value.return_value = KEYCLOAK_ADMIN_CLIENT_SECRET
    return SimpleNamespace(
        keycloak_url=KEYCLOAK_INTERNAL_URL,
        keycloak_realm=KEYCLOAK_REALM,
        keycloak_client_id=KEYCLOAK_ADMIN_CLIENT_ID,
        keycloak_client_secret=secret,
    )


async def main() -> None:
    deps.reset_dependencies()

    with httpx.Client(timeout=15) as raw:
        admin_token = get_raw_admin_token_sync(raw)
        kronos_dev_org_id = uuid.UUID(raw_get_org_id_sync(raw, admin_token, KRONOS_DEV_ORG_ALIAS))
        log(f"real kronos-dev org id resolved via Admin API: {kronos_dev_org_id}")

    # -----------------------------------------------------------------
    # Real DI wiring against the real, fresh throwaway Postgres.
    # -----------------------------------------------------------------
    with patch("src.config.Settings", return_value=_fake_keycloak_settings()):
        deps.configure_keycloak_admin_client_from_settings()

    engine = create_async_engine(POSTGRES_DSN)
    await PostgresAuditLogRepository.create_tables(engine)
    await PostgresCaseRepository.create_tables(engine)
    await PostgresDetectionRepository.create_tables(engine)

    audit_repo = PostgresAuditLogRepository(engine)
    audit_log = AuditLogService(audit_repo)
    case_repo: CaseRepository = PostgresCaseRepository(engine)
    detection_repo = PostgresDetectionRepository(engine)
    triage_service = DetectionTriageService(detection_repo, audit_log)

    ticket_store = InMemoryTicketStore()
    deps.configure_step_up_auth(ticket_store)

    # Real registry via the real, unmodified DI function -- registers
    # revoke_keycloak_session for real since a real KeycloakAdminClient was
    # just configured above. Uses a StaticPolicyApprovalGate standing allow
    # for this org (skips the step-up-ticket dance, already independently
    # verified end-to-end by poc/revoke_session_route/ -- this PoC's own
    # focus is downstream of the gate, not re-proving the gate itself).
    org_admin_tenant = make_tenant(kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ADMIN_USER_ID, "admin", Role.ORG_ADMIN)
    static_gate = StaticPolicyApprovalGate(frozenset({(kronos_dev_org_id, "revoke_keycloak_session")}))

    registry = deps.get_playbook_action_registry(detection_repo, triage_service, audit_log)
    # Real registry already has revoke_keycloak_session registered (StepUpApprovalGate
    # by default via get_containment_approval_gate) -- re-register it here with the
    # StaticPolicyApprovalGate instead, same real KeycloakAdminClient, same real
    # RevokeKeycloakSessionAction class, only the gate differs.
    from src.application.containment_actions import RevokeKeycloakSessionAction  # noqa: E402

    real_admin_client = deps.get_keycloak_admin_client()
    assert real_admin_client is not None
    registry.register(RevokeKeycloakSessionAction(real_admin_client, static_gate, audit_log))

    # Real local webhook receiver standing in for a configured SIEM sink.
    server = ThreadingHTTPServer(("127.0.0.1", 0), WebhookReceiver)
    webhook_port = server.server_address[1]
    Thread(target=server.serve_forever, daemon=True).start()
    log(f"real local webhook receiver listening on 127.0.0.1:{webhook_port}")

    webhook_sink = HttpJsonIntegrationSink(
        endpoint_url=f"http://127.0.0.1:{webhook_port}/services/collector",
        authenticator=NullAuthenticator(),
    )
    registry.register(
        SyncDetectionToSiemAction(
            "test_webhook",
            detection_repo,
            DetectionSinkPushService(webhook_sink, GenericJsonStandInMapper(), audit_log),
        )
    )

    execution_service = deps.get_playbook_execution_service(registry, audit_log)

    app = create_app(step_up_ticket_store=ticket_store)
    app.dependency_overrides[deps.get_playbook_action_registry] = lambda: registry
    app.dependency_overrides[deps.get_playbook_execution_service] = lambda: execution_service
    app.dependency_overrides[deps.get_case_repository] = lambda: case_repo
    app.dependency_overrides[deps.get_detection_repository] = lambda: detection_repo
    app.dependency_overrides[deps.get_audit_log_service] = lambda: audit_log
    app.dependency_overrides[deps.get_detection_triage_service] = lambda: triage_service

    current_tenant: TenantContext = org_admin_tenant
    app.dependency_overrides[get_tenant_context] = lambda: current_tenant

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://poc-ir") as client:
        # -------------------------------------------------------------
        # Step 1: real case creation (org-admin), through the real route.
        # -------------------------------------------------------------
        log("=== Step 1: real case creation via POST /api/cases ===")
        case_resp = await client.post(
            "/api/cases",
            json={"title": "IR walkthrough PoC case", "description": "kronos-poc-ir scratch case"},
        )
        check("case creation returns 201", case_resp.status_code == 201)
        case_id = uuid.UUID(case_resp.json()["id"])
        log(f"real case created: {case_id}")

        # -------------------------------------------------------------
        # Step 2: a Detection "fires" tied to this case -- direct
        # DetectionRepository.save(), standing in for a real
        # DetectionSyncService.sync_org_findings() run (already verified
        # end to end elsewhere, poc/detection_finding_sync/); this PoC's
        # own focus is everything downstream of a real Detection existing.
        # -------------------------------------------------------------
        log("=== Step 2: a Detection fires, tied to the real case above ===")
        detection = Detection(
            org_id=kronos_dev_org_id,
            org_alias=KRONOS_DEV_ORG_ALIAS,
            case_id=case_id,
            finding_id=f"poc-ir-finding-{uuid.uuid4()}",
            detector_name="poc-ir-suspicious-login-detector",
            source_index=f".opensearch-sap--detectors-{case_id}",
            rule_matches=(
                DetectionRuleMatch(
                    rule_id="poc-ir-rule-1",
                    rule_name="Suspicious login from new location",
                    tags=("high", "attack.t1078"),
                ),
            ),
            matched_document_ids=("poc-ir-doc-1",),
            finding_timestamp=datetime.now(UTC),
        )
        detection = await detection_repo.save(detection)
        check("detection saved with the real case_id attached", detection.case_id == case_id)

        # -------------------------------------------------------------
        # Step 3: analyst investigates -- list (filtered by case), get.
        # -------------------------------------------------------------
        log("=== Step 3: analyst lists/filters/gets the detection ===")
        list_resp = await client.get("/api/detections", params={"caseId": str(case_id)})
        check("list detections (caseId filter) returns 200", list_resp.status_code == 200)
        check(
            "the real detection appears in the case-filtered list",
            any(d["id"] == str(detection.detection_id) for d in list_resp.json()["items"]),
        )

        get_resp = await client.get(f"/api/detections/{detection.detection_id}")
        check("get detection returns 200", get_resp.status_code == 200)
        check("get detection shows triageState=NEW", get_resp.json()["triageState"] == "NEW")

        # -------------------------------------------------------------
        # Step 4: analyst triages -- NEW -> INVESTIGATING -> TRUE_POSITIVE.
        # -------------------------------------------------------------
        log("=== Step 4: analyst triages NEW -> INVESTIGATING -> TRUE_POSITIVE ===")
        current_tenant = make_tenant(kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ANALYST_USER_ID, "analyst", Role.ANALYST)
        t1 = await client.post(f"/api/detections/{detection.detection_id}/triage", json={"targetState": "INVESTIGATING"})
        check("triage NEW->INVESTIGATING succeeds", t1.status_code == 200 and t1.json()["triageState"] == "INVESTIGATING")
        t2 = await client.post(f"/api/detections/{detection.detection_id}/triage", json={"targetState": "TRUE_POSITIVE"})
        check("triage INVESTIGATING->TRUE_POSITIVE succeeds", t2.status_code == 200 and t2.json()["triageState"] == "TRUE_POSITIVE")

        # -------------------------------------------------------------
        # Step 5: real containment -- a real live Keycloak session for
        # the "analyst" dev user is revoked via the real route.
        # -------------------------------------------------------------
        log("=== Step 5: real containment -- revoke the analyst's real live Keycloak session ===")
        _tok, real_session_id = real_login_get_session("analyst", "DevAnalyst#2026", state="poc-ir-walkthrough")
        log(f"real analyst login succeeded, sid={real_session_id}")

        with httpx.Client(timeout=15) as raw2:
            sessions_before = raw_list_sessions_sync(raw2, admin_token, ANALYST_USER_ID)
        check("real session visible via Admin API before revoke", any(s["id"] == real_session_id for s in sessions_before))

        current_tenant = make_tenant(kronos_dev_org_id, KRONOS_DEV_ORG_ALIAS, ADMIN_USER_ID, "admin", Role.ORG_ADMIN, Role.CASE_LEAD)
        revoke_resp = await client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"userId": str(ANALYST_USER_ID), "sessionId": real_session_id},
        )
        check("revoke-session route returns 200", revoke_resp.status_code == 200)
        revoke_body = revoke_resp.json()
        check("real containment action succeeded=true", revoke_body["succeeded"] is True)

        with httpx.Client(timeout=15) as raw3:
            sessions_after = raw_list_sessions_sync(raw3, admin_token, ANALYST_USER_ID)
        check("real session is GONE after containment (independent Admin API re-check)", not any(s["id"] == real_session_id for s in sessions_after))

        # -------------------------------------------------------------
        # Step 6: real SIEM notification via the real local webhook.
        # -------------------------------------------------------------
        log("=== Step 6: real SIEM sync via the real local webhook receiver ===")
        sync_resp = await client.post(f"/api/detections/{detection.detection_id}/sync-to-siem/test_webhook")
        check("sync-to-siem route returns 200", sync_resp.status_code == 200)
        sync_body = sync_resp.json()
        check("real SIEM push succeeded=true", sync_body["succeeded"] is True)
        check("the real local webhook actually received the push", len(WebhookReceiver.received) == 1)
        server.shutdown()

        # -------------------------------------------------------------
        # Step 7: auditor exports the org's audit log and runs the real
        # `kronos-attest case-report` CLI against it, offline.
        # -------------------------------------------------------------
        log("=== Step 7: auditor exports audit log, runs real kronos-attest case-report ===")
        export_resp = await client.get("/api/audit/export")
        check("audit export route returns 200", export_resp.status_code == 200)
        all_events = export_resp.json()
        log(f"real org audit export contains {len(all_events)} total events")

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(all_events, f)
            export_path = f.name

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "kronos_attest.cli",
                "case-report",
                "--audit-log",
                export_path,
                "--case-id",
                str(case_id),
            ],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        log(f"kronos-attest case-report stdout:\n{proc.stdout}")
        if proc.stderr:
            log(f"kronos-attest case-report stderr:\n{proc.stderr}")
        check("kronos-attest case-report exits 0", proc.returncode == 0)
        report = json.loads(proc.stdout)

        # -------------------------------------------------------------
        # THE FINDING: manually compute which real audit rows exist for
        # this detection's own containment/SIEM-sync activity (by
        # inspecting each event's own details.params/detection_ids,
        # since these events carry no case_id of their own), and compare
        # against what kronos-attest case-report actually reported.
        # -------------------------------------------------------------
        log("=== Step 8: THE FINDING -- does case-report see the containment/SIEM audit trail? ===")

        def _references_our_detection(ev: dict) -> bool:
            details = ev.get("details") or {}
            params = details.get("params") or {}
            if params.get("detection_id") == str(detection.detection_id):
                return True
            det_ids = details.get("detection_ids") or []
            return str(detection.detection_id) in det_ids

        containment_and_sink_events = [
            ev
            for ev in all_events
            if ev["event_type"]
            in {
                "containment.action_attempted",
                "containment.action_executed",
                "sink.push_attempted",
                "sink.push_executed",
            }
            and _references_our_detection(ev)
        ]
        check(
            "real CONTAINMENT_ACTION_*/SINK_PUSH_* rows for this detection DO exist "
            "in the full org export",
            len(containment_and_sink_events) >= 4,  # attempted+executed x2 action types
        )
        none_have_case_id = all(ev.get("case_id") is None for ev in containment_and_sink_events)
        check(
            "...but NONE of them carry this (or any) case_id in the exported event "
            "(ContainmentAction.execute()/DetectionSinkPushService.push() never pass "
            "case_id= to AuditLogService.log())",
            none_have_case_id,
        )

        case_report_event_ids = {ev["event_id"] for ev in all_events if ev.get("case_id") == str(case_id)}
        missing_from_case_report = [
            ev for ev in containment_and_sink_events if ev["event_id"] not in case_report_event_ids
        ]
        check(
            "THE GAP: every one of this detection's own real containment/SIEM-sync "
            "audit rows is invisible to `kronos-attest case-report --case-id "
            f"{case_id}` (event_count={report['event_count']}), even though the "
            "underlying Detection is genuinely, correctly tied to this exact case",
            len(missing_from_case_report) == len(containment_and_sink_events)
            and len(containment_and_sink_events) > 0,
        )

        # Contrast: triage events DO correctly carry case_id (DetectionTriageService
        # passes case_id=detection.case_id) -- confirms this is a real, specific
        # inconsistency between two collaborators, not a blanket "nothing works".
        triage_events_for_case = [
            ev
            for ev in all_events
            if ev["event_type"] == "detection.triage_transitioned" and ev.get("case_id") == str(case_id)
        ]
        check(
            "CONTRAST: DetectionTriageService's own audit rows DO correctly carry "
            "this case_id (proves the omission above is specific to Containment/"
            "SinkPush, not a platform-wide audit-export bug)",
            len(triage_events_for_case) == 2,
        )

        Path(export_path).unlink(missing_ok=True)

    await engine.dispose()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(f"PoC {'PASSED' if passed == total else 'FAILED'} -- {passed}/{total} checks passed.")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
