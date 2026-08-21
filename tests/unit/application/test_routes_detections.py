"""Unit tests for the detection HTTP routes (roadmap M2/C6) via TestClient.

Mocks only the repository/audit-log layer (§B.5) -- exercises the real
DetectionTriageService and the real Detection domain FSM, not a
reimplementation of either.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from src.adapter.keycloak.admin_client import (
    KeycloakAdminClient,
    KeycloakOrganization,
    KeycloakSession,
)
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.approval_gate import StaticPolicyApprovalGate, StepUpApprovalGate
from src.application.audit_log import AuditLogService
from src.application.containment_actions import RevokeKeycloakSessionAction
from src.application.detection_triage import DetectionTriageService
from src.application.playbook import PlaybookAction, PlaybookActionRegistry
from src.application.playbook_execution import PlaybookExecutionService
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState
from src.domain.user import Role, TenantContext
from src.exceptions import PlaybookError
from src.external.dependencies import (
    get_detection_repository,
    get_detection_triage_service,
    get_playbook_action_registry,
    get_playbook_execution_service,
)
from src.external.fastapi_app import create_app
from src.external.middleware.step_up_store import InMemoryTicketStore
from src.external.middleware.tenant_context import get_tenant_context
from tests.conftest import InMemoryAuditLogRepository

ORG_A = uuid.uuid4()
ORG_B = uuid.uuid4()
CASE_A = uuid.uuid4()
USER_A = uuid.uuid4()


def _make_detection(
    *,
    org_id: uuid.UUID = ORG_A,
    case_id: uuid.UUID | None = CASE_A,
    triage_state: DetectionTriageState = DetectionTriageState.NEW,
    finding_id: str | None = None,
) -> Detection:
    return Detection(
        org_id=org_id,
        org_alias="testorg",
        case_id=case_id,
        finding_id=finding_id or str(uuid.uuid4()),
        detector_name="kronos-testorg-network-detector",
        source_index=(
            f"kronos-testorg-case-{case_id}-202601"
            if case_id
            else "kronos-testorg-stream-dns-202601"
        ),
        rule_matches=(
            DetectionRuleMatch(
                rule_id="rule-1", rule_name="Suspicious Thing", tags=("attack.t1021.001", "high")
            ),
        ),
        matched_document_ids=("doc-1",),
        finding_timestamp=datetime.now(UTC),
        triage_state=triage_state,
    )


def _fixed_tenant(org_id: uuid.UUID, *roles: Role) -> TenantContext:
    return TenantContext(
        org_id=org_id,
        org_alias="testorg",
        user_id=USER_A,
        username="testuser",
        roles=frozenset(roles),
        correlation_id=str(uuid.uuid4()),
    )


@pytest.fixture
def detection_repo() -> InMemoryDetectionRepository:
    return InMemoryDetectionRepository()


def _build_client(
    detection_repo: InMemoryDetectionRepository,
    tenant: TenantContext,
    *,
    playbook_registry: PlaybookActionRegistry | None = None,
) -> TestClient:
    audit_svc = AuditLogService(InMemoryAuditLogRepository())
    triage_service = DetectionTriageService(detection_repo, audit_svc)

    app = create_app()
    app.dependency_overrides[get_tenant_context] = lambda: tenant
    app.dependency_overrides[get_detection_repository] = lambda: detection_repo
    app.dependency_overrides[get_detection_triage_service] = lambda: triage_service
    if playbook_registry is not None:
        app.dependency_overrides[get_playbook_action_registry] = lambda: playbook_registry
        app.dependency_overrides[get_playbook_execution_service] = lambda: PlaybookExecutionService(
            playbook_registry, audit_svc
        )
    return TestClient(app)


class _FakeSyncToSiemAction(PlaybookAction):
    """Minimal, hand-written PlaybookAction fake for these route tests --
    the real SyncDetectionToSiemAction is already covered by
    tests/unit/application/test_sync_detection_to_siem_action.py; this route
    only needs to prove PlaybookExecutionService.execute() is genuinely
    reachable and its result correctly shaped in the HTTP response, per
    CLAUDE.md SS B.5 ("mock only external dependencies")."""

    def __init__(self, sink_name: str, *, fail: bool = False) -> None:
        self._sink_name = sink_name
        self._fail = fail
        self.calls: list[dict[str, object]] = []

    @property
    def action_name(self) -> str:
        return f"sync_detection_to_siem_{self._sink_name}"

    async def execute(self, params: dict[str, object], tenant: TenantContext) -> dict[str, object]:
        self.calls.append({"params": params, "org_id": tenant.org_id})
        if self._fail:
            raise PlaybookError("simulated real sink push failure", context={"params": params})
        return {"detection_id": params["detection_id"], "sink": self._sink_name, "pushed": True}


class TestListDetections:
    def test_empty_org_returns_empty_list(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get("/api/detections")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"items": [], "total": 0, "page": 1, "pageSize": 50}

    def test_returns_only_the_callers_org(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        asyncio.run(detection_repo.save(_make_detection(org_id=ORG_B)))

        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get("/api/detections")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["orgId"] == str(ORG_A)

    def test_response_fields_are_camel_case(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get("/api/detections")
        item = resp.json()["items"][0]
        assert item["id"] == str(detection.detection_id)
        assert item["findingId"] == detection.finding_id
        assert item["detectorName"] == detection.detector_name
        assert item["ruleMatches"][0]["ruleId"] == "rule-1"
        assert item["attackTags"] == ["attack.t1021.001"]
        assert item["triageState"] == "NEW"

    def test_filter_by_triage_state(self, detection_repo: InMemoryDetectionRepository) -> None:
        new_one = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        investigating = asyncio.run(
            detection_repo.save(_make_detection(org_id=ORG_A, finding_id="f-2"))
        )
        investigating = investigating.with_triage_state(DetectionTriageState.INVESTIGATING)
        asyncio.run(detection_repo.update(investigating))

        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get("/api/detections", params={"triageState": "NEW"})
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["id"] == str(new_one.detection_id)

    def test_filter_by_case_id(self, detection_repo: InMemoryDetectionRepository) -> None:
        other_case = uuid.uuid4()
        asyncio.run(
            detection_repo.save(_make_detection(org_id=ORG_A, case_id=CASE_A, finding_id="f-1"))
        )
        asyncio.run(
            detection_repo.save(_make_detection(org_id=ORG_A, case_id=other_case, finding_id="f-2"))
        )

        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get("/api/detections", params={"caseId": str(CASE_A)})
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["caseId"] == str(CASE_A)

    def test_read_only_role_can_list(self, detection_repo: InMemoryDetectionRepository) -> None:
        asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.READ_ONLY))
        resp = client.get("/api/detections")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_risk_score_and_factors_surface_in_the_response(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        """Roadmap M5/F4: risk_score/risk_factors are plain frozen fields on
        Detection (set once at sync time by DetectionSyncService) -- this
        confirms they actually round-trip through the existing triage list
        route, camelCased like every other field on this DTO."""
        from src.domain.risk import RiskFactor

        detection = _make_detection(org_id=ORG_A).model_copy(
            update={
                "risk_score": 82.65,
                "risk_factors": (
                    RiskFactor(
                        name="rule_severity",
                        weight=0.35,
                        normalized_value=0.75,
                        detail="highest matched rule severity is 'high'",
                    ),
                    RiskFactor(
                        name="identity_privilege",
                        weight=0.15,
                        normalized_value=None,
                        detail="no identity-context enricher exists yet",
                    ),
                ),
            }
        )
        asyncio.run(detection_repo.save(detection))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get("/api/detections")
        item = resp.json()["items"][0]
        assert item["riskScore"] == 82.65
        assert item["riskFactors"][0]["name"] == "rule_severity"
        assert item["riskFactors"][0]["normalizedValue"] == 0.75
        assert item["riskFactors"][1]["name"] == "identity_privilege"
        assert item["riskFactors"][1]["normalizedValue"] is None

    def test_risk_score_defaults_to_null_when_never_computed(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get("/api/detections")
        item = resp.json()["items"][0]
        assert item["riskScore"] is None
        assert item["riskFactors"] == []


class TestGetDetection:
    def test_returns_detail_for_own_org(self, detection_repo: InMemoryDetectionRepository) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get(f"/api/detections/{detection.detection_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == str(detection.detection_id)

    def test_cross_org_returns_404_not_403(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_B)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get(f"/api/detections/{detection.detection_id}")
        assert resp.status_code == 404

    def test_nonexistent_id_returns_404(self, detection_repo: InMemoryDetectionRepository) -> None:
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.CASE_LEAD))
        resp = client.get(f"/api/detections/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestTriageDetection:
    def test_valid_transition_returns_200_and_persists(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.ANALYST))

        resp = client.post(
            f"/api/detections/{detection.detection_id}/triage",
            json={"targetState": "INVESTIGATING"},
        )
        assert resp.status_code == 200
        assert resp.json()["triageState"] == "INVESTIGATING"

        persisted = asyncio.run(detection_repo.get_by_id(detection.detection_id, ORG_A))
        assert persisted is not None
        assert persisted.triage_state == DetectionTriageState.INVESTIGATING

    def test_illegal_transition_returns_409_not_500(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.ANALYST))

        resp = client.post(
            f"/api/detections/{detection.detection_id}/triage",
            json={"targetState": "TRUE_POSITIVE"},
        )
        assert resp.status_code == 409

        persisted = asyncio.run(detection_repo.get_by_id(detection.detection_id, ORG_A))
        assert persisted is not None
        assert persisted.triage_state == DetectionTriageState.NEW

    def test_terminal_state_rejects_retransition(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(
            detection_repo.save(
                _make_detection(org_id=ORG_A, triage_state=DetectionTriageState.TRUE_POSITIVE)
            )
        )
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.ANALYST))

        resp = client.post(
            f"/api/detections/{detection.detection_id}/triage",
            json={"targetState": "INVESTIGATING"},
        )
        assert resp.status_code == 409

    def test_cross_org_triage_returns_404(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_B)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.ANALYST))

        resp = client.post(
            f"/api/detections/{detection.detection_id}/triage",
            json={"targetState": "INVESTIGATING"},
        )
        assert resp.status_code == 404

    def test_read_only_role_forbidden(self, detection_repo: InMemoryDetectionRepository) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        client = _build_client(detection_repo, _fixed_tenant(ORG_A, Role.READ_ONLY))

        resp = client.post(
            f"/api/detections/{detection.detection_id}/triage",
            json={"targetState": "INVESTIGATING"},
        )
        assert resp.status_code == 403


class TestSyncDetectionToSiem:
    """POST /api/detections/{id}/sync-to-siem/{sink_name} (roadmap Milestone
    W/W1, IR walkthrough F3) -- the first HTTP route anywhere in this
    codebase that reaches PlaybookExecutionService.execute()."""

    def test_registered_sink_pushes_and_returns_succeeded_true(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        action = _FakeSyncToSiemAction("splunk")
        registry = PlaybookActionRegistry()
        registry.register(action)
        client = _build_client(
            detection_repo, _fixed_tenant(ORG_A, Role.ANALYST), playbook_registry=registry
        )

        resp = client.post(f"/api/detections/{detection.detection_id}/sync-to-siem/splunk")

        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded"] is True
        assert body["haltedEarly"] is False
        assert body["stepResults"][0]["actionName"] == "sync_detection_to_siem_splunk"
        assert body["stepResults"][0]["output"]["pushed"] is True
        assert action.calls[0]["params"]["detection_id"] == str(detection.detection_id)
        assert action.calls[0]["org_id"] == ORG_A

    def test_unconfigured_sink_returns_404(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        registry = PlaybookActionRegistry()  # no sinks registered -- honest "unconfigured"
        client = _build_client(
            detection_repo, _fixed_tenant(ORG_A, Role.ANALYST), playbook_registry=registry
        )

        resp = client.post(f"/api/detections/{detection.detection_id}/sync-to-siem/splunk")

        assert resp.status_code == 404

    def test_action_failure_is_reflected_not_raised(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        registry = PlaybookActionRegistry()
        registry.register(_FakeSyncToSiemAction("splunk", fail=True))
        client = _build_client(
            detection_repo, _fixed_tenant(ORG_A, Role.ANALYST), playbook_registry=registry
        )

        resp = client.post(f"/api/detections/{detection.detection_id}/sync-to-siem/splunk")

        assert resp.status_code == 200  # audited failure, not a raised HTTP error
        body = resp.json()
        assert body["succeeded"] is False
        assert body["haltedEarly"] is True
        assert "simulated real sink push failure" in body["stepResults"][0]["error"]

    def test_read_only_role_forbidden(self, detection_repo: InMemoryDetectionRepository) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        registry = PlaybookActionRegistry()
        registry.register(_FakeSyncToSiemAction("splunk"))
        client = _build_client(
            detection_repo, _fixed_tenant(ORG_A, Role.READ_ONLY), playbook_registry=registry
        )

        resp = client.post(f"/api/detections/{detection.detection_id}/sync-to-siem/splunk")

        assert resp.status_code == 403

    def test_multiple_sinks_select_by_name(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        """Roadmap-honest design decision: sink_name in the URL, not one
        hardcoded action, so a deployment with >1 real configured sink
        (e.g. Splunk AND Sentinel) is fully reachable, not silently
        limited to whichever one happened to be hardcoded."""
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        splunk_action = _FakeSyncToSiemAction("splunk")
        sentinel_action = _FakeSyncToSiemAction("sentinel")
        registry = PlaybookActionRegistry()
        registry.register(splunk_action)
        registry.register(sentinel_action)
        client = _build_client(
            detection_repo, _fixed_tenant(ORG_A, Role.ANALYST), playbook_registry=registry
        )

        resp = client.post(f"/api/detections/{detection.detection_id}/sync-to-siem/sentinel")

        assert resp.status_code == 200
        assert resp.json()["stepResults"][0]["actionName"] == "sync_detection_to_siem_sentinel"
        assert len(sentinel_action.calls) == 1
        assert len(splunk_action.calls) == 0


class _FakeKeycloakAdminClientForRoute(KeycloakAdminClient):
    """Small typed fake -- the ONE external dependency these route tests
    mock (mirrors ``_FakeKeycloakAdminClient`` in
    ``tests/unit/application/test_containment_actions.py``, CLAUDE.md SS
    B.5). ``RevokeKeycloakSessionAction``, ``ContainmentAction``,
    ``StepUpApprovalGate``/``StaticPolicyApprovalGate``, and
    ``PlaybookExecutionService`` are all real, unmodified ``src/`` code,
    reached through the real HTTP route below -- not reimplemented or
    faked at the route boundary the way ``_FakeSyncToSiemAction`` above
    fakes a whole ``PlaybookAction``."""

    def __init__(
        self,
        *,
        org_members: set[uuid.UUID] | None = None,
        sessions_by_user: dict[uuid.UUID, tuple[KeycloakSession, ...]] | None = None,
    ) -> None:
        self.org_members = org_members or set()
        self.sessions_by_user = sessions_by_user or {}
        self.revoked_session_ids: list[str] = []

    async def list_user_sessions(self, user_id: uuid.UUID) -> tuple[KeycloakSession, ...]:
        return self.sessions_by_user.get(user_id, ())

    async def revoke_session(self, session_id: str) -> None:
        self.revoked_session_ids.append(session_id)

    async def is_org_member(self, org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        return user_id in self.org_members

    async def get_organization_alias(self, org_id: uuid.UUID) -> str | None:
        return None

    async def list_organizations(self) -> tuple[KeycloakOrganization, ...]:
        return ()


def _build_revoke_session_client(
    detection_repo: InMemoryDetectionRepository,
    tenant: TenantContext,
    *,
    admin: KeycloakAdminClient | None,
    approval_gate: StepUpApprovalGate | StaticPolicyApprovalGate,
) -> tuple[TestClient, InMemoryAuditLogRepository]:
    audit_repo = InMemoryAuditLogRepository()
    audit_svc = AuditLogService(audit_repo)
    triage_service = DetectionTriageService(detection_repo, audit_svc)

    registry = PlaybookActionRegistry()
    if admin is not None:
        registry.register(RevokeKeycloakSessionAction(admin, approval_gate, audit_svc))

    app = create_app()
    app.dependency_overrides[get_tenant_context] = lambda: tenant
    app.dependency_overrides[get_detection_repository] = lambda: detection_repo
    app.dependency_overrides[get_detection_triage_service] = lambda: triage_service
    app.dependency_overrides[get_playbook_action_registry] = lambda: registry
    app.dependency_overrides[get_playbook_execution_service] = lambda: PlaybookExecutionService(
        registry, audit_svc
    )
    return TestClient(app), audit_repo


class TestRevokeSessionForDetection:
    """POST /api/detections/{id}/contain/revoke-session (roadmap M7/H2/EE1).

    Wires the real, previously-unreachable ``RevokeKeycloakSessionAction``
    (H2's own "one real, deeply-verified adapter", shipped with zero HTTP
    route per that item's own explicitly-flagged scope note) into the real
    HTTP surface for the first time. Mocks only the external
    ``KeycloakAdminClient`` (CLAUDE.md SS B.5) -- the gate, audit, and
    route response-shaping logic exercised here is all real, unmodified
    ``src/`` code, the same bar ``test_containment_actions.py`` already
    holds this action's own unit tests to.
    """

    def test_org_admin_with_valid_ticket_revokes_for_real(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClientForRoute(
            org_members={target_user},
            sessions_by_user={
                target_user: (KeycloakSession("sess-1", str(target_user), "victim", "10.0.0.5", 0),)
            },
        )
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        ticket_store = InMemoryTicketStore()
        ticket_id = uuid.uuid4()
        ticket_store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-1")
        client, _audit_repo = _build_revoke_session_client(
            detection_repo, tenant, admin=admin, approval_gate=StepUpApprovalGate(ticket_store)
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={
                "userId": str(target_user),
                "sessionId": "sess-1",
                "approvalTicketId": str(ticket_id),
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded"] is True
        assert body["haltedEarly"] is False
        assert body["stepResults"][0]["actionName"] == "revoke_keycloak_session"
        assert body["stepResults"][0]["output"] == {
            "user_id": str(target_user),
            "session_id": "sess-1",
            "revoked": True,
        }
        assert admin.revoked_session_ids == ["sess-1"]  # the real (fake-backed) revoke ran

    def test_audit_rows_are_case_scoped_via_a_real_detection_lookup(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        """Gap Audit Milestone LL: the route looks the real Detection up by
        detection_id (audit context only, same as detection_id itself --
        an unknown/cross-org id never blocks the real containment action)
        and threads its case_id through to ContainmentAction.execute() so
        these rows are visible to kronos-attest case-report /
        GET /api/cases/{id}/audit, mirroring
        DetectionTriageService.transition()'s own real pattern."""
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A, case_id=CASE_A)))
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClientForRoute(
            org_members={target_user},
            sessions_by_user={
                target_user: (KeycloakSession("sess-1", str(target_user), "victim", "10.0.0.5", 0),)
            },
        )
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        ticket_store = InMemoryTicketStore()
        ticket_id = uuid.uuid4()
        ticket_store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-1")
        client, audit_repo = _build_revoke_session_client(
            detection_repo, tenant, admin=admin, approval_gate=StepUpApprovalGate(ticket_store)
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={
                "userId": str(target_user),
                "sessionId": "sess-1",
                "approvalTicketId": str(ticket_id),
            },
        )

        assert resp.status_code == 200
        assert resp.json()["succeeded"] is True

        async def _collect() -> list[AuditEvent]:
            return [e async for e in audit_repo.stream_by_org(tenant.org_id)]

        events = asyncio.run(_collect())
        containment_events = [
            e
            for e in events
            if e.event_type
            in (
                AuditEventType.CONTAINMENT_ACTION_ATTEMPTED,
                AuditEventType.CONTAINMENT_ACTION_EXECUTED,
            )
        ]
        assert len(containment_events) == 2
        assert all(e.case_id == CASE_A for e in containment_events)

    def test_case_lead_role_is_permitted(self, detection_repo: InMemoryDetectionRepository) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClientForRoute(
            org_members={target_user},
            sessions_by_user={
                target_user: (KeycloakSession("sess-1", str(target_user), "v", "1.2.3.4", 0),)
            },
        )
        tenant = _fixed_tenant(ORG_A, Role.CASE_LEAD)
        policy_gate = StaticPolicyApprovalGate(frozenset({(ORG_A, "revoke_keycloak_session")}))
        client, _audit_repo = _build_revoke_session_client(
            detection_repo, tenant, admin=admin, approval_gate=policy_gate
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"userId": str(target_user), "sessionId": "sess-1"},
        )

        assert resp.status_code == 200
        assert resp.json()["succeeded"] is True
        assert admin.revoked_session_ids == ["sess-1"]

    def test_analyst_role_forbidden(self, detection_repo: InMemoryDetectionRepository) -> None:
        """Deliberately narrower than sync-to-siem's ANALYST-inclusive
        gate -- this is a genuinely destructive containment action."""
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        admin = _FakeKeycloakAdminClientForRoute()
        tenant = _fixed_tenant(ORG_A, Role.ANALYST)
        client, _audit_repo = _build_revoke_session_client(
            detection_repo,
            tenant,
            admin=admin,
            approval_gate=StaticPolicyApprovalGate(frozenset()),
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"userId": str(uuid.uuid4()), "sessionId": "sess-1"},
        )

        assert resp.status_code == 403
        assert admin.revoked_session_ids == []

    def test_read_only_role_forbidden(self, detection_repo: InMemoryDetectionRepository) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        admin = _FakeKeycloakAdminClientForRoute()
        tenant = _fixed_tenant(ORG_A, Role.READ_ONLY)
        client, _audit_repo = _build_revoke_session_client(
            detection_repo,
            tenant,
            admin=admin,
            approval_gate=StaticPolicyApprovalGate(frozenset()),
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"userId": str(uuid.uuid4()), "sessionId": "sess-1"},
        )

        assert resp.status_code == 403

    def test_missing_ticket_is_denied_not_executed(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClientForRoute(
            org_members={target_user},
            sessions_by_user={
                target_user: (KeycloakSession("sess-1", str(target_user), "v", "1.2.3.4", 0),)
            },
        )
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        client, _audit_repo = _build_revoke_session_client(
            detection_repo,
            tenant,
            admin=admin,
            approval_gate=StepUpApprovalGate(InMemoryTicketStore()),
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"userId": str(target_user), "sessionId": "sess-1"},  # no ticket supplied
        )

        assert resp.status_code == 200  # audited denial, not a raised HTTP error
        body = resp.json()
        assert body["succeeded"] is False
        assert body["haltedEarly"] is True
        assert "denied" in body["stepResults"][0]["error"].lower()
        assert admin.revoked_session_ids == []  # the real destructive call never ran

    def test_ticket_for_one_session_cannot_revoke_a_different_real_session(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        """Gap Audit Milestone JJ regression test, exercised at the real HTTP
        route layer (not just the gate unit level -- see
        test_approval_gate.py's own
        test_ticket_cannot_be_replayed_against_a_different_real_resource).

        Before this fix, RevokeKeycloakSessionIn accepted a separate,
        caller-supplied ``approvalResourceId`` field that the route passed
        straight through to ``ApprovalGate.authorize()`` with no check that
        it actually matched ``sessionId``. A caller holding a valid ticket
        minted for session X could revoke a completely different session Y
        by setting ``approvalResourceId`` to X while ``sessionId`` named Y.
        That field no longer exists on the request model at all -- the real
        target (``sessionId``) is what the ticket is checked against,
        server-side, every time."""
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClientForRoute(
            org_members={target_user},
            sessions_by_user={
                target_user: (
                    KeycloakSession("sess-X", str(target_user), "victim", "10.0.0.5", 0),
                    KeycloakSession("sess-Y", str(target_user), "victim", "10.0.0.6", 0),
                )
            },
        )
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        ticket_store = InMemoryTicketStore()
        ticket_id = uuid.uuid4()
        # Ticket is minted for sess-X only.
        ticket_store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-X")
        client, _audit_repo = _build_revoke_session_client(
            detection_repo, tenant, admin=admin, approval_gate=StepUpApprovalGate(ticket_store)
        )

        # Attack: real target is sess-Y, but the only valid ticket held is
        # for sess-X.
        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={
                "userId": str(target_user),
                "sessionId": "sess-Y",
                "approvalTicketId": str(ticket_id),
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded"] is False
        assert "denied" in body["stepResults"][0]["error"].lower()
        assert admin.revoked_session_ids == []  # sess-Y was never revoked

        # The ticket must remain unconsumed by the denied mismatch attempt --
        # a legitimate follow-up request against its real resource (sess-X)
        # must still succeed.
        retry = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={
                "userId": str(target_user),
                "sessionId": "sess-X",
                "approvalTicketId": str(ticket_id),
            },
        )
        assert retry.status_code == 200
        retry_body = retry.json()
        assert retry_body["succeeded"] is True
        assert admin.revoked_session_ids == ["sess-X"]

    def test_cross_org_target_user_rejected_even_with_valid_ticket(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        """Roadmap invariant #3: a valid step-up ticket does not bypass
        RevokeKeycloakSessionAction's own real, independent org-membership
        check."""
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        other_org_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClientForRoute(
            org_members=set(),  # NOT a member of ORG_A
            sessions_by_user={
                other_org_user: (
                    KeycloakSession("sess-cross-org", str(other_org_user), "o", "1.2.3.4", 0),
                )
            },
        )
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        ticket_store = InMemoryTicketStore()
        ticket_id = uuid.uuid4()
        ticket_store.put(ticket_id, tenant.user_id, "revoke_keycloak_session", "sess-cross-org")
        client, _audit_repo = _build_revoke_session_client(
            detection_repo, tenant, admin=admin, approval_gate=StepUpApprovalGate(ticket_store)
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={
                "userId": str(other_org_user),
                "sessionId": "sess-cross-org",
                "approvalTicketId": str(ticket_id),
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded"] is False
        assert "organization" in body["stepResults"][0]["error"].lower()
        assert admin.revoked_session_ids == []

    def test_unconfigured_action_returns_404(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        """Mirrors sync-to-siem's own "honestly unconfigured" 404 -- no
        RevokeKeycloakSessionAction registered (no real KeycloakAdminClient
        in this deployment)."""
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        client, _audit_repo = _build_revoke_session_client(
            detection_repo,
            tenant,
            admin=None,
            approval_gate=StaticPolicyApprovalGate(frozenset()),
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"userId": str(uuid.uuid4()), "sessionId": "sess-1"},
        )

        assert resp.status_code == 404

    def test_missing_required_field_returns_422(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        admin = _FakeKeycloakAdminClientForRoute()
        client, _audit_repo = _build_revoke_session_client(
            detection_repo,
            tenant,
            admin=admin,
            approval_gate=StaticPolicyApprovalGate(frozenset()),
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"sessionId": "sess-1"},  # missing userId
        )

        assert resp.status_code == 422

    def test_real_containment_audit_rows_are_recorded(
        self, detection_repo: InMemoryDetectionRepository
    ) -> None:
        """Confirms the route reaches the real ContainmentAction audit
        sequence (CONTAINMENT_ACTION_ATTEMPTED/_EXECUTED) -- the audit
        trail this route's own docstring claims is the real source of
        truth, not just a 200 status code."""
        detection = asyncio.run(detection_repo.save(_make_detection(org_id=ORG_A)))
        target_user = uuid.uuid4()
        admin = _FakeKeycloakAdminClientForRoute(
            org_members={target_user},
            sessions_by_user={
                target_user: (KeycloakSession("sess-1", str(target_user), "v", "1.2.3.4", 0),)
            },
        )
        tenant = _fixed_tenant(ORG_A, Role.ORG_ADMIN)
        policy_gate = StaticPolicyApprovalGate(frozenset({(ORG_A, "revoke_keycloak_session")}))
        client, audit_repo = _build_revoke_session_client(
            detection_repo, tenant, admin=admin, approval_gate=policy_gate
        )

        resp = client.post(
            f"/api/detections/{detection.detection_id}/contain/revoke-session",
            json={"userId": str(target_user), "sessionId": "sess-1"},
        )
        assert resp.status_code == 200

        events = asyncio.run(_collect(audit_repo.stream_by_org(ORG_A)))
        types = [e.event_type for e in events]
        assert AuditEventType.CONTAINMENT_ACTION_ATTEMPTED in types
        assert AuditEventType.CONTAINMENT_ACTION_EXECUTED in types


async def _collect(async_iter: AsyncIterator[AuditEvent]) -> list[AuditEvent]:
    return [item async for item in async_iter]
