"""Unit tests for the detection HTTP routes (roadmap M2/C6) via TestClient.

Mocks only the repository/audit-log layer (§B.5) -- exercises the real
DetectionTriageService and the real Detection domain FSM, not a
reimplementation of either.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.detection_triage import DetectionTriageService
from src.application.playbook import PlaybookAction, PlaybookActionRegistry
from src.application.playbook_execution import PlaybookExecutionService
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
