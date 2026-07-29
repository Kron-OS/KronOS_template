"""Unit tests for the evidence HTTP routes via TestClient."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.case_repository import InMemoryCaseRepository
from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.scanning import NoOpScanner
from src.application.validation import default_validator_chain
from src.domain.case import Case, CaseMetadata
from src.domain.evidence import EvidenceState
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_case_repository,
    get_evidence_repository,
    get_intake_service,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository

_JSON_CONTENT = b'{"Records": []}'
_EVTX_HEADER = b"ElfFile\x00" + b"\x00" * 512


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def app_client(tmp_path: Path):  # type: ignore[no-untyped-def]
    from src.adapter.storage.local import LocalEvidenceStorage

    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    audit_svc = AuditLogService(audit_repo)
    case_repo = InMemoryCaseRepository()

    intake = EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=storage,
        audit_log=audit_svc,
        validator=default_validator_chain(10_000_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=10_000_000,
    )

    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()
    fixed_case_id = uuid.uuid4()

    # Pre-populate a case so request_upload ownership check passes.
    case = Case(
        case_id=fixed_case_id,
        org_id=fixed_org,
        org_alias="testorg",
        owner_user_id=fixed_user,
        metadata=CaseMetadata(title="Test Case"),
    )
    asyncio.run(case_repo.save(case))

    def _fixed_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="testuser",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

    app = create_app()
    app.dependency_overrides[get_intake_service] = lambda: intake
    app.dependency_overrides[get_tenant_context] = _fixed_tenant
    app.dependency_overrides[get_case_repository] = lambda: case_repo
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo

    return TestClient(app), storage, audit_repo, fixed_org, fixed_case_id


class TestRequestUploadRoute:
    def test_returns_201_with_presigned_url(self, app_client) -> None:
        client, _, _, _, case_id = app_client
        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "test.json",
                "contentType": "application/json",
                "sizeBytes": 100,
                "caseId": str(case_id),
            },
        )
        assert resp.status_code == 201
        body = resp.json()
        assert "evidenceId" in body
        assert "presignedUrl" in body

    def test_invalid_payload_returns_422(self, app_client) -> None:
        client, *_ = app_client
        resp = client.post("/api/evidence/upload/request", json={"filename": ""})
        assert resp.status_code == 422

    def test_unknown_case_returns_404(self, app_client) -> None:
        client, *_ = app_client
        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "test.json",
                "contentType": "application/json",
                "sizeBytes": 100,
                "caseId": str(uuid.uuid4()),  # not in case_repo
            },
        )
        assert resp.status_code == 404

    def test_read_only_forbidden(self, app_client) -> None:
        """AUTH-005: the §1 matrix excludes read-only from uploading evidence."""
        client, _, _, org_id, case_id = app_client
        _override_tenant_role(client, org_id, {Role.READ_ONLY})
        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "test.json",
                "contentType": "application/json",
                "sizeBytes": 100,
                "caseId": str(case_id),
            },
        )
        assert resp.status_code == 403


class TestFinalizeUploadRoute:
    def test_happy_path_returns_received(self, app_client) -> None:
        client, storage, _, _, case_id = app_client
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        assert req_resp.status_code == 201
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]

        storage.write_quarantine(object_key, _JSON_CONTENT)

        fin_resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": _sha256(_JSON_CONTENT)},
        )
        # 202: finalize is now a hand-off to kronos.process_intake, not a
        # synchronous completion (see cases.py/evidence.py's finalize_upload
        # docstring) -- this test's fixture has no task_queue configured, so
        # it still falls back to running intake inline and the returned
        # body already reflects the real end state.
        assert fin_resp.status_code == 202
        body = fin_resp.json()
        assert body["state"] == EvidenceState.RECEIVED.value
        assert body["sha256"] == _sha256(_JSON_CONTENT)

    def test_hash_mismatch_returns_422(self, app_client) -> None:
        client, storage, _, _, case_id = app_client
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]
        storage.write_quarantine(object_key, _JSON_CONTENT)

        fin_resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": "a" * 64},
        )
        assert fin_resp.status_code == 422

    def test_nonexistent_evidence_returns_422(self, app_client) -> None:
        client, *_ = app_client
        fin_resp = client.post(
            f"/api/evidence/upload/finalize/{uuid.uuid4()}",
            json={"client_sha256": "a" * 64},
        )
        assert fin_resp.status_code == 422

    def test_read_only_forbidden(self, app_client) -> None:
        """AUTH-005: finalize shares the upload role gate — read-only is excluded
        even for evidence someone else already started uploading."""
        client, storage, _, org_id, case_id = app_client
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]
        storage.write_quarantine(object_key, _JSON_CONTENT)

        _override_tenant_role(client, org_id, {Role.READ_ONLY})
        fin_resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": _sha256(_JSON_CONTENT)},
        )
        assert fin_resp.status_code == 403


class TestRetryParseRoute:
    """POST /evidence/{id}/retry-parse re-enters PARSING for a retryable
    parse-stage ERROR reason, reusing the already-promoted evidence-bucket
    object (no re-upload/re-scan needed)."""

    def _finalize_to_received(self, client, storage, case_id) -> str:  # type: ignore[no-untyped-def]
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]
        storage.write_quarantine(object_key, _JSON_CONTENT)
        client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": _sha256(_JSON_CONTENT)},
        )
        return evidence_id

    def _wire_real_orchestrator(self, client, storage, org_id, case_id):  # type: ignore[no-untyped-def]
        """Override the orchestrator dependency to use this test's local
        storage/evidence_repo instead of the production global singletons."""
        from src.application.parsing_orchestration import ParsingOrchestrationService
        from src.external.dependencies import (
            get_parser_registry,
            get_parsing_orchestration_service,
            get_task_queue,
        )

        evidence_repo = client.app.dependency_overrides[get_evidence_repository]()
        audit_repo = InMemoryAuditLogRepository()
        orchestrator = ParsingOrchestrationService(
            evidence_repository=evidence_repo,
            storage=storage,
            audit_log=AuditLogService(audit_repo),
            parser_registry=get_parser_registry(),
            task_queue=get_task_queue(),
        )
        client.app.dependency_overrides[get_parsing_orchestration_service] = (
            lambda: orchestrator
        )
        return evidence_repo

    def _force_error(self, evidence_repo, evidence_id: str, org_id, reason: str) -> None:  # type: ignore[no-untyped-def]
        ev = asyncio.run(evidence_repo.get_by_id(uuid.UUID(evidence_id), org_id))
        assert ev is not None
        ev2 = ev.with_state(EvidenceState.PARSING).with_error(reason)
        asyncio.run(evidence_repo.update(ev2))

    def test_retryable_parse_reason_reenters_parsing(self, app_client) -> None:
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_to_received(client, storage, case_id)
        evidence_repo = self._wire_real_orchestrator(client, storage, org_id, case_id)
        self._force_error(evidence_repo, evidence_id, org_id, "ingest_failed")

        resp = client.post(f"/api/evidence/{evidence_id}/retry-parse")
        assert resp.status_code == 202
        body = resp.json()
        assert body["state"] == EvidenceState.PARSING.value
        assert body["errorReason"] is None

    def test_terminal_reason_refused(self, app_client) -> None:
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_to_received(client, storage, case_id)
        evidence_repo = self._wire_real_orchestrator(client, storage, org_id, case_id)
        self._force_error(evidence_repo, evidence_id, org_id, "no_parser_found")

        resp = client.post(f"/api/evidence/{evidence_id}/retry-parse")
        assert resp.status_code == 422

    def test_intake_stage_reason_refused_with_hint(self, app_client) -> None:
        """A retryable but intake-stage reason must be refused here — the
        client should call retry-intake instead, not retry-parse."""
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_to_received(client, storage, case_id)
        evidence_repo = self._wire_real_orchestrator(client, storage, org_id, case_id)
        self._force_error(evidence_repo, evidence_id, org_id, "intake_failed:StorageError")

        resp = client.post(f"/api/evidence/{evidence_id}/retry-parse")
        assert resp.status_code == 422
        assert "retry-intake" in resp.json()["detail"]

    def test_wrong_state_returns_409(self, app_client) -> None:
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_to_received(client, storage, case_id)
        self._wire_real_orchestrator(client, storage, org_id, case_id)

        resp = client.post(f"/api/evidence/{evidence_id}/retry-parse")
        assert resp.status_code == 409

    def test_unknown_evidence_returns_404(self, app_client) -> None:
        client, storage, _, org_id, case_id = app_client
        self._wire_real_orchestrator(client, storage, org_id, case_id)

        resp = client.post(f"/api/evidence/{uuid.uuid4()}/retry-parse")
        assert resp.status_code == 404


def _override_tenant_role(
    client: TestClient,
    org_id: uuid.UUID,
    roles: set[Role],
    user_id: uuid.UUID | None = None,
) -> None:
    """Swap the fixed tenant's roles (and optionally user_id) for a single test.

    ``user_id`` lets AUTH-009 ownership tests impersonate the case owner (to
    prove a leading case-lead is allowed) or a different user (to prove a
    non-leading case-lead is forbidden) — the default random UUID is fine
    when only the role matters (EVID-2 role-only RBAC).
    """

    def _tenant() -> TenantContext:
        return TenantContext(
            org_id=org_id,
            org_alias="testorg",
            user_id=user_id if user_id is not None else uuid.uuid4(),
            username="admin",
            roles=frozenset(roles),
            correlation_id=str(uuid.uuid4()),
        )

    client.app.dependency_overrides[get_tenant_context] = _tenant  # type: ignore[attr-defined]


def _get_case_owner(client: TestClient, org_id: uuid.UUID, case_id: uuid.UUID) -> uuid.UUID:
    """Fetch a case's owner_user_id via the real route (AUTH-009 ownership tests)."""
    _override_tenant_role(client, org_id, {Role.ORG_ADMIN})
    resp = client.get(f"/api/cases/{case_id}")
    assert resp.status_code == 200
    return uuid.UUID(resp.json()["createdBy"])


class TestLegalHoldRoute:
    def _finalize_evidence(self, client, storage, case_id) -> str:  # type: ignore[no-untyped-def]
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]
        storage.write_quarantine(object_key, _JSON_CONTENT)
        client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": _sha256(_JSON_CONTENT)},
        )
        return evidence_id

    def test_org_admin_can_set_hold(self, app_client) -> None:
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_evidence(client, storage, case_id)
        _override_tenant_role(client, org_id, {Role.ORG_ADMIN})

        resp = client.put(f"/api/evidence/{evidence_id}/legal-hold", json={"hold": True})
        assert resp.status_code == 200
        assert resp.json()["legalHold"] is True

    def test_analyst_forbidden(self, app_client) -> None:
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_evidence(client, storage, case_id)
        _override_tenant_role(client, org_id, {Role.ANALYST})

        resp = client.put(f"/api/evidence/{evidence_id}/legal-hold", json={"hold": True})
        assert resp.status_code == 403

    def test_unknown_evidence_returns_404(self, app_client) -> None:
        client, _, _, org_id, _ = app_client
        _override_tenant_role(client, org_id, {Role.ORG_ADMIN})

        resp = client.put(f"/api/evidence/{uuid.uuid4()}/legal-hold", json={"hold": True})
        assert resp.status_code == 404

    def test_case_lead_owner_can_set_hold(self, app_client) -> None:
        """AUTH-009: a case-lead who actually leads this case may set legal hold."""
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_evidence(client, storage, case_id)
        owner_id = _get_case_owner(client, org_id, case_id)

        _override_tenant_role(client, org_id, {Role.CASE_LEAD}, user_id=owner_id)
        resp = client.put(f"/api/evidence/{evidence_id}/legal-hold", json={"hold": True})
        assert resp.status_code == 200
        assert resp.json()["legalHold"] is True

    def test_case_lead_non_owner_forbidden(self, app_client) -> None:
        """AUTH-009: a case-lead who does NOT lead this case is forbidden, not just
        any case-lead anywhere in the org — the matrix's "(of case)" qualifier."""
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_evidence(client, storage, case_id)

        _override_tenant_role(client, org_id, {Role.CASE_LEAD})  # random user_id != owner
        resp = client.put(f"/api/evidence/{evidence_id}/legal-hold", json={"hold": True})
        assert resp.status_code == 403


class TestDeleteEvidenceRetentionGate:
    """EVID-1: DELETE /evidence/{id} maps the retention gate to 409, end-to-end
    through a real step-up ticket (not just the service-layer unit tests)."""

    def _finalize_evidence(self, client, storage, case_id) -> str:  # type: ignore[no-untyped-def]
        req_resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "cloudtrail.json",
                "contentType": "application/json",
                "sizeBytes": len(_JSON_CONTENT),
                "caseId": str(case_id),
            },
        )
        evidence_id = req_resp.json()["evidenceId"]
        object_key = req_resp.json()["objectKey"]
        storage.write_quarantine(object_key, _JSON_CONTENT)
        client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": _sha256(_JSON_CONTENT)},
        )
        return evidence_id

    def test_active_retention_returns_409(self, app_client) -> None:
        from src.external.dependencies import get_step_up_auth
        from src.external.middleware.step_up_auth import StepUpAuth

        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_evidence(client, storage, case_id)

        user_id = uuid.uuid4()
        step_up = StepUpAuth()
        ticket_id = step_up.issue_ticket(user_id, "evidence.delete", evidence_id)

        def _admin_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="testorg",
                user_id=user_id,
                username="admin",
                roles=frozenset({Role.ORG_ADMIN}),
                correlation_id=str(uuid.uuid4()),
                acr="aal2",
            )

        client.app.dependency_overrides[get_tenant_context] = _admin_tenant  # type: ignore[attr-defined]
        client.app.dependency_overrides[get_step_up_auth] = lambda: step_up  # type: ignore[attr-defined]

        resp = client.request(
            "DELETE",
            f"/api/evidence/{evidence_id}",
            headers={"X-Step-Up-Ticket": str(ticket_id)},
        )
        assert resp.status_code == 409

    def test_case_lead_non_owner_forbidden(self, app_client) -> None:
        """AUTH-009: delete is granted to case-lead "of the case" — a case-lead
        who does not lead this case gets 403 before the retention/step-up gates
        are ever reached (ownership is checked first)."""
        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_evidence(client, storage, case_id)

        _override_tenant_role(client, org_id, {Role.CASE_LEAD}, user_id=uuid.uuid4())
        resp = client.request("DELETE", f"/api/evidence/{evidence_id}")
        assert resp.status_code == 403

    def test_case_lead_owner_reaches_retention_gate(self, app_client) -> None:
        """AUTH-009: a case-lead who DOES lead this case passes the ownership
        check and reaches the same retention gate an org-admin would (409, not
        403) — proving ownership, not just role, now gates the route."""
        from src.external.dependencies import get_step_up_auth
        from src.external.middleware.step_up_auth import StepUpAuth

        client, storage, _, org_id, case_id = app_client
        evidence_id = self._finalize_evidence(client, storage, case_id)
        owner_id = _get_case_owner(client, org_id, case_id)

        step_up = StepUpAuth()
        ticket_id = step_up.issue_ticket(owner_id, "evidence.delete", evidence_id)

        def _case_lead_owner_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="testorg",
                user_id=owner_id,
                username="lead",
                roles=frozenset({Role.CASE_LEAD}),
                correlation_id=str(uuid.uuid4()),
                acr="aal2",
            )

        client.app.dependency_overrides[get_tenant_context] = _case_lead_owner_tenant  # type: ignore[attr-defined]
        client.app.dependency_overrides[get_step_up_auth] = lambda: step_up  # type: ignore[attr-defined]

        resp = client.request(
            "DELETE",
            f"/api/evidence/{evidence_id}",
            headers={"X-Step-Up-Ticket": str(ticket_id)},
        )
        assert resp.status_code == 409
