"""Unit tests for cases HTTP routes."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TypeVar

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.case_repository import InMemoryCaseRepository
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_audit_log_service,
    get_case_repository,
    get_evidence_repository,
    get_evidence_storage,
    get_opensearch_dashboards_url,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository


@pytest.fixture
def cases_client():
    case_repo = InMemoryCaseRepository()
    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    audit_svc = AuditLogService(audit_repo)

    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()

    def _admin_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="admin",
            roles=frozenset({Role.ORG_ADMIN}),
            correlation_id=str(uuid.uuid4()),
            acr="aal2",
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _admin_tenant
    app.dependency_overrides[get_case_repository] = lambda: case_repo
    app.dependency_overrides[get_audit_log_service] = lambda: audit_svc
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo

    return TestClient(app), case_repo, fixed_org, fixed_user, audit_repo


class TestCreateCase:
    def test_create_case_returns_201(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.post("/api/cases", json={"title": "Test Case"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Test Case"
        assert "id" in data

    def test_create_case_persists(self, cases_client):
        client, repo, org_id, _, _ = cases_client
        resp = client.post(
            "/api/cases", json={"title": "Saved Case", "reference_number": "REF-001"}
        )
        assert resp.status_code == 201
        case_id = uuid.UUID(resp.json()["id"])
        import asyncio

        stored = asyncio.run(repo.get_by_id(case_id, org_id))
        assert stored is not None
        assert stored.metadata.title == "Saved Case"
        assert stored.metadata.reference_number == "REF-001"

    def test_create_case_missing_title_returns_422(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.post("/api/cases", json={})
        assert resp.status_code == 422


class TestListCases:
    def test_empty_list(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.get("/api/cases")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_returns_created_cases(self, cases_client):
        client, _, _, _, _ = cases_client
        client.post("/api/cases", json={"title": "Case A"})
        client.post("/api/cases", json={"title": "Case B"})
        resp = client.get("/api/cases")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2


class TestGetCase:
    def test_get_existing_case(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "Specific"}).json()
        resp = client.get(f"/api/cases/{created['id']}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "Specific"

    def test_get_missing_case_returns_404(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.get(f"/api/cases/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestDeleteCase:
    def test_delete_archives_case(self, cases_client):
        client, repo, org_id, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "To Delete"}).json()
        case_id = created["id"]
        resp = client.delete(f"/api/cases/{case_id}")
        assert resp.status_code == 204

    def test_delete_missing_returns_404(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.delete(f"/api/cases/{uuid.uuid4()}")
        assert resp.status_code == 404


class TestRemoveCaseMember:
    def test_remove_member_persists(self, cases_client):
        client, repo, org_id, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "Membership Case"}).json()
        case_id = created["id"]
        member_id = str(uuid.uuid4())
        client.post(f"/api/cases/{case_id}/members", json={"userId": member_id})

        resp = client.delete(f"/api/cases/{case_id}/members/{member_id}")
        assert resp.status_code == 200

        stored = asyncio.run(repo.get_by_id(uuid.UUID(case_id), org_id))
        assert uuid.UUID(member_id) not in stored.member_user_ids

    def test_remove_missing_case_returns_404(self, cases_client):
        client, _, _, _, _ = cases_client
        resp = client.delete(f"/api/cases/{uuid.uuid4()}/members/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_remove_non_member_is_idempotent_success(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "No-Op Removal Case"}).json()
        case_id = created["id"]
        resp = client.delete(f"/api/cases/{case_id}/members/{uuid.uuid4()}")
        assert resp.status_code == 200


class TestListCaseEvidence:
    def test_empty_evidence_list(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "E-Case"}).json()
        resp = client.get(f"/api/cases/{created['id']}/evidence")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0


class TestDashboardUrl:
    def test_returns_503_when_not_configured(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "Timeline Case"}).json()
        # Settings() won't have opensearch_dashboards_url in test env
        resp = client.get(f"/api/cases/{created['id']}/dashboard-url")
        # Either 503 (not configured) or 422 (missing required env vars)
        assert resp.status_code in (422, 503)

    def test_returns_absolute_url_rooted_at_configured_origin(self, cases_client):
        # dashboards_url is browser-facing (see src/config.py) — the response
        # must load Dashboards from its own origin directly, not proxy it
        # under a subpath (Dashboards' absolute asset URLs like /ui/* and
        # /bootstrap.js only resolve when served from its own root).
        client, _, _, _, _ = cases_client
        client.app.dependency_overrides[get_opensearch_dashboards_url] = (
            lambda: "http://localhost:5601"
        )
        created = client.post("/api/cases", json={"title": "Timeline Case"}).json()
        resp = client.get(f"/api/cases/{created['id']}/dashboard-url")
        assert resp.status_code == 200
        url = resp.json()["url"]
        assert url.startswith("http://localhost:5601/app/data-explorer/discover?")


class TestListCaseAuditEvents:
    def test_nonexistent_case_returns_404(self, cases_client):
        # Regression guard for AUTH-004: the route now loads the case first
        # (to check case-lead ownership), so an unknown case_id 404s instead
        # of silently returning an empty audit page.
        client, _, _, _, _ = cases_client
        resp = client.get(f"/api/cases/{uuid.uuid4()}/audit")
        assert resp.status_code == 404

    def test_returns_events_for_case(self, cases_client):
        client, _, org_id, _, audit_repo = cases_client
        created = client.post("/api/cases", json={"title": "Audit Case"}).json()
        case_id = uuid.UUID(created["id"])
        import asyncio

        async def _add():
            svc = AuditLogService(audit_repo)
            await svc.log(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                org_id=org_id,
                case_id=case_id,
                details={"filename": "test.evtx"},
            )

        asyncio.run(_add())
        resp = client.get(f"/api/cases/{case_id}/audit")
        assert resp.status_code == 200
        data = resp.json()
        # create_case logs CASE_CREATED, plus the EVIDENCE_UPLOAD_FINALIZED added above.
        assert data["total"] == 2
        event_types = {item["eventType"] for item in data["items"]}
        assert AuditEventType.EVIDENCE_UPLOAD_FINALIZED.value in event_types
        assert AuditEventType.CASE_CREATED.value in event_types

    def test_pagination(self, cases_client):
        client, _, org_id, _, audit_repo = cases_client
        created = client.post("/api/cases", json={"title": "Audit Case"}).json()
        case_id = uuid.UUID(created["id"])
        import asyncio

        async def _add_many():
            svc = AuditLogService(audit_repo)
            for _ in range(5):
                await svc.log(
                    AuditEventType.SYSTEM_ERROR,
                    org_id=org_id,
                    case_id=case_id,
                    details={},
                )

        asyncio.run(_add_many())
        resp = client.get(f"/api/cases/{case_id}/audit?page=1&pageSize=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 3
        # create_case logs CASE_CREATED, plus the 5 SYSTEM_ERROR events added above.
        assert data["total"] == 6


def _tenant(
    org_id: uuid.UUID, user_id: uuid.UUID, roles: frozenset[Role], acr: str = "aal2"
) -> TenantContext:
    return TenantContext(
        org_id=org_id,
        org_alias="testorg",
        user_id=user_id,
        username="user",
        roles=roles,
        correlation_id=str(uuid.uuid4()),
        acr=acr,
    )


class TestCaseAccessScoping:
    """AUTH-007: case-lead/analyst/read-only access is scoped to case ownership/membership."""

    def test_analyst_not_a_case_member_gets_403_on_get_case(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        created = client.post("/api/cases", json={"title": "Scoped Case"}).json()

        outsider_id = uuid.uuid4()
        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, outsider_id, frozenset({Role.ANALYST})
        )
        resp = client.get(f"/api/cases/{created['id']}")
        assert resp.status_code == 403

    def test_analyst_who_is_a_member_can_get_case(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        created = client.post("/api/cases", json={"title": "Member Case"}).json()
        case_id = created["id"]

        member_id = uuid.uuid4()
        # Admin (still the active tenant override) assigns the analyst as a member.
        resp = client.post(f"/api/cases/{case_id}/members", json={"userId": str(member_id)})
        assert resp.status_code == 200

        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, member_id, frozenset({Role.ANALYST})
        )
        resp = client.get(f"/api/cases/{case_id}")
        assert resp.status_code == 200

    def test_case_lead_who_does_not_own_case_cannot_delete(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        created = client.post("/api/cases", json={"title": "Admin-owned"}).json()

        other_lead_id = uuid.uuid4()
        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, other_lead_id, frozenset({Role.CASE_LEAD})
        )
        resp = client.delete(f"/api/cases/{created['id']}")
        assert resp.status_code == 403

    def test_case_lead_who_owns_case_can_delete(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        lead_id = uuid.uuid4()
        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, lead_id, frozenset({Role.CASE_LEAD})
        )
        created = client.post("/api/cases", json={"title": "Lead-owned"}).json()
        resp = client.delete(f"/api/cases/{created['id']}")
        assert resp.status_code == 204

    def test_add_member_by_non_owning_case_lead_returns_403(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        created = client.post("/api/cases", json={"title": "Admin-owned 2"}).json()

        other_lead_id = uuid.uuid4()
        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, other_lead_id, frozenset({Role.CASE_LEAD})
        )
        resp = client.post(
            f"/api/cases/{created['id']}/members", json={"userId": str(uuid.uuid4())}
        )
        assert resp.status_code == 403

    def test_analyst_cannot_view_case_audit_log(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        created = client.post("/api/cases", json={"title": "Audit-scoped"}).json()

        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, uuid.uuid4(), frozenset({Role.ANALYST})
        )
        resp = client.get(f"/api/cases/{created['id']}/audit")
        assert resp.status_code == 403

    def test_read_only_cannot_view_case_audit_log(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        created = client.post("/api/cases", json={"title": "Audit-scoped 2"}).json()

        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, uuid.uuid4(), frozenset({Role.READ_ONLY})
        )
        resp = client.get(f"/api/cases/{created['id']}/audit")
        assert resp.status_code == 403

    def test_case_lead_who_does_not_own_case_cannot_view_audit_log(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        created = client.post("/api/cases", json={"title": "Audit-scoped 3"}).json()

        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, uuid.uuid4(), frozenset({Role.CASE_LEAD})
        )
        resp = client.get(f"/api/cases/{created['id']}/audit")
        assert resp.status_code == 403

    def test_case_lead_who_owns_case_can_view_audit_log(self, cases_client):
        client, _, org_id, admin_id, _ = cases_client
        lead_id = uuid.uuid4()
        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, lead_id, frozenset({Role.CASE_LEAD})
        )
        created = client.post("/api/cases", json={"title": "Own audit log"}).json()
        resp = client.get(f"/api/cases/{created['id']}/audit")
        assert resp.status_code == 200


@pytest.fixture
def download_client(tmp_path):
    """Like ``cases_client``, but also wires a real ``LocalEvidenceStorage``
    and exposes ``evidence_repo``/``storage`` directly, for the evidence
    download route tests below (Gap Audit X1) -- a separate fixture rather
    than changing ``cases_client``'s own return-tuple shape, which 24
    existing tests already unpack positionally."""
    case_repo = InMemoryCaseRepository()
    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    audit_svc = AuditLogService(audit_repo)

    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()

    def _admin_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="admin",
            roles=frozenset({Role.ORG_ADMIN}),
            correlation_id=str(uuid.uuid4()),
            acr="aal2",
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _admin_tenant
    app.dependency_overrides[get_case_repository] = lambda: case_repo
    app.dependency_overrides[get_audit_log_service] = lambda: audit_svc
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo
    app.dependency_overrides[get_evidence_storage] = lambda: storage

    return TestClient(app), case_repo, evidence_repo, storage, fixed_org, fixed_user, audit_repo


async def _seed_promoted_evidence(
    storage: LocalEvidenceStorage,
    evidence_repo: InMemoryEvidenceRepository,
    *,
    org_id: uuid.UUID,
    case_id: uuid.UUID,
    content: bytes = b"real evtx bytes for download test",
    filename: str = "security.evtx",
) -> Evidence:
    """Real promotion flow through LocalEvidenceStorage's own public API
    (write to quarantine, promote to the evidence bucket) -- mirrors how a
    real upload actually lands an object, not a shortcut that pokes the
    storage double's private dict directly."""
    meta = EvidenceMetadata(
        original_filename=filename,
        content_type="application/octet-stream",
        size_bytes=len(content),
        uploader_user_id=uuid.uuid4(),
        case_id=case_id,
        org_id=org_id,
        org_alias="testorg",
    )
    evidence = Evidence(metadata=meta, state=EvidenceState.RECEIVED)
    presigned = await storage.request_presigned_upload(evidence)
    path = Path(presigned.url.removeprefix("file://"))
    path.write_bytes(content)
    evidence_key = await storage.promote_to_evidence_bucket(presigned.object_key, evidence)
    evidence = evidence.with_keys(quarantine_key=None, evidence_key=evidence_key)
    return await evidence_repo.save(evidence)


_T = TypeVar("_T")


async def _collect(items: AsyncIterator[_T]) -> list[_T]:
    return [item async for item in items]


class TestDownloadEvidence:
    def test_download_returns_real_bytes_and_headers(self, download_client):
        client, case_repo, evidence_repo, storage, org_id, _user_id, _audit_repo = download_client
        created = client.post("/api/cases", json={"title": "Download Case"}).json()
        case_id = uuid.UUID(created["id"])
        content = b"real evtx bytes for download test"
        evidence = asyncio.run(
            _seed_promoted_evidence(
                storage, evidence_repo, org_id=org_id, case_id=case_id, content=content
            )
        )

        resp = client.get(f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/download")

        assert resp.status_code == 200
        assert resp.content == content
        assert resp.headers["content-type"] == "application/octet-stream"
        assert 'filename="security.evtx"' in resp.headers["content-disposition"]

    def test_download_writes_real_audit_event(self, download_client):
        client, case_repo, evidence_repo, storage, org_id, user_id, audit_repo = download_client
        created = client.post("/api/cases", json={"title": "Audited Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence(storage, evidence_repo, org_id=org_id, case_id=case_id)
        )

        resp = client.get(f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/download")
        assert resp.status_code == 200

        events = asyncio.run(_collect(audit_repo.stream_by_org(org_id)))
        download_events = [e for e in events if e.event_type == AuditEventType.EVIDENCE_DOWNLOAD]
        assert len(download_events) == 1
        assert download_events[0].evidence_id == evidence.evidence_id
        assert download_events[0].case_id == case_id
        assert download_events[0].actor_user_id == user_id

    def test_evidence_not_yet_promoted_returns_404(self, download_client):
        client, case_repo, evidence_repo, storage, org_id, _user_id, _audit_repo = download_client
        created = client.post("/api/cases", json={"title": "Unpromoted Case"}).json()
        case_id = uuid.UUID(created["id"])
        meta = EvidenceMetadata(
            original_filename="not-ready.evtx",
            content_type="application/octet-stream",
            size_bytes=10,
            uploader_user_id=uuid.uuid4(),
            case_id=case_id,
            org_id=org_id,
            org_alias="testorg",
        )
        evidence = asyncio.run(
            evidence_repo.save(Evidence(metadata=meta, state=EvidenceState.SCANNING))
        )

        resp = client.get(f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/download")
        assert resp.status_code == 404

    def test_nonexistent_evidence_returns_404(self, download_client):
        client, case_repo, evidence_repo, storage, org_id, _user_id, _audit_repo = download_client
        created = client.post("/api/cases", json={"title": "No Evidence Case"}).json()
        case_id = uuid.UUID(created["id"])
        resp = client.get(f"/api/cases/{case_id}/evidence/{uuid.uuid4()}/download")
        assert resp.status_code == 404

    def test_nonexistent_case_returns_404(self, download_client):
        client, case_repo, evidence_repo, storage, org_id, _user_id, _audit_repo = download_client
        resp = client.get(f"/api/cases/{uuid.uuid4()}/evidence/{uuid.uuid4()}/download")
        assert resp.status_code == 404

    def test_filename_with_crlf_does_not_break_download(self, download_client):
        """Gap Audit Milestone DD: Evidence.metadata.original_filename is
        only length-bounded at intake (UploadRequestIn.filename), never
        content-restricted -- a DFIR platform must accept evidence from a
        compromised host with an adversarial/malformed filename. Before the
        fix, a filename containing a raw CRLF reached the
        Content-Disposition header unsanitized (only the double quote was
        escaped) and crashed the real ASGI server's own HTTP/1.1 header
        serializer (h11.LocalProtocolError: Illegal header value, confirmed
        live against a real running uvicorn server) -- a real 500 for every
        subsequent download attempt by anyone in the org, not just the
        uploader. This is not exploitable as header injection (h11 defends
        against that at the protocol level), but was a real, live
        availability bug triggerable by any authenticated user with
        ordinary upload permission."""
        client, case_repo, evidence_repo, storage, org_id, _user_id, _audit_repo = download_client
        created = client.post("/api/cases", json={"title": "Crafted Filename Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence(
                storage,
                evidence_repo,
                org_id=org_id,
                case_id=case_id,
                filename='evil\r\nSet-Cookie: x=1\r\n".evtx',
            )
        )

        resp = client.get(f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/download")

        assert resp.status_code == 200
        disposition = resp.headers["content-disposition"]
        assert "\r" not in disposition
        assert "\n" not in disposition
        assert disposition == 'attachment; filename="evilSet-Cookie: x=1.evtx"'
        assert "Set-Cookie" not in resp.headers

    def test_another_orgs_evidence_returns_404(self, download_client):
        """Tenant isolation: real evidence exists (a different org's), but
        the case lookup itself already scopes by tenant.org_id, so a
        cross-org case_id never resolves -- confirms the standing "404
        never 403, never leak cross-org existence" invariant this file's
        other routes already establish."""
        client, case_repo, evidence_repo, storage, org_id, _user_id, _audit_repo = download_client
        other_org = uuid.uuid4()
        other_case_id = uuid.uuid4()
        evidence = asyncio.run(
            _seed_promoted_evidence(storage, evidence_repo, org_id=other_org, case_id=other_case_id)
        )
        # Real case exists, but for a DIFFERENT org than the caller's tenant.
        resp = client.get(f"/api/cases/{other_case_id}/evidence/{evidence.evidence_id}/download")
        assert resp.status_code == 404
