"""Unit tests for cases HTTP routes."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

import pytest
from fastapi.testclient import TestClient

from src.adapter.keycloak.admin_client import (
    KeycloakAdminClient,
    KeycloakOrganization,
    KeycloakSession,
    OrgMember,
)
from src.adapter.queue.task_queue import InMemoryTaskQueue
from src.adapter.repository.artifact_repository import InMemoryArtifactRepository
from src.adapter.repository.case_repository import InMemoryCaseRepository
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.domain.artifact import StructuredArtifact
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState
from src.domain.timeline import KronosProvenance
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_artifact_repository,
    get_audit_log_service,
    get_case_repository,
    get_derived_artifact_storage,
    get_evidence_repository,
    get_evidence_storage,
    get_keycloak_admin_client,
    get_opensearch_dashboards_url,
    get_task_queue,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository


class FakeKeycloakAdminClient(KeycloakAdminClient):
    """Fake for Milestone QQQQ's ``is_org_member`` validation and Milestone
    ZZZZ's case-member search -- mocks the external Keycloak dependency
    (CLAUDE.md §B.5), not a domain object. Only ``is_org_member``/
    ``list_org_members`` are meaningfully implemented; the other abstract
    methods aren't reachable from any ``cases.py`` route."""

    def __init__(
        self,
        *,
        org_members: set[uuid.UUID],
        member_directory: tuple[OrgMember, ...] = (),
    ) -> None:
        self._org_members = org_members
        self._member_directory = member_directory

    async def list_user_sessions(self, user_id: uuid.UUID) -> tuple[KeycloakSession, ...]:
        raise NotImplementedError

    async def revoke_session(self, session_id: str) -> None:
        raise NotImplementedError

    async def is_org_member(self, org_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        return user_id in self._org_members

    async def get_organization_alias(self, org_id: uuid.UUID) -> str | None:
        raise NotImplementedError

    async def list_organizations(self) -> tuple[KeycloakOrganization, ...]:
        raise NotImplementedError

    async def list_org_members(self, org_id: uuid.UUID) -> tuple[OrgMember, ...]:
        return self._member_directory


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

    def test_get_case_includes_empty_member_list(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "No Members Yet"}).json()
        assert created["memberUserIds"] == []

    def test_get_case_includes_real_member_ids(self, cases_client):
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "Has Members"}).json()
        member_id = str(uuid.uuid4())
        client.post(f"/api/cases/{created['id']}/members", json={"userId": member_id})
        resp = client.get(f"/api/cases/{created['id']}")
        assert resp.json()["memberUserIds"] == [member_id]


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


class TestAddCaseMemberOrgValidation:
    """Milestone QQQQ: add_case_member now validates body.userId against
    the caller's own org via KeycloakAdminClient.is_org_member when one is
    configured. cases_client (above) leaves get_keycloak_admin_client at
    its default None, exercising the "honestly skipped" path already --
    these tests exercise the CONFIGURED path, both branches."""

    def _client_with_admin(self, *, org_members: set[uuid.UUID]):
        case_repo = InMemoryCaseRepository()
        audit_repo = InMemoryAuditLogRepository()
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
        app.dependency_overrides[get_keycloak_admin_client] = lambda: FakeKeycloakAdminClient(
            org_members=org_members
        )
        return TestClient(app), case_repo, fixed_org

    def test_rejects_userid_not_in_caller_org(self):
        client, _, _ = self._client_with_admin(org_members=set())
        created = client.post("/api/cases", json={"title": "Validated Case"}).json()
        resp = client.post(
            f"/api/cases/{created['id']}/members", json={"userId": str(uuid.uuid4())}
        )
        assert resp.status_code == 403
        assert "not a member of your organization" in resp.json()["detail"]

    def test_accepts_userid_confirmed_in_caller_org(self):
        real_member_id = uuid.uuid4()
        client, repo, org_id = self._client_with_admin(org_members={real_member_id})
        created = client.post("/api/cases", json={"title": "Validated Case 2"}).json()
        resp = client.post(
            f"/api/cases/{created['id']}/members", json={"userId": str(real_member_id)}
        )
        assert resp.status_code == 200
        stored = asyncio.run(repo.get_by_id(uuid.UUID(created["id"]), org_id))
        assert real_member_id in stored.member_user_ids


class TestListCaseMemberCandidates:
    """Gap Audit Milestone ZZZZ: GET /{case_id}/member-candidates, the
    new case-scoped user-search endpoint for add_case_member's own
    "how do I find a userId" gap (Tier 1 item 6 of
    docs/HANDOFF_AND_ORCHESTRATION.md)."""

    def _client_with_directory(self, *, directory: tuple[OrgMember, ...]):
        case_repo = InMemoryCaseRepository()
        audit_repo = InMemoryAuditLogRepository()
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
        app.dependency_overrides[get_keycloak_admin_client] = lambda: FakeKeycloakAdminClient(
            org_members=set(), member_directory=directory
        )
        return TestClient(app), fixed_org

    def test_matches_by_username_substring_case_insensitive(self):
        alice = OrgMember(
            user_id=uuid.uuid4(), username="alice-analyst", email="alice@example.invalid"
        )
        bob = OrgMember(user_id=uuid.uuid4(), username="bob-lead", email="bob@example.invalid")
        client, _ = self._client_with_directory(directory=(alice, bob))
        created = client.post("/api/cases", json={"title": "Search Case"}).json()

        resp = client.get(f"/api/cases/{created['id']}/member-candidates", params={"q": "ALICE"})
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert [i["username"] for i in items] == ["alice-analyst"]
        assert items[0]["userId"] == str(alice.user_id)

    def test_matches_by_email_substring(self):
        alice = OrgMember(
            user_id=uuid.uuid4(), username="alice-analyst", email="alice@example.invalid"
        )
        client, _ = self._client_with_directory(directory=(alice,))
        created = client.post("/api/cases", json={"title": "Search Case 2"}).json()

        resp = client.get(
            f"/api/cases/{created['id']}/member-candidates", params={"q": "example.invalid"}
        )
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 1

    def test_no_match_returns_empty_items_not_error(self):
        alice = OrgMember(
            user_id=uuid.uuid4(), username="alice-analyst", email="alice@example.invalid"
        )
        client, _ = self._client_with_directory(directory=(alice,))
        created = client.post("/api/cases", json={"title": "Search Case 3"}).json()

        resp = client.get(
            f"/api/cases/{created['id']}/member-candidates", params={"q": "nobody-like-this"}
        )
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_empty_query_is_rejected_422(self):
        client, _ = self._client_with_directory(directory=())
        created = client.post("/api/cases", json={"title": "Search Case 4"}).json()

        resp = client.get(f"/api/cases/{created['id']}/member-candidates", params={"q": ""})
        assert resp.status_code == 422

    def test_results_capped_at_20(self):
        directory = tuple(
            OrgMember(user_id=uuid.uuid4(), username=f"user-{i}", email=f"user-{i}@example.invalid")
            for i in range(30)
        )
        client, _ = self._client_with_directory(directory=directory)
        created = client.post("/api/cases", json={"title": "Search Case 5"}).json()

        resp = client.get(f"/api/cases/{created['id']}/member-candidates", params={"q": "user-"})
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 20

    def test_no_admin_client_configured_returns_empty_not_error(self, cases_client):
        # cases_client (the default fixture) leaves get_keycloak_admin_client
        # at its default None -- honestly-skipped, matching add_case_member's
        # own "None means not configured" contract, never a 500.
        client, _, _, _, _ = cases_client
        created = client.post("/api/cases", json={"title": "No Admin Client"}).json()

        resp = client.get(f"/api/cases/{created['id']}/member-candidates", params={"q": "anyone"})
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_case_lead_who_does_not_own_case_gets_403(self):
        alice = OrgMember(
            user_id=uuid.uuid4(), username="alice-analyst", email="alice@example.invalid"
        )
        client, org_id = self._client_with_directory(directory=(alice,))
        created = client.post("/api/cases", json={"title": "Admin-owned Search Case"}).json()

        other_lead_id = uuid.uuid4()
        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, other_lead_id, frozenset({Role.CASE_LEAD})
        )
        resp = client.get(f"/api/cases/{created['id']}/member-candidates", params={"q": "alice"})
        assert resp.status_code == 403

    def test_case_lead_who_owns_case_can_search(self):
        alice = OrgMember(
            user_id=uuid.uuid4(), username="alice-analyst", email="alice@example.invalid"
        )
        client, org_id = self._client_with_directory(directory=(alice,))

        lead_id = uuid.uuid4()
        client.app.dependency_overrides[get_tenant_context] = lambda: _tenant(
            org_id, lead_id, frozenset({Role.CASE_LEAD})
        )
        created = client.post("/api/cases", json={"title": "Lead-owned Search Case"}).json()

        resp = client.get(f"/api/cases/{created['id']}/member-candidates", params={"q": "alice"})
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 1

    def test_case_not_found_returns_404(self):
        client, _ = self._client_with_directory(directory=())
        resp = client.get(f"/api/cases/{uuid.uuid4()}/member-candidates", params={"q": "anyone"})
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


class TestListCaseArtifacts:
    """Gap Audit Milestone AAAAA: GET /{case_id}/artifacts, the new
    case-scoped StructuredArtifact listing backing the Artifacts view.

    Uses its own local fixture (not the shared ``cases_client``) because
    ``get_artifact_repository``'s DI default is a module-level singleton
    (``src/external/dependencies.py``'s ``_artifact_repository``) --
    reusing it unoverridden across tests would leak artifacts between
    them, unlike ``case_repo``/``evidence_repo``, which ``cases_client``
    already creates fresh and overrides per test.
    """

    def _client_with_artifacts(self):
        case_repo = InMemoryCaseRepository()
        artifact_repo = InMemoryArtifactRepository()
        audit_svc = AuditLogService(InMemoryAuditLogRepository())
        fixed_org = uuid.uuid4()
        fixed_user = uuid.uuid4()

        def _tenant_ctx() -> TenantContext:
            # ORG_ADMIN (not READ_ONLY): this fixture's own tests need to
            # both create the case (requires_role(ORG_ADMIN, CASE_LEAD))
            # and read it back -- assert_case_access's own READ_ONLY-can-read
            # behavior already has dedicated coverage elsewhere
            # (TestCaseAccessScoping), not this route's own focus.
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
        app.dependency_overrides[get_tenant_context] = _tenant_ctx
        app.dependency_overrides[get_case_repository] = lambda: case_repo
        app.dependency_overrides[get_artifact_repository] = lambda: artifact_repo
        app.dependency_overrides[get_audit_log_service] = lambda: audit_svc
        return TestClient(app), case_repo, artifact_repo, fixed_org, fixed_user

    def test_empty_artifact_list(self):
        client, _, _, _, _ = self._client_with_artifacts()
        created = client.post("/api/cases", json={"title": "Artifact Case"}).json()
        resp = client.get(f"/api/cases/{created['id']}/artifacts")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_unknown_case_returns_404(self):
        client, _, _, _, _ = self._client_with_artifacts()
        resp = client.get(f"/api/cases/{uuid.uuid4()}/artifacts")
        assert resp.status_code == 404

    def test_returns_real_artifacts_scoped_to_the_case(self):
        client, case_repo, artifact_repo, org_id, user_id = self._client_with_artifacts()
        created = client.post("/api/cases", json={"title": "Artifact Case 2"}).json()
        case_id = uuid.UUID(created["id"])
        other_case_id = uuid.uuid4()
        evidence_id = uuid.uuid4()

        matching = StructuredArtifact(
            kind="volatility.psscan",
            content={
                "plugin": "windows.psscan",
                "rows": [{"PID": 908, "ImageFileName": "svchost.exe"}],
            },
            kronos=KronosProvenance(
                evidence_id=evidence_id,
                case_id=case_id,
                org_id=org_id,
                org_alias="testorg",
                sha256="a" * 64,
                parser="volatility3",
                parser_version="2.28.0",
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )
        # artifact_id must be distinct too -- model_copy() does not
        # re-trigger the default_factory, so without this the second
        # save() below would silently overwrite the first in
        # InMemoryArtifactRepository's own artifact_id-keyed dict.
        other_case_artifact = matching.model_copy(
            update={
                "artifact_id": uuid.uuid4(),
                "kronos": matching.kronos.model_copy(update={"case_id": other_case_id}),
            }
        )
        asyncio.run(artifact_repo.save(matching))
        asyncio.run(artifact_repo.save(other_case_artifact))

        resp = client.get(f"/api/cases/{case_id}/artifacts")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["kind"] == "volatility.psscan"
        assert items[0]["content"]["rows"][0]["ImageFileName"] == "svchost.exe"
        assert items[0]["evidenceId"] == str(evidence_id)
        assert items[0]["caseId"] == str(case_id)
        assert items[0]["parser"] == "volatility3"


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
        client.app.dependency_overrides[get_opensearch_dashboards_url] = lambda: (
            "http://localhost:5601"
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


class _FakeDerivedArtifactStorage:
    """Stands in for S3DerivedArtifactStorage (CLAUDE.md SS B.5: mock the
    external dependency, not domain objects) -- an in-memory dict keyed by
    object_key, real enough to round-trip bytes for the download route
    tests below."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def seed(self, object_key: str, data: bytes) -> None:
        self._objects[object_key] = data

    async def put_object(
        self,
        org_alias: str,
        object_key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
    ) -> None:
        self._objects[object_key] = data

    async def stream_object(self, object_key: str, chunk_size: int = 65536):
        data = self._objects[object_key]

        async def _gen():
            yield data

        return _gen()

    def bucket_for(self, object_key: str) -> str:
        return "kronos-derived-testorg"


@pytest.fixture
def on_demand_client(tmp_path):
    """Like ``download_client``, but also wires a real ``InMemoryTaskQueue``
    (to assert on-demand extraction tasks are enqueued with the right args),
    a fake ``DerivedArtifactStorage``, and ``InMemoryArtifactRepository``
    (Milestone EEEEE: the on-demand dumpfiles/registry-key trigger routes
    and the derived-artifact download route)."""
    case_repo = InMemoryCaseRepository()
    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    artifact_repo = InMemoryArtifactRepository()
    storage = LocalEvidenceStorage(base_dir=tmp_path)
    derived_storage = _FakeDerivedArtifactStorage()
    task_queue = InMemoryTaskQueue()
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
    app.dependency_overrides[get_artifact_repository] = lambda: artifact_repo
    app.dependency_overrides[get_derived_artifact_storage] = lambda: derived_storage
    app.dependency_overrides[get_task_queue] = lambda: task_queue

    return (
        TestClient(app),
        case_repo,
        evidence_repo,
        artifact_repo,
        derived_storage,
        task_queue,
        fixed_org,
        fixed_user,
        audit_repo,
    )


class TestRequestVolatilityDumpFile:
    """POST .../volatility/dump-file (Milestone EEEEE) -- enqueues the
    real on-demand extraction task, never runs it synchronously (CLAUDE.md
    SS A.5/SS G.3)."""

    def test_enqueues_task_and_returns_202(self, on_demand_client):
        client, _, evidence_repo, *_rest, org_id, _user_id, _audit_repo = on_demand_client
        created = client.post("/api/cases", json={"title": "Dumpfiles Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )

        resp = client.post(
            f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/volatility/dump-file",
            json={"physaddr": 88029040},
        )

        assert resp.status_code == 202
        assert "taskId" in resp.json()

    def test_records_real_enqueued_task(self, on_demand_client):
        (
            client,
            _,
            evidence_repo,
            _artifact_repo,
            _derived,
            task_queue,
            org_id,
            _user_id,
            _audit_repo,
        ) = on_demand_client
        created = client.post("/api/cases", json={"title": "Dumpfiles Case 2"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )

        client.post(
            f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/volatility/dump-file",
            json={"physaddr": 88029040},
        )

        assert task_queue.enqueued[0][0] == "volatility_dump_file"
        assert task_queue.enqueued[0][1] == evidence.evidence_id

    def test_logs_extraction_requested_audit_event(self, on_demand_client):
        client, _, evidence_repo, *_rest, org_id, user_id, audit_repo = on_demand_client
        created = client.post("/api/cases", json={"title": "Dumpfiles Audit Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )

        client.post(
            f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/volatility/dump-file",
            json={"physaddr": 88029040},
        )

        events = asyncio.run(_collect(audit_repo.stream_by_org(org_id)))
        requested = [
            e
            for e in events
            if e.event_type == AuditEventType.DERIVED_ARTIFACT_EXTRACTION_REQUESTED
        ]
        assert len(requested) == 1
        assert requested[0].details["physaddr"] == 88029040

    def test_unpromoted_evidence_returns_409(self, on_demand_client):
        client, _, evidence_repo, *_rest, org_id, _user_id, _audit_repo = on_demand_client
        created = client.post("/api/cases", json={"title": "Not Ready"}).json()
        case_id = uuid.UUID(created["id"])
        meta = EvidenceMetadata(
            original_filename="not-ready.raw",
            content_type="application/octet-stream",
            size_bytes=10,
            uploader_user_id=uuid.uuid4(),
            case_id=case_id,
            org_id=org_id,
            org_alias="testorg",
        )
        evidence = asyncio.run(
            evidence_repo.save(Evidence(metadata=meta, state=EvidenceState.PARSING))
        )

        resp = client.post(
            f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/volatility/dump-file",
            json={"physaddr": 1234},
        )
        assert resp.status_code == 409

    def test_nonexistent_evidence_returns_404(self, on_demand_client):
        client, *_rest = on_demand_client
        created = client.post("/api/cases", json={"title": "No Evidence"}).json()
        case_id = uuid.UUID(created["id"])
        resp = client.post(
            f"/api/cases/{case_id}/evidence/{uuid.uuid4()}/volatility/dump-file",
            json={"physaddr": 1234},
        )
        assert resp.status_code == 404


class TestRequestVolatilityRegistryKey:
    """POST .../volatility/registry-key (Milestone EEEEE)."""

    def test_enqueues_task_and_returns_202(self, on_demand_client):
        client, _, evidence_repo, *_rest, org_id, _user_id, _audit_repo = on_demand_client
        created = client.post("/api/cases", json={"title": "Registry Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )

        resp = client.post(
            f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/volatility/registry-key",
            json={"hiveOffset": 273366078603280, "key": "ControlSet001"},
        )

        assert resp.status_code == 202
        assert "taskId" in resp.json()

    def test_key_is_optional(self, on_demand_client):
        client, _, evidence_repo, *_rest, org_id, _user_id, _audit_repo = on_demand_client
        created = client.post("/api/cases", json={"title": "Registry Root Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )

        resp = client.post(
            f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/volatility/registry-key",
            json={"hiveOffset": 273366078603280},
        )
        assert resp.status_code == 202

    def test_records_real_enqueued_task(self, on_demand_client):
        (
            client,
            _,
            evidence_repo,
            _artifact_repo,
            _derived,
            task_queue,
            org_id,
            _user_id,
            _audit_repo,
        ) = on_demand_client
        created = client.post("/api/cases", json={"title": "Registry Case 2"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )

        client.post(
            f"/api/cases/{case_id}/evidence/{evidence.evidence_id}/volatility/registry-key",
            json={"hiveOffset": 273366078603280},
        )

        assert task_queue.enqueued[0][0] == "volatility_registry_key"


class TestDownloadDerivedArtifact:
    """GET /{case_id}/artifacts/{artifact_id}/download (Milestone EEEEE) --
    gated/shaped identically to TestDownloadEvidence above."""

    def test_download_returns_real_bytes(self, on_demand_client):
        (
            client,
            case_repo,
            evidence_repo,
            artifact_repo,
            derived_storage,
            _tq,
            org_id,
            _user_id,
            _audit_repo,
        ) = on_demand_client
        created = client.post("/api/cases", json={"title": "Derived Download Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )
        object_key = f"testorg/{case_id}/{evidence.evidence_id}/artifact/example.dat"
        derived_storage.seed(object_key, b"real extracted file bytes")
        artifact = asyncio.run(
            artifact_repo.save(
                StructuredArtifact(
                    kind="volatility.dumpfiles",
                    content={
                        "plugin": "windows.dumpfiles.DumpFiles",
                        "filename": "example.dat",
                        "object_key": object_key,
                        "sha256": "abc",
                        "size_bytes": 26,
                        "enrichment": {},
                    },
                    kronos=KronosProvenance(
                        evidence_id=evidence.evidence_id,
                        case_id=case_id,
                        org_id=org_id,
                        sha256="abc",
                        parser="volatility3",
                        parser_version="2.28.0",
                        record_index=0,
                        ingest_timestamp=datetime.now(UTC),
                    ),
                )
            )
        )

        resp = client.get(f"/api/cases/{case_id}/artifacts/{artifact.artifact_id}/download")

        assert resp.status_code == 200
        assert resp.content == b"real extracted file bytes"
        assert 'filename="example.dat"' in resp.headers["content-disposition"]

    def test_logs_real_audit_event(self, on_demand_client):
        (
            client,
            case_repo,
            evidence_repo,
            artifact_repo,
            derived_storage,
            _tq,
            org_id,
            user_id,
            audit_repo,
        ) = on_demand_client
        created = client.post("/api/cases", json={"title": "Derived Audit Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )
        object_key = f"testorg/{case_id}/{evidence.evidence_id}/artifact/example.dat"
        derived_storage.seed(object_key, b"bytes")
        artifact = asyncio.run(
            artifact_repo.save(
                StructuredArtifact(
                    kind="volatility.dumpfiles",
                    content={"filename": "example.dat", "object_key": object_key},
                    kronos=KronosProvenance(
                        evidence_id=evidence.evidence_id,
                        case_id=case_id,
                        org_id=org_id,
                        sha256="abc",
                        parser="volatility3",
                        parser_version="2.28.0",
                        record_index=0,
                        ingest_timestamp=datetime.now(UTC),
                    ),
                )
            )
        )

        resp = client.get(f"/api/cases/{case_id}/artifacts/{artifact.artifact_id}/download")
        assert resp.status_code == 200

        events = asyncio.run(_collect(audit_repo.stream_by_org(org_id)))
        downloaded = [
            e for e in events if e.event_type == AuditEventType.DERIVED_ARTIFACT_DOWNLOADED
        ]
        assert len(downloaded) == 1
        assert downloaded[0].actor_user_id == user_id

    def test_artifact_without_object_key_returns_404(self, on_demand_client):
        (
            client,
            case_repo,
            evidence_repo,
            artifact_repo,
            _derived,
            _tq,
            org_id,
            _user_id,
            _audit_repo,
        ) = on_demand_client
        created = client.post("/api/cases", json={"title": "No Bytes Case"}).json()
        case_id = uuid.UUID(created["id"])
        evidence = asyncio.run(
            _seed_promoted_evidence_for_org(evidence_repo, org_id=org_id, case_id=case_id)
        )
        artifact = asyncio.run(
            artifact_repo.save(
                StructuredArtifact(
                    kind="volatility.registry.printkey",
                    content={"plugin": "windows.registry.printkey.PrintKey", "rows": []},
                    kronos=KronosProvenance(
                        evidence_id=evidence.evidence_id,
                        case_id=case_id,
                        org_id=org_id,
                        sha256="abc",
                        parser="volatility3",
                        parser_version="2.28.0",
                        record_index=0,
                        ingest_timestamp=datetime.now(UTC),
                    ),
                )
            )
        )

        resp = client.get(f"/api/cases/{case_id}/artifacts/{artifact.artifact_id}/download")
        assert resp.status_code == 404

    def test_nonexistent_artifact_returns_404(self, on_demand_client):
        client, *_rest = on_demand_client
        created = client.post("/api/cases", json={"title": "No Artifact Case"}).json()
        case_id = uuid.UUID(created["id"])
        resp = client.get(f"/api/cases/{case_id}/artifacts/{uuid.uuid4()}/download")
        assert resp.status_code == 404


async def _seed_promoted_evidence_for_org(
    evidence_repo: InMemoryEvidenceRepository,
    *,
    org_id: uuid.UUID,
    case_id: uuid.UUID,
    filename: str = "memory.raw",
) -> Evidence:
    """Lighter-weight than ``_seed_promoted_evidence`` -- the on-demand
    routes only need a real, promoted minio_evidence_key on the Evidence
    row itself (the launcher/storage calls are mocked at the service layer
    in the Celery task, never reached by these route-level tests), not a
    real byte round-trip through LocalEvidenceStorage."""
    meta = EvidenceMetadata(
        original_filename=filename,
        content_type="application/octet-stream",
        size_bytes=1024,
        uploader_user_id=uuid.uuid4(),
        case_id=case_id,
        org_id=org_id,
        org_alias="testorg",
    )
    evidence = Evidence(metadata=meta, state=EvidenceState.COMPLETE).with_keys(
        quarantine_key=None, evidence_key=f"testorg/{case_id}/evidence/{filename}"
    )
    return await evidence_repo.save(evidence)
