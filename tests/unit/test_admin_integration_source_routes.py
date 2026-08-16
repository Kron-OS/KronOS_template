"""Unit tests for /api/admin/integration-sources routes (Milestone W8, Gap
Audit P1-7) via TestClient.

Mirrors test_admin_quota_routes.py's own fixture shape (TestClient +
app.dependency_overrides) and test_routes_evidence.py's step-up ticket
pattern (issue a real StepUpAuth ticket, pass it via X-Step-Up-Ticket).
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.integration_source_key import (
    InMemoryIntegrationSourceKeyRepository,
)
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_audit_log_service,
    get_integration_source_key_repository,
    get_step_up_auth,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from src.external.middleware.step_up_auth import StepUpAuth
from tests.conftest import InMemoryAuditLogRepository


@pytest.fixture
def routes_client():  # type: ignore[no-untyped-def]
    audit_repo = InMemoryAuditLogRepository()
    key_repo = InMemoryIntegrationSourceKeyRepository()
    step_up = StepUpAuth()
    fixed_org = uuid.uuid4()
    user_id = uuid.uuid4()

    def _admin_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=user_id,
            username="admin",
            roles=frozenset({Role.ORG_ADMIN}),
            correlation_id=str(uuid.uuid4()),
            acr="aal2",
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _admin_tenant
    app.dependency_overrides[get_integration_source_key_repository] = lambda: key_repo
    app.dependency_overrides[get_audit_log_service] = lambda: AuditLogService(audit_repo)
    app.dependency_overrides[get_step_up_auth] = lambda: step_up

    return TestClient(app), key_repo, audit_repo, step_up, fixed_org, user_id


def _provision_ticket(step_up: StepUpAuth, user_id: uuid.UUID, source_type: str, source_id: str):  # type: ignore[no-untyped-def]
    return step_up.issue_ticket(
        user_id=user_id,
        operation="integration_source_key.provision",
        resource_id=f"{source_type}:{source_id}",
    )


def _revoke_ticket(step_up: StepUpAuth, user_id: uuid.UUID, source_type: str, source_id: str):  # type: ignore[no-untyped-def]
    return step_up.issue_ticket(
        user_id=user_id,
        operation="integration_source_key.revoke",
        resource_id=f"{source_type}:{source_id}",
    )


class TestProvisionRoute:
    def test_provision_requires_org_admin(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, _step_up, org_id, user_id = routes_client
        app = client.app

        def _analyst_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="testorg",
                user_id=user_id,
                username="analyst",
                roles=frozenset({Role.ANALYST}),
                correlation_id=str(uuid.uuid4()),
                acr="aal2",
            )

        app.dependency_overrides[get_tenant_context] = _analyst_tenant
        resp = client.post(
            "/api/admin/integration-sources/wazuh/provision", json={"sourceId": "s1"}
        )
        assert resp.status_code == 403

    def test_provision_without_step_up_ticket_is_401(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, *_rest = routes_client
        resp = client.post(
            "/api/admin/integration-sources/wazuh/provision", json={"sourceId": "s1"}
        )
        assert resp.status_code == 401

    def test_provision_without_aal2_is_401(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, _step_up, org_id, user_id = routes_client
        app = client.app

        def _aal1_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="testorg",
                user_id=user_id,
                username="admin",
                roles=frozenset({Role.ORG_ADMIN}),
                correlation_id=str(uuid.uuid4()),
                acr="aal1",
            )

        app.dependency_overrides[get_tenant_context] = _aal1_tenant
        resp = client.post(
            "/api/admin/integration-sources/wazuh/provision", json={"sourceId": "s1"}
        )
        assert resp.status_code == 401

    def test_provision_returns_plaintext_key_and_audits(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, audit_repo, step_up, org_id, user_id = routes_client
        ticket = _provision_ticket(step_up, user_id, "wazuh", "s1")

        resp = client.post(
            "/api/admin/integration-sources/wazuh/provision",
            json={"sourceId": "s1"},
            headers={"X-Step-Up-Ticket": str(ticket)},
        )

        assert resp.status_code == 201
        body = resp.json()
        assert body["sourceId"] == "s1"
        assert body["sourceType"] == "wazuh"
        assert body["apiKey"]  # real plaintext key present in the response
        assert body["createdAt"]

        # The repository really has it -- and the returned key really
        # resolves via get_by_key.
        import asyncio

        resolved = asyncio.run(key_repo.get_by_key(body["apiKey"]))
        assert resolved is not None
        assert resolved.org_id == org_id

        events = [
            e
            for e in audit_repo.events
            if e.event_type == AuditEventType.INTEGRATION_SOURCE_KEY_PROVISIONED
        ]
        assert len(events) == 1
        assert events[0].org_id == org_id
        # The plaintext key must never appear in the audit details.
        assert body["apiKey"] not in str(events[0].details)

    def test_provision_ticket_is_single_use(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, step_up, _org_id, user_id = routes_client
        ticket = _provision_ticket(step_up, user_id, "wazuh", "s1")

        first = client.post(
            "/api/admin/integration-sources/wazuh/provision",
            json={"sourceId": "s1"},
            headers={"X-Step-Up-Ticket": str(ticket)},
        )
        assert first.status_code == 201

        second = client.post(
            "/api/admin/integration-sources/wazuh/provision",
            json={"sourceId": "s1"},
            headers={"X-Step-Up-Ticket": str(ticket)},
        )
        assert second.status_code == 401


class TestListRoute:
    def test_list_requires_org_admin(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, _step_up, org_id, user_id = routes_client
        app = client.app

        def _analyst_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="testorg",
                user_id=user_id,
                username="analyst",
                roles=frozenset({Role.ANALYST}),
                correlation_id=str(uuid.uuid4()),
                acr="aal2",
            )

        app.dependency_overrides[get_tenant_context] = _analyst_tenant
        resp = client.get("/api/admin/integration-sources")
        assert resp.status_code == 403

    def test_list_excludes_plaintext_key(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, _audit_repo, _step_up, org_id, _user_id = routes_client
        import asyncio

        asyncio.run(key_repo.provision(org_id, "s1", "wazuh"))

        resp = client.get("/api/admin/integration-sources")

        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["sourceId"] == "s1"
        assert item["sourceType"] == "wazuh"
        assert "apiKey" not in item
        assert item["revokedAt"] is None

    def test_list_is_org_scoped(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, _audit_repo, _step_up, org_id, _user_id = routes_client
        import asyncio

        asyncio.run(key_repo.provision(org_id, "s1", "wazuh"))
        asyncio.run(key_repo.provision(uuid.uuid4(), "other-org-source", "wazuh"))

        resp = client.get("/api/admin/integration-sources")

        assert resp.status_code == 200
        assert resp.json()["total"] == 1


class TestRevokeRoute:
    def test_revoke_requires_org_admin(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, _step_up, org_id, user_id = routes_client
        app = client.app

        def _analyst_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="testorg",
                user_id=user_id,
                username="analyst",
                roles=frozenset({Role.ANALYST}),
                correlation_id=str(uuid.uuid4()),
                acr="aal2",
            )

        app.dependency_overrides[get_tenant_context] = _analyst_tenant
        resp = client.request("DELETE", "/api/admin/integration-sources/wazuh/s1")
        assert resp.status_code == 403

    def test_revoke_without_step_up_ticket_is_401(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, *_rest = routes_client
        resp = client.request("DELETE", "/api/admin/integration-sources/wazuh/s1")
        assert resp.status_code == 401

    def test_revoke_takes_effect_and_audits(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, audit_repo, step_up, org_id, user_id = routes_client
        import asyncio

        record = asyncio.run(key_repo.provision(org_id, "s1", "wazuh"))
        assert asyncio.run(key_repo.get_by_key(record.api_key)) is not None

        ticket = _revoke_ticket(step_up, user_id, "wazuh", "s1")
        resp = client.request(
            "DELETE",
            "/api/admin/integration-sources/wazuh/s1",
            headers={"X-Step-Up-Ticket": str(ticket)},
        )

        assert resp.status_code == 204
        assert asyncio.run(key_repo.get_by_key(record.api_key)) is None

        events = [
            e
            for e in audit_repo.events
            if e.event_type == AuditEventType.INTEGRATION_SOURCE_KEY_REVOKED
        ]
        assert len(events) == 1
        assert events[0].org_id == org_id
