"""Unit tests for /api/admin/connectors routes (connector marketplace)
via TestClient.

Mirrors test_admin_integration_source_routes.py's exact fixture shape
(TestClient + app.dependency_overrides, real StepUpAuth ticket issuance).
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from src.adapter.repository.connector_config import InMemoryConnectorConfigRepository
from src.application.audit_log import AuditLogService
from src.application.connector_catalog import ConnectorCatalog
from src.application.connector_config import ConnectorConfigService
from src.application.secret_store import InMemorySecretStore
from src.domain.audit import AuditEventType
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_audit_log_service,
    get_connector_config_service,
    get_step_up_auth,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from src.external.middleware.step_up_auth import StepUpAuth
from tests.conftest import InMemoryAuditLogRepository


@pytest.fixture
def routes_client():  # type: ignore[no-untyped-def]
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    config_repo = InMemoryConnectorConfigRepository()
    secret_store = InMemorySecretStore()
    step_up = StepUpAuth()
    fixed_org = uuid.uuid4()
    user_id = uuid.uuid4()
    service = ConnectorConfigService(ConnectorCatalog(), config_repo, secret_store, audit_log)

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
    app.dependency_overrides[get_connector_config_service] = lambda: service
    app.dependency_overrides[get_audit_log_service] = lambda: audit_log
    app.dependency_overrides[get_step_up_auth] = lambda: step_up

    return TestClient(app), service, audit_repo, step_up, fixed_org, user_id


def _ticket(step_up: StepUpAuth, user_id: uuid.UUID, operation: str, source_type: str):  # type: ignore[no-untyped-def]
    return step_up.issue_ticket(user_id=user_id, operation=operation, resource_id=source_type)


class TestCatalogRoute:
    def test_catalog_lists_all_seven_connectors(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, *_ = routes_client
        resp = client.get("/api/admin/connectors/catalog")
        assert resp.status_code == 200
        source_types = {item["sourceType"] for item in resp.json()["items"]}
        assert source_types == {
            "wazuh",
            "suricata-eve",
            "zeek-json",
            "ms-defender-alerts",
            "splunk-hec",
            "cef-syslog",
            "sentinel",
        }

    def test_every_connector_has_real_asset_setup_notes(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        """An admin configuring a connector must be told what to set up on
        the OTHER side of the connection (their own Wazuh manager/Entra ID
        tenant/syslog receiver) -- every catalog entry must carry real,
        non-empty guidance, not a placeholder."""
        client, *_ = routes_client
        resp = client.get("/api/admin/connectors/catalog")
        for item in resp.json()["items"]:
            assert len(item["assetSetupNotes"]) > 20, item["sourceType"]

    def test_catalog_requires_org_admin(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _service, _audit, _step_up, org_id, user_id = routes_client
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
        resp = client.get("/api/admin/connectors/catalog")
        assert resp.status_code == 403


class TestSetConfigRoute:
    def test_set_config_requires_step_up_ticket(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, *_ = routes_client
        resp = client.put(
            "/api/admin/connectors/cef-syslog/config",
            json={"values": {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"}},
        )
        assert resp.status_code == 401

    def test_set_config_succeeds_with_valid_ticket(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, service, audit_repo, step_up, org_id, user_id = routes_client
        ticket = _ticket(step_up, user_id, "connector_config.set", "cef-syslog")

        resp = client.put(
            "/api/admin/connectors/cef-syslog/config",
            json={"values": {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"}},
            headers={"X-Step-Up-Ticket": str(ticket)},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["nonSecretFields"] == {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"}
        assert body["enabled"] is True

        events = [e.event_type for e in audit_repo.events]
        assert AuditEventType.CONNECTOR_CONFIG_SET_EXECUTED in events

    def test_set_config_rejects_missing_required_param(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _service, _audit, step_up, _org_id, user_id = routes_client
        ticket = _ticket(step_up, user_id, "connector_config.set", "ms-defender-alerts")

        resp = client.put(
            "/api/admin/connectors/ms-defender-alerts/config",
            json={"values": {"defender_tenant_id": "t1"}},  # missing client_id/client_secret
            headers={"X-Step-Up-Ticket": str(ticket)},
        )
        assert resp.status_code == 422

    def test_set_config_ticket_cannot_be_reused(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _service, _audit, step_up, _org_id, user_id = routes_client
        ticket = _ticket(step_up, user_id, "connector_config.set", "cef-syslog")
        headers = {"X-Step-Up-Ticket": str(ticket)}
        body = {"values": {"cef_syslog_host": "h", "cef_syslog_port": "514"}}

        first = client.put("/api/admin/connectors/cef-syslog/config", json=body, headers=headers)
        assert first.status_code == 200
        second = client.put("/api/admin/connectors/cef-syslog/config", json=body, headers=headers)
        assert second.status_code == 401


class TestGetConfigRoute:
    def test_get_config_never_leaks_secret_values(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _service, _audit, step_up, _org_id, user_id = routes_client
        ticket = _ticket(step_up, user_id, "connector_config.set", "splunk-hec")
        client.put(
            "/api/admin/connectors/splunk-hec/config",
            json={"values": {"splunk_hec_url": "https://s", "splunk_hec_token": "top-secret"}},
            headers={"X-Step-Up-Ticket": str(ticket)},
        )

        resp = client.get("/api/admin/connectors/splunk-hec/config")
        assert resp.status_code == 200
        assert "top-secret" not in resp.text
        assert resp.json()["secretsSet"] is True

    def test_get_config_404_when_unconfigured(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, *_ = routes_client
        resp = client.get("/api/admin/connectors/splunk-hec/config")
        assert resp.status_code == 404


class TestDeleteAndDisableRoutes:
    def test_delete_config_requires_step_up_and_removes_it(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _service, _audit, step_up, _org_id, user_id = routes_client
        set_ticket = _ticket(step_up, user_id, "connector_config.set", "cef-syslog")
        client.put(
            "/api/admin/connectors/cef-syslog/config",
            json={"values": {"cef_syslog_host": "h", "cef_syslog_port": "514"}},
            headers={"X-Step-Up-Ticket": str(set_ticket)},
        )

        no_ticket_resp = client.delete("/api/admin/connectors/cef-syslog/config")
        assert no_ticket_resp.status_code == 401

        delete_ticket = _ticket(step_up, user_id, "connector_config.delete", "cef-syslog")
        resp = client.delete(
            "/api/admin/connectors/cef-syslog/config", headers={"X-Step-Up-Ticket": str(delete_ticket)}
        )
        assert resp.status_code == 204
        assert client.get("/api/admin/connectors/cef-syslog/config").status_code == 404

    def test_disable_then_enable_round_trip(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _service, _audit, step_up, _org_id, user_id = routes_client
        set_ticket = _ticket(step_up, user_id, "connector_config.set", "cef-syslog")
        client.put(
            "/api/admin/connectors/cef-syslog/config",
            json={"values": {"cef_syslog_host": "h", "cef_syslog_port": "514"}},
            headers={"X-Step-Up-Ticket": str(set_ticket)},
        )

        disable_ticket = _ticket(step_up, user_id, "connector_config.disable", "cef-syslog")
        disable_resp = client.post(
            "/api/admin/connectors/cef-syslog/config/disable",
            headers={"X-Step-Up-Ticket": str(disable_ticket)},
        )
        assert disable_resp.status_code == 200
        assert disable_resp.json()["enabled"] is False

        enable_ticket = _ticket(step_up, user_id, "connector_config.enable", "cef-syslog")
        enable_resp = client.post(
            "/api/admin/connectors/cef-syslog/config/enable",
            headers={"X-Step-Up-Ticket": str(enable_ticket)},
        )
        assert enable_resp.status_code == 200
        assert enable_resp.json()["enabled"] is True

    def test_disable_404_when_unconfigured(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, _service, _audit, step_up, _org_id, user_id = routes_client
        ticket = _ticket(step_up, user_id, "connector_config.disable", "sentinel")
        resp = client.post(
            "/api/admin/connectors/sentinel/config/disable", headers={"X-Step-Up-Ticket": str(ticket)}
        )
        assert resp.status_code == 404


class TestCrossOrgIsolationViaRoutes:
    def test_list_only_returns_callers_own_org(self, routes_client) -> None:  # type: ignore[no-untyped-def]
        client, service, _audit, step_up, org_a, user_id = routes_client
        ticket = _ticket(step_up, user_id, "connector_config.set", "cef-syslog")
        client.put(
            "/api/admin/connectors/cef-syslog/config",
            json={"values": {"cef_syslog_host": "h", "cef_syslog_port": "514"}},
            headers={"X-Step-Up-Ticket": str(ticket)},
        )

        # A different org, configured directly via the service (bypassing
        # the route/tenant), must never show up in org_a's list.
        import asyncio

        org_b = uuid.uuid4()
        asyncio.run(
            service.set_config(
                org_b, "cef-syslog", {"cef_syslog_host": "other", "cef_syslog_port": "514"}, actor_user_id=uuid.uuid4()
            )
        )

        resp = client.get("/api/admin/connectors")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["nonSecretFields"]["cef_syslog_host"] == "h"
