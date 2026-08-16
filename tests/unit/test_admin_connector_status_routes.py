"""Unit tests for GET /api/admin/connectors/status (Milestone W14, Gap Audit
P2-W14, docs/assessments/ux_onboarding_review.md SS1).

Mirrors test_admin_integration_source_routes.py's own fixture shape
(TestClient + app.dependency_overrides). Exercises real route logic against
InMemoryIntegrationSourceKeyRepository/InMemoryAuditLogRepository -- no
mocked domain objects (CLAUDE.md SS B.5).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

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
    get_defender_poll_org_id,
    get_defender_poll_source_id,
    get_integration_source_key_repository,
    get_tenant_context,
)
from src.external.fastapi_app import create_app
from tests.conftest import InMemoryAuditLogRepository


@pytest.fixture
def status_client():  # type: ignore[no-untyped-def]
    audit_repo = InMemoryAuditLogRepository()
    key_repo = InMemoryIntegrationSourceKeyRepository()
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
            acr="aal1",
        )

    app = create_app()
    app.dependency_overrides[get_tenant_context] = _admin_tenant
    app.dependency_overrides[get_integration_source_key_repository] = lambda: key_repo
    app.dependency_overrides[get_audit_log_service] = lambda: AuditLogService(audit_repo)
    app.dependency_overrides[get_defender_poll_org_id] = lambda: None
    app.dependency_overrides[get_defender_poll_source_id] = lambda: "ms-defender-alerts"

    return TestClient(app), key_repo, audit_repo, fixed_org, user_id


class TestRoleGate:
    def test_requires_org_admin(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, org_id, user_id = status_client
        app = client.app

        def _analyst_tenant() -> TenantContext:
            return TenantContext(
                org_id=org_id,
                org_alias="testorg",
                user_id=user_id,
                username="analyst",
                roles=frozenset({Role.ANALYST}),
                correlation_id=str(uuid.uuid4()),
                acr="aal1",
            )

        app.dependency_overrides[get_tenant_context] = _analyst_tenant
        resp = client.get("/api/admin/connectors/status")
        assert resp.status_code == 403

    def test_no_step_up_required_for_read(self, status_client) -> None:  # type: ignore[no-untyped-def]
        # ORG_ADMIN with aal1 (no step-up) must still succeed -- read-only
        # status is not credential issuance.
        client, *_rest = status_client
        resp = client.get("/api/admin/connectors/status")
        assert resp.status_code == 200


class TestPushSourceEnrichment:
    def test_never_used_push_source(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, _audit_repo, org_id, _user_id = status_client
        import asyncio

        asyncio.run(key_repo.provision(org_id, "wazuh-1", "wazuh"))

        resp = client.get("/api/admin/connectors/status")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        item = items[0]
        assert item["sourceId"] == "wazuh-1"
        assert item["sourceType"] == "wazuh"
        assert item["mode"] == "push"
        assert item["selfService"] is True
        assert item["status"] == "never_used"
        assert item["lastIngestedAt"] is None
        assert item["revokedAt"] is None

    def test_active_push_source_gets_real_last_ingested_at(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, audit_repo, org_id, _user_id = status_client
        import asyncio

        asyncio.run(key_repo.provision(org_id, "wazuh-1", "wazuh"))
        audit_svc = AuditLogService(audit_repo)
        older = datetime.now(UTC) - timedelta(hours=2)
        newest = datetime.now(UTC) - timedelta(minutes=5)
        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED,
                org_id=org_id,
                details={"source_id": "wazuh-1", "source_type": "wazuh", "event_count": 3},
                occurred_at=older,
            )
        )
        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED,
                org_id=org_id,
                details={"source_id": "wazuh-1", "source_type": "wazuh", "event_count": 1},
                occurred_at=newest,
            )
        )

        resp = client.get("/api/admin/connectors/status")
        assert resp.status_code == 200
        item = resp.json()["items"][0]
        assert item["status"] == "active"
        # Real most-recent occurred_at, not the older event's.
        assert item["lastIngestedAt"] == newest.isoformat()

    def test_revoked_push_source_status_wins_over_past_activity(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, audit_repo, org_id, _user_id = status_client
        import asyncio

        asyncio.run(key_repo.provision(org_id, "wazuh-1", "wazuh"))
        audit_svc = AuditLogService(audit_repo)
        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED,
                org_id=org_id,
                details={"source_id": "wazuh-1", "source_type": "wazuh"},
            )
        )
        asyncio.run(key_repo.revoke(org_id, "wazuh-1"))

        resp = client.get("/api/admin/connectors/status")
        item = resp.json()["items"][0]
        assert item["status"] == "revoked"
        assert item["revokedAt"] is not None
        # lastIngestedAt still reflects real history even though revoked.
        assert item["lastIngestedAt"] is not None

    def test_push_never_carries_poll_failure_fields(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, _audit_repo, org_id, _user_id = status_client
        import asyncio

        asyncio.run(key_repo.provision(org_id, "wazuh-1", "wazuh"))
        resp = client.get("/api/admin/connectors/status")
        item = resp.json()["items"][0]
        assert item["lastPollFailedAt"] is None
        assert item["lastFailureReason"] is None

    def test_org_scoping_no_cross_org_leak(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, key_repo, audit_repo, org_id, _user_id = status_client
        import asyncio

        other_org = uuid.uuid4()
        asyncio.run(key_repo.provision(org_id, "mine", "wazuh"))
        asyncio.run(key_repo.provision(other_org, "not-mine", "wazuh"))
        audit_svc = AuditLogService(audit_repo)
        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED,
                org_id=other_org,
                details={"source_id": "not-mine", "source_type": "wazuh"},
            )
        )

        resp = client.get("/api/admin/connectors/status")
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["sourceId"] == "mine"
        assert items[0]["lastIngestedAt"] is None  # the other org's event never leaks in


class TestDefenderEntry:
    def test_absent_when_unset(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, *_rest = status_client
        resp = client.get("/api/admin/connectors/status")
        assert resp.json()["items"] == []

    def test_absent_when_configured_for_a_different_org(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, _org_id, _user_id = status_client
        app = client.app
        app.dependency_overrides[get_defender_poll_org_id] = lambda: str(uuid.uuid4())

        resp = client.get("/api/admin/connectors/status")
        assert resp.json()["items"] == []

    def test_absent_when_malformed(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, *_rest = status_client
        app = client.app
        app.dependency_overrides[get_defender_poll_org_id] = lambda: "not-a-real-uuid"

        resp = client.get("/api/admin/connectors/status")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_present_when_matching_this_org(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, _audit_repo, org_id, _user_id = status_client
        app = client.app
        app.dependency_overrides[get_defender_poll_org_id] = lambda: str(org_id)
        app.dependency_overrides[get_defender_poll_source_id] = lambda: "ms-defender-alerts"

        resp = client.get("/api/admin/connectors/status")
        items = resp.json()["items"]
        assert len(items) == 1
        item = items[0]
        assert item["sourceId"] == "ms-defender-alerts"
        assert item["sourceType"] == "ms-defender-alerts"
        assert item["mode"] == "poll"
        assert item["selfService"] is False
        assert item["status"] == "never_used"
        assert "platform settings" in item["note"]

    def test_present_with_real_poll_completed_and_failed_signals(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, audit_repo, org_id, _user_id = status_client
        app = client.app
        app.dependency_overrides[get_defender_poll_org_id] = lambda: str(org_id)

        audit_svc = AuditLogService(audit_repo)
        import asyncio

        completed_at = datetime.now(UTC) - timedelta(hours=1)
        failed_at = datetime.now(UTC) - timedelta(minutes=10)
        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_POLL_COMPLETED,
                org_id=org_id,
                details={"source_id": "ms-defender-alerts", "source_type": "ms-defender-alerts"},
                occurred_at=completed_at,
            )
        )
        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_POLL_FAILED,
                org_id=org_id,
                details={
                    "source_id": "ms-defender-alerts",
                    "source_type": "ms-defender-alerts",
                    "error": "401 from Graph API",
                },
                occurred_at=failed_at,
            )
        )

        resp = client.get("/api/admin/connectors/status")
        item = resp.json()["items"][0]
        assert item["status"] == "failing"
        assert item["lastPolledAt"] == completed_at.isoformat()
        assert item["lastPollFailedAt"] == failed_at.isoformat()
        assert item["lastFailureReason"] == "401 from Graph API"

    def test_present_active_with_only_a_successful_poll(self, status_client) -> None:  # type: ignore[no-untyped-def]
        client, _key_repo, audit_repo, org_id, _user_id = status_client
        app = client.app
        app.dependency_overrides[get_defender_poll_org_id] = lambda: str(org_id)

        audit_svc = AuditLogService(audit_repo)
        import asyncio

        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_POLL_COMPLETED,
                org_id=org_id,
                details={"source_id": "ms-defender-alerts", "source_type": "ms-defender-alerts"},
            )
        )

        resp = client.get("/api/admin/connectors/status")
        item = resp.json()["items"][0]
        assert item["status"] == "active"
        assert item["lastPollFailedAt"] is None

    def test_defender_events_from_other_source_type_never_leak_in(self, status_client) -> None:  # type: ignore[no-untyped-def]
        # A POLL_COMPLETED event for some other (hypothetical) poll source
        # must never be attributed to Defender's status.
        client, _key_repo, audit_repo, org_id, _user_id = status_client
        app = client.app
        app.dependency_overrides[get_defender_poll_org_id] = lambda: str(org_id)

        audit_svc = AuditLogService(audit_repo)
        import asyncio

        asyncio.run(
            audit_svc.log(
                AuditEventType.INTEGRATION_SOURCE_POLL_COMPLETED,
                org_id=org_id,
                details={"source_id": "other-poll", "source_type": "some-other-poll-source"},
            )
        )

        resp = client.get("/api/admin/connectors/status")
        item = resp.json()["items"][0]
        assert item["status"] == "never_used"
        assert item["lastPolledAt"] is None
