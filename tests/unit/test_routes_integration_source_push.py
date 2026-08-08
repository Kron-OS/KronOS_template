"""Unit tests for the integration-source push HTTP route via TestClient.

Full real end-to-end verification (real local HTTP server, real API-key
auth, real stream produce) is in poc/integration_source_foundation/ -- these
tests cover the route's own HTTP-status/DTO-translation contract, mocking
the authenticator and service per CLAUDE.md SS B.5 (mirrors
test_routes_collector_ingest.py's own scope split exactly).
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from src.application.integration_source import IntegrationSourceError
from src.application.integration_source_ingest import (
    EventOutcome,
    IntegrationSourceBackpressureError,
)
from src.domain.integration_source import IntegrationSourceIdentity
from src.exceptions import AuthenticationError
from src.external.dependencies import (
    get_inbound_source_authenticator,
    get_integration_source_ingest_service,
)
from src.external.fastapi_app import create_app


@pytest.fixture
def identity() -> IntegrationSourceIdentity:
    return IntegrationSourceIdentity(
        org_id=uuid.uuid4(), source_id="s1", source_type="generic-webhook", auth_method="api-key"
    )


@pytest.fixture
def authenticator(identity: IntegrationSourceIdentity) -> AsyncMock:
    mock = AsyncMock()
    mock.authenticate.return_value = identity
    return mock


@pytest.fixture
def service() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def client(authenticator: AsyncMock, service: AsyncMock) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_inbound_source_authenticator] = lambda: authenticator
    app.dependency_overrides[get_integration_source_ingest_service] = lambda: service
    return TestClient(app)


class TestPushWebhookRoute:
    def test_accepted_events_return_202(self, client: TestClient, service: AsyncMock) -> None:
        service.ingest_push.return_value = [
            EventOutcome(accepted=True, duplicate=False, message_id="1-0")
        ]

        resp = client.post("/api/integrations/push/generic-webhook", json={"alert": "x"})

        assert resp.status_code == 202
        assert resp.json() == {
            "results": [{"accepted": True, "duplicate": False, "messageId": "1-0"}]
        }

    def test_unauthenticated_request_returns_401(
        self, client: TestClient, authenticator: AsyncMock
    ) -> None:
        authenticator.authenticate.side_effect = AuthenticationError("bad key")

        resp = client.post("/api/integrations/push/generic-webhook", json={"a": 1})

        assert resp.status_code == 401

    def test_source_type_mismatch_returns_403(
        self, client: TestClient, authenticator: AsyncMock, identity: IntegrationSourceIdentity
    ) -> None:
        # Credential was provisioned for "generic-webhook", request path claims a different one.
        resp = client.post("/api/integrations/push/some-other-source", json={"a": 1})

        assert resp.status_code == 403

    def test_backpressure_returns_503(self, client: TestClient, service: AsyncMock) -> None:
        service.ingest_push.side_effect = IntegrationSourceBackpressureError("stream at capacity")

        resp = client.post("/api/integrations/push/generic-webhook", json={"a": 1})

        assert resp.status_code == 503
        assert "capacity" in resp.json()["detail"]

    def test_integration_source_error_returns_400(
        self, client: TestClient, service: AsyncMock
    ) -> None:
        service.ingest_push.side_effect = IntegrationSourceError("bad payload")

        resp = client.post("/api/integrations/push/generic-webhook", json={"a": 1})

        assert resp.status_code == 400

    def test_service_receives_the_identity_from_the_authenticator_not_the_body(
        self, client: TestClient, service: AsyncMock, identity: IntegrationSourceIdentity
    ) -> None:
        service.ingest_push.return_value = []

        client.post(
            "/api/integrations/push/generic-webhook",
            json={"source_id": "attacker-supplied", "org_id": str(uuid.uuid4())},
        )

        called_identity, _raw_body = service.ingest_push.await_args[0]
        assert called_identity is identity
