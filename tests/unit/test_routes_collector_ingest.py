"""Unit tests for the collector ingest HTTP route via TestClient.

Full real mTLS + step-ca + Redis verification is in
poc/collector_ingest_mtls/ (17/17 checks) -- these tests cover the route's
own HTTP-status/DTO-translation contract, mocking the service and the
identity dependency per CLAUDE.md SS B.5.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from src.application.collector_ingest import BackpressureError, EventOutcome
from src.domain.collector import CollectorIdentity
from src.external.collector_app import create_collector_app
from src.external.dependencies import get_collector_ingest_service
from src.external.middleware.collector_mtls import get_collector_identity


@pytest.fixture
def identity() -> CollectorIdentity:
    return CollectorIdentity(
        org_id=uuid.uuid4(),
        source_id="zeek-conn",
        cert_subject="CN=test",
        not_after="2026-01-01T00:00:00+00:00",
    )


@pytest.fixture
def service() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def client(identity: CollectorIdentity, service: AsyncMock) -> TestClient:
    app = create_collector_app()
    app.dependency_overrides[get_collector_identity] = lambda: identity
    app.dependency_overrides[get_collector_ingest_service] = lambda: service
    return TestClient(app)


class TestIngestRoute:
    def test_accepted_events_return_202(self, client: TestClient, service: AsyncMock) -> None:
        service.ingest_events.return_value = [
            EventOutcome(accepted=True, duplicate=False, message_id="1-0")
        ]

        resp = client.post("/api/collector/ingest", json={"events": [{"a": 1}]})

        assert resp.status_code == 202
        assert resp.json() == {
            "results": [{"accepted": True, "duplicate": False, "messageId": "1-0"}]
        }

    def test_backpressure_returns_503(self, client: TestClient, service: AsyncMock) -> None:
        service.ingest_events.side_effect = BackpressureError("stream at capacity")

        resp = client.post("/api/collector/ingest", json={"events": [{"a": 1}]})

        assert resp.status_code == 503
        assert "capacity" in resp.json()["detail"]

    def test_service_receives_the_identity_dependency_not_anything_from_the_body(
        self, client: TestClient, service: AsyncMock, identity: CollectorIdentity
    ) -> None:
        service.ingest_events.return_value = []
        client.post("/api/collector/ingest", json={"events": [{"org_id": str(uuid.uuid4())}]})

        called_identity, _events = service.ingest_events.await_args[0]
        assert called_identity is identity

    def test_empty_events_list_is_rejected_by_the_schema(self, client: TestClient) -> None:
        resp = client.post("/api/collector/ingest", json={"events": []})
        assert resp.status_code == 422

    def test_no_verified_identity_returns_401(self, service: AsyncMock) -> None:
        from src.exceptions import AuthenticationError

        app = create_collector_app()

        def _raise() -> CollectorIdentity:
            raise AuthenticationError("no cert")

        app.dependency_overrides[get_collector_identity] = _raise
        app.dependency_overrides[get_collector_ingest_service] = lambda: service
        client = TestClient(app)

        resp = client.post("/api/collector/ingest", json={"events": [{"a": 1}]})
        assert resp.status_code == 401
