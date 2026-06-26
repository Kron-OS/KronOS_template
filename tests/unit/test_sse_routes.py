"""Unit tests for SSE ticket and stream routes."""

from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient

from src.domain.user import Role, TenantContext
from src.external.dependencies import get_evidence_repository, get_tenant_context
from src.external.fastapi_app import create_app
from src.external.routes import sse as sse_module
from tests.conftest import InMemoryEvidenceRepository


@pytest.fixture(autouse=True)
def clear_tickets():
    """Clear the in-memory ticket store between tests."""
    sse_module._tickets.clear()
    yield
    sse_module._tickets.clear()


@pytest.fixture
def sse_client():
    fixed_org = uuid.uuid4()
    fixed_user = uuid.uuid4()

    def _fixed_tenant() -> TenantContext:
        return TenantContext(
            org_id=fixed_org,
            org_alias="testorg",
            user_id=fixed_user,
            username="tester",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )

    evidence_repo = InMemoryEvidenceRepository()
    app = create_app()
    app.dependency_overrides[get_tenant_context] = _fixed_tenant
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo
    return TestClient(app), fixed_org, fixed_user


class TestCreateSSETicket:
    def test_creates_ticket(self, sse_client):
        client, org_id, _ = sse_client
        case_id = uuid.uuid4()
        resp = client.post(f"/api/sse/ticket?case_id={case_id}")
        assert resp.status_code == 201
        data = resp.json()
        assert "ticket" in data
        assert data["expires_in"] == 60
        assert data["ticket"] in sse_module._tickets

    def test_ticket_is_scoped_to_case(self, sse_client):
        client, org_id, _ = sse_client
        case_id = uuid.uuid4()
        resp = client.post(f"/api/sse/ticket?case_id={case_id}")
        ticket = resp.json()["ticket"]
        assert sse_module._tickets[ticket]["case_id"] == str(case_id)

    def test_ticket_is_scoped_to_org(self, sse_client):
        client, org_id, _ = sse_client
        case_id = uuid.uuid4()
        resp = client.post(f"/api/sse/ticket?case_id={case_id}")
        ticket = resp.json()["ticket"]
        assert sse_module._tickets[ticket]["org_id"] == str(org_id)


class TestSSEStream:
    def test_expired_ticket_returns_401(self, sse_client):
        client, _, _ = sse_client
        case_id = uuid.uuid4()
        ticket = str(uuid.uuid4())
        # Insert an already-expired ticket
        sse_module._tickets[ticket] = {
            "case_id": str(case_id),
            "org_id": str(uuid.uuid4()),
            "expires": time.time() - 1,
        }
        resp = client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket={ticket}",
            headers={"Accept": "text/event-stream"},
        )
        assert resp.status_code == 401

    def test_wrong_case_id_returns_401(self, sse_client):
        client, org_id, _ = sse_client
        case_id = uuid.uuid4()
        wrong_case = uuid.uuid4()
        ticket = str(uuid.uuid4())
        sse_module._tickets[ticket] = {
            "case_id": str(wrong_case),
            "org_id": str(org_id),
            "expires": time.time() + 60,
        }
        resp = client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket={ticket}",
            headers={"Accept": "text/event-stream"},
        )
        assert resp.status_code == 401

    def test_missing_ticket_returns_401(self, sse_client):
        client, _, _ = sse_client
        case_id = uuid.uuid4()
        resp = client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket=nonexistent",
            headers={"Accept": "text/event-stream"},
        )
        assert resp.status_code == 401

    def test_valid_ticket_consumed_once(self, sse_client):
        client, org_id, _ = sse_client
        case_id = uuid.uuid4()
        ticket = str(uuid.uuid4())
        sse_module._tickets[ticket] = {
            "case_id": str(case_id),
            "org_id": str(org_id),
            "expires": time.time() + 60,
        }
        # First call should consume the ticket (ticket removed from dict)
        # TestClient streams so we just check it was popped
        assert ticket in sse_module._tickets
        client.get(
            f"/api/sse/cases/{case_id}/evidence?ticket={ticket}",
            headers={"Accept": "text/event-stream"},
        )
        assert ticket not in sse_module._tickets
