"""Integration tests for Phase 5 auth/RBAC/step-up flows via FastAPI TestClient."""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.adapter.storage.storage import EvidenceStorage
from src.domain.evidence import Evidence, EvidenceState
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    configure_dependencies,
    get_step_up_auth,
    get_tenant_context,
    reset_dependencies,
)
from src.external.fastapi_app import create_app
from src.external.middleware.step_up_auth import StepUpAuth
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository

# ---------------------------------------------------------------------------
# Factories / fixtures
# ---------------------------------------------------------------------------


def _make_tenant(
    roles: frozenset[Role] | None = None,
    acr: str = "aal1",
    org_id: uuid.UUID | None = None,
) -> TenantContext:
    return TenantContext(
        org_id=org_id or uuid.uuid4(),
        org_alias="testorg",
        user_id=uuid.uuid4(),
        username="testuser",
        roles=roles or frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
        acr=acr,
    )


class _NoopStorage(EvidenceStorage):
    async def request_presigned_upload(self, evidence, expires_in_seconds=3600):
        from src.adapter.storage.storage import PresignedUploadResponse

        return PresignedUploadResponse("http://fake/upload", "key/test", expires_in_seconds)

    async def stream_object(self, object_key, chunk_size=65536):
        yield b"\x00" * 16

    async def promote_to_evidence_bucket(self, quarantine_key, evidence):
        return f"evidence/{evidence.evidence_id}"

    async def delete_from_quarantine(self, quarantine_key):
        pass

    async def object_exists(self, object_key):
        return True


@pytest.fixture(autouse=True)
def reset_deps():
    reset_dependencies()
    yield
    reset_dependencies()


@pytest.fixture
def audit_repo() -> InMemoryAuditLogRepository:
    return InMemoryAuditLogRepository()


@pytest.fixture
def evidence_repo() -> InMemoryEvidenceRepository:
    return InMemoryEvidenceRepository()


@pytest.fixture
def step_up() -> StepUpAuth:
    return StepUpAuth()


@pytest.fixture
def app(audit_repo, evidence_repo, step_up) -> FastAPI:
    configure_dependencies(
        audit_log_repository=audit_repo,
        evidence_repository=evidence_repo,
        evidence_storage=_NoopStorage(),
    )
    application = create_app()
    application.dependency_overrides[get_step_up_auth] = lambda: step_up
    return application


# ---------------------------------------------------------------------------
# Helper: create an Evidence record in the repo directly
# ---------------------------------------------------------------------------


def _seed_evidence(
    repo: InMemoryEvidenceRepository,
    org_id: uuid.UUID,
    state: EvidenceState = EvidenceState.RECEIVED,
) -> Evidence:
    from src.domain.evidence import Evidence
    from tests.fixtures.factories import make_evidence_metadata

    ev = Evidence(
        metadata=make_evidence_metadata(org_id=org_id),
        state=state,
    )
    import asyncio

    asyncio.run(repo.save(ev))
    return ev


# ---------------------------------------------------------------------------
# Tests: RBAC — requires_role
# ---------------------------------------------------------------------------


def test_delete_route_requires_org_admin(app: FastAPI, evidence_repo, step_up) -> None:
    """Analyst role must receive 403 on the DELETE route."""
    org_id = uuid.uuid4()
    tenant = _make_tenant(roles=frozenset({Role.ANALYST}), org_id=org_id)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    evidence = _seed_evidence(evidence_repo, org_id)
    with TestClient(app) as client:
        resp = client.delete(
            f"/api/evidence/{evidence.evidence_id}",
            headers={"x-step-up-ticket": str(uuid.uuid4())},
        )
    assert resp.status_code == 403


def test_delete_route_org_admin_proceeds(app: FastAPI, evidence_repo, step_up) -> None:
    """Org-admin with aal2 token and valid step-up ticket succeeds."""
    org_id = uuid.uuid4()
    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=org_id)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    evidence = _seed_evidence(evidence_repo, org_id)
    ticket_id = step_up.issue_ticket(tenant.user_id, "evidence.delete", str(evidence.evidence_id))

    with TestClient(app) as client:
        resp = client.delete(
            f"/api/evidence/{evidence.evidence_id}",
            headers={"x-step-up-ticket": str(ticket_id)},
        )
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Tests: Step-up auth
# ---------------------------------------------------------------------------


def test_delete_requires_aal2_acr(app: FastAPI, evidence_repo, step_up) -> None:
    """Org-admin with only aal1 ACR gets 401 step-up challenge."""
    org_id = uuid.uuid4()
    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal1", org_id=org_id)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    evidence = _seed_evidence(evidence_repo, org_id)
    ticket_id = step_up.issue_ticket(tenant.user_id, "evidence.delete", str(evidence.evidence_id))

    with TestClient(app) as client:
        resp = client.delete(
            f"/api/evidence/{evidence.evidence_id}",
            headers={"x-step-up-ticket": str(ticket_id)},
        )
    assert resp.status_code == 401
    assert "acr_values" in resp.headers.get("www-authenticate", "")


def test_delete_step_up_ticket_single_use(app: FastAPI, evidence_repo, step_up) -> None:
    """Reusing a consumed step-up ticket must be rejected."""
    org_id = uuid.uuid4()
    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=org_id)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    ev1 = _seed_evidence(evidence_repo, org_id)
    ev2 = _seed_evidence(evidence_repo, org_id)

    ticket_id = step_up.issue_ticket(tenant.user_id, "evidence.delete", str(ev1.evidence_id))

    with TestClient(app) as client:
        # First use — succeeds.
        r1 = client.delete(
            f"/api/evidence/{ev1.evidence_id}",
            headers={"x-step-up-ticket": str(ticket_id)},
        )
        assert r1.status_code == 204

        # Reuse — fails even for a different resource.
        r2 = client.delete(
            f"/api/evidence/{ev2.evidence_id}",
            headers={"x-step-up-ticket": str(ticket_id)},
        )
    assert r2.status_code == 401


def test_delete_invalid_ticket_uuid_rejected(app: FastAPI, evidence_repo, step_up) -> None:
    """Malformed ticket header must yield 401."""
    org_id = uuid.uuid4()
    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=org_id)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    evidence = _seed_evidence(evidence_repo, org_id)
    with TestClient(app) as client:
        resp = client.delete(
            f"/api/evidence/{evidence.evidence_id}",
            headers={"x-step-up-ticket": "not-a-uuid"},
        )
    assert resp.status_code == 401


def test_delete_missing_ticket_rejected(app: FastAPI, evidence_repo, step_up) -> None:
    """Missing X-Step-Up-Ticket header must yield 401."""
    org_id = uuid.uuid4()
    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=org_id)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    evidence = _seed_evidence(evidence_repo, org_id)
    with TestClient(app) as client:
        resp = client.delete(f"/api/evidence/{evidence.evidence_id}")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tests: Query isolation
# ---------------------------------------------------------------------------


def test_delete_wrong_org_returns_404(app: FastAPI, evidence_repo, step_up) -> None:
    """An org-admin cannot delete evidence that belongs to another org."""
    owner_org = uuid.uuid4()
    requester_org = uuid.uuid4()

    evidence = _seed_evidence(evidence_repo, owner_org)

    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=requester_org)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    ticket_id = step_up.issue_ticket(
        tenant.user_id, "evidence.delete", str(evidence.evidence_id)
    )
    with TestClient(app) as client:
        resp = client.delete(
            f"/api/evidence/{evidence.evidence_id}",
            headers={"x-step-up-ticket": str(ticket_id)},
        )
    # Repository returns None for wrong org_id → 404.
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: Audit log on deletion
# ---------------------------------------------------------------------------


def test_delete_audit_event_logged(
    app: FastAPI, evidence_repo, audit_repo: InMemoryAuditLogRepository, step_up
) -> None:
    """EVIDENCE_DELETED audit event must be emitted on successful delete."""
    from src.domain.audit import AuditEventType

    org_id = uuid.uuid4()
    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=org_id)
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    evidence = _seed_evidence(evidence_repo, org_id)
    ticket_id = step_up.issue_ticket(tenant.user_id, "evidence.delete", str(evidence.evidence_id))

    with TestClient(app) as client:
        resp = client.delete(
            f"/api/evidence/{evidence.evidence_id}",
            headers={"x-step-up-ticket": str(ticket_id)},
        )
    assert resp.status_code == 204

    event_types = [e.event_type for e in audit_repo.events]
    assert AuditEventType.EVIDENCE_DELETED in event_types


# ---------------------------------------------------------------------------
# Tests: Concurrent isolation (different orgs don't interfere)
# ---------------------------------------------------------------------------


def test_concurrent_orgs_isolation(app: FastAPI, evidence_repo, step_up) -> None:
    """Evidence from org1 is not visible or deletable by org2."""
    org1 = uuid.uuid4()
    org2 = uuid.uuid4()

    ev1 = _seed_evidence(evidence_repo, org1)
    _seed_evidence(evidence_repo, org2)

    tenant1 = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=org1)
    tenant2 = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2", org_id=org2)

    # org2 cannot delete org1's evidence.
    app.dependency_overrides[get_tenant_context] = lambda: tenant2
    ticket = step_up.issue_ticket(tenant2.user_id, "evidence.delete", str(ev1.evidence_id))
    with TestClient(app) as client:
        resp = client.delete(
            f"/api/evidence/{ev1.evidence_id}",
            headers={"x-step-up-ticket": str(ticket)},
        )
    assert resp.status_code == 404

    # org1 can delete its own evidence.
    app.dependency_overrides[get_tenant_context] = lambda: tenant1
    ticket2 = step_up.issue_ticket(tenant1.user_id, "evidence.delete", str(ev1.evidence_id))
    with TestClient(app) as client:
        resp2 = client.delete(
            f"/api/evidence/{ev1.evidence_id}",
            headers={"x-step-up-ticket": str(ticket2)},
        )
    assert resp2.status_code == 204
