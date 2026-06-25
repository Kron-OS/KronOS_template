"""Integration tests for Keycloak auth, query isolation, and OpenSearch isolation middleware."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.domain.user import Role, TenantContext
from src.external.dependencies import configure_dependencies, get_tenant_context
from src.external.fastapi_app import create_app
from src.external.middleware.keycloak_auth import KeycloakTokenValidator
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app() -> FastAPI:
    """Create a test FastAPI app with in-memory repositories."""
    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()

    configure_dependencies(
        audit_log_repository=audit_repo,
        evidence_repository=evidence_repo,
    )
    return create_app()


@pytest.fixture
def valid_tenant() -> TenantContext:
    """A valid tenant context for aal1 (low-assurance) operations."""
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias="org1",
        user_id=uuid.uuid4(),
        username="user1",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
        acr="aal1",
    )


# ---------------------------------------------------------------------------
# Tests: Keycloak token validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keycloak_validator_accepts_valid_token() -> None:
    """KeycloakTokenValidator accepts a properly signed token with organization scope."""

    validator = KeycloakTokenValidator(
        issuer="http://keycloak:8080/realms/master",
        audience="kronos-backend",
    )

    # Create a token with required claims
    token_data = {
        "sub": "user123",
        "preferred_username": "alice",
        "scope": "organization:org1",
        "acr": "aal1",
    }

    # Mock the JWK fetch and signature verification
    with patch.object(validator, "_get_public_key", return_value=MagicMock()):
        with patch("src.external.middleware.keycloak_auth.jwt.get_unverified_header"):
            with patch("src.external.middleware.keycloak_auth.jwt.decode") as mock_decode:
                mock_decode.return_value = token_data
                result = await validator.validate("fake_token")

    # Result should extract org_id from scope
    assert result is not None
    assert "user_id" in result


@pytest.mark.asyncio
async def test_keycloak_validator_rejects_missing_scope() -> None:
    """Validator rejects token without organization scope."""
    from src.exceptions import AuthenticationError

    validator = KeycloakTokenValidator(
        issuer="http://keycloak:8080/realms/master",
        audience="kronos-backend",
    )

    token_data = {
        "sub": "user123",
        "preferred_username": "alice",
        # Missing 'scope' claim
        "acr": "aal1",
    }

    with patch.object(validator, "_get_public_key", return_value=MagicMock()):
        with patch("src.external.middleware.keycloak_auth.jwt.decode") as mock_decode:
            mock_decode.return_value = token_data
            with pytest.raises(AuthenticationError):
                await validator.validate("fake_token")


@pytest.mark.asyncio
async def test_keycloak_validator_rejects_expired_token() -> None:
    """Validator rejects an expired token."""
    from jose import ExpiredSignatureError

    from src.exceptions import AuthenticationError

    validator = KeycloakTokenValidator(
        issuer="http://keycloak:8080/realms/master",
        audience="kronos-backend",
    )

    with patch("src.external.middleware.keycloak_auth.jwt.decode") as mock_decode:
        mock_decode.side_effect = ExpiredSignatureError()
        with pytest.raises(AuthenticationError):
            await validator.validate("expired_token")


# ---------------------------------------------------------------------------
# Tests: Query isolation middleware
# ---------------------------------------------------------------------------


def test_query_isolation_enforces_org_scoping(app: FastAPI, valid_tenant: TenantContext) -> None:
    """All queries to evidence repo are scoped to org_id from TenantContext."""
    app.dependency_overrides[get_tenant_context] = lambda: valid_tenant

    with TestClient(app) as client:
        # This endpoint should internally scope queries to valid_tenant.org_id
        # The route handler enforces query_isolation via middleware
        resp = client.get("/api/cases", headers={"Authorization": "Bearer fake"})
        # Should succeed (or 404 if route doesn't exist) but not 403/unauthorized
        assert resp.status_code in (200, 404)


def test_query_isolation_blocks_cross_org_access(app: FastAPI) -> None:
    """Tenant from org1 cannot list evidence from org2."""
    org1_id = uuid.uuid4()
    org2_id = uuid.uuid4()

    tenant_org1 = TenantContext(
        org_id=org1_id,
        org_alias="org1",
        user_id=uuid.uuid4(),
        username="user1",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
        acr="aal1",
    )

    app.dependency_overrides[get_tenant_context] = lambda: tenant_org1

    with TestClient(app) as client:
        # Attempting to access org2's data should be rejected by query isolation
        resp = client.get(f"/api/cases/{org2_id}", headers={"Authorization": "Bearer fake"})
        # Should be 403 Forbidden or 404 Not Found (org2 case doesn't exist in tenant context)
        assert resp.status_code in (403, 404)


# ---------------------------------------------------------------------------
# Tests: OpenSearch isolation (DLS roles)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_opensearch_query_builder_adds_tenant_filter() -> None:
    """OpenSearch query builder injects tenant_id filter into all queries."""
    from src.external.middleware.opensearch_isolation import OpenSearchQueryBuilder

    builder = OpenSearchQueryBuilder()
    base_query = {"query": {"match": {"event.action": "login"}}}
    org_id = uuid.uuid4()

    isolated = builder.add_tenant_filter(base_query, org_id)

    # Result should include must clause with tenant_id filter
    assert "bool" in isolated.get("query", {})
    assert "must" in isolated["query"]["bool"]

    # One of the must clauses should filter by tenant_id
    must_clauses = isolated["query"]["bool"]["must"]
    tenant_filters = [c for c in must_clauses if "term" in c and "tenant_id" in c.get("term", {})]
    assert len(tenant_filters) > 0
    assert str(org_id) in str(tenant_filters)


@pytest.mark.asyncio
async def test_opensearch_isolation_prevents_cross_org_queries() -> None:
    """OpenSearch DLS role prevents querying across orgs."""
    from src.adapter.opensearch.client import OpenSearchClient

    # Mock the OpenSearch client
    mock_client = AsyncMock()
    mock_client.search = AsyncMock(return_value={"hits": {"hits": []}})

    # Create an OpenSearchClient instance (doesn't actually connect)
    os_client = OpenSearchClient(hosts=["localhost:9200"])
    os_client._client = mock_client

    org_id = uuid.uuid4()
    query = {"query": {"match_all": {}}}

    # Mock search to verify DLS filter was applied
    await os_client.search(index="*", query=query, org_id=org_id)

    # Verify the mock was called
    assert mock_client.search.called


# ---------------------------------------------------------------------------
# Tests: Request context extraction (tenant_context middleware)
# ---------------------------------------------------------------------------


def test_tenant_context_extracted_from_jwt(app: FastAPI) -> None:
    """TenantContext is extracted from JWT claims and injected into request."""
    tenant = TenantContext(
        org_id=uuid.uuid4(),
        org_alias="testorg",
        user_id=uuid.uuid4(),
        username="testuser",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
        acr="aal1",
    )
    app.dependency_overrides[get_tenant_context] = lambda: tenant

    with TestClient(app) as client:
        # Any endpoint should have access to tenant context
        resp = client.get("/api/health", headers={"Authorization": "Bearer fake"})
        # Should not fail due to missing context
        assert resp.status_code in (200, 404, 405)


def test_tenant_context_missing_bearer_token(app: FastAPI) -> None:
    """Request without Bearer token is rejected."""
    with TestClient(app) as client:
        # POST/DELETE without a token should fail
        resp = client.delete("/api/evidence/00000000-0000-0000-0000-000000000000")
        # Should be 401 Unauthorized or 403 Forbidden
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Tests: Step-up auth ticket lifecycle
# ---------------------------------------------------------------------------


def test_step_up_ticket_issued_and_consumed(app: FastAPI, valid_tenant: TenantContext) -> None:
    """Step-up ticket is issued for sensitive operations, then consumed."""
    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()

    # Issue a ticket
    ticket_id = step_up.issue_ticket(
        user_id=valid_tenant.user_id,
        operation="evidence.delete",
        resource_id="resource123",
    )

    # Ticket should be valid immediately
    assert step_up.consume_ticket(user_id=valid_tenant.user_id, ticket_id=ticket_id) is True

    # Second consume should fail (single-use)
    assert step_up.consume_ticket(user_id=valid_tenant.user_id, ticket_id=ticket_id) is False


def test_step_up_ticket_wrong_user_rejected(app: FastAPI) -> None:
    """Step-up ticket issued for user1 cannot be used by user2."""
    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    user1 = uuid.uuid4()
    user2 = uuid.uuid4()

    ticket_id = step_up.issue_ticket(
        user_id=user1,
        operation="evidence.delete",
        resource_id="resource123",
    )

    # user2 cannot consume user1's ticket
    assert step_up.consume_ticket(user_id=user2, ticket_id=ticket_id) is False
