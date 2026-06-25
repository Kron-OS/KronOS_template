"""Integration tests for Keycloak auth, query isolation, and OpenSearch isolation middleware."""

from __future__ import annotations

import uuid

import pytest

from src.domain.user import Role, TenantContext
from src.external.middleware.keycloak_auth import KeycloakTokenValidator

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


def test_keycloak_validator_initializes() -> None:
    """KeycloakTokenValidator accepts required parameters."""
    validator = KeycloakTokenValidator(
        issuer="http://keycloak:8080/realms/master",
        audience="kronos-backend",
        jwks_url="http://keycloak:8080/realms/master/.well-known/jwks.json",
    )
    assert validator._issuer == "http://keycloak:8080/realms/master"
    assert validator._audience == "kronos-backend"
    assert validator._jwks_url == "http://keycloak:8080/realms/master/.well-known/jwks.json"


def test_keycloak_validator_has_validate_method() -> None:
    """KeycloakTokenValidator has validate_and_extract method."""
    validator = KeycloakTokenValidator(
        issuer="http://keycloak:8080/realms/master",
        audience="kronos-backend",
        jwks_url="http://keycloak:8080/realms/master/.well-known/jwks.json",
    )
    assert hasattr(validator, "validate_and_extract")
    assert callable(validator.validate_and_extract)


# ---------------------------------------------------------------------------
# Tests: Query isolation middleware
# ---------------------------------------------------------------------------


def test_query_isolation_context_available() -> None:
    """TenantContext provides org_id for query isolation."""

    tenant = valid_tenant()
    # Middleware expects org_id to be available in context
    assert hasattr(tenant, "org_id")
    assert tenant.org_id is not None


def test_tenant_context_scoping() -> None:
    """TenantContext includes all necessary fields for query scoping."""
    tenant = valid_tenant()
    assert tenant.org_id is not None
    assert tenant.org_alias is not None
    assert tenant.user_id is not None
    assert tenant.roles is not None


# ---------------------------------------------------------------------------
# Tests: OpenSearch isolation (DLS roles)
# ---------------------------------------------------------------------------


def test_opensearch_query_builder_wraps_queries() -> None:
    """OpenSearch query builder injects org_id filter into all queries."""
    from src.external.middleware.opensearch_isolation import OpenSearchQueryBuilder

    tenant = valid_tenant()
    builder = OpenSearchQueryBuilder(tenant)
    base_query = {"query": {"match": {"event.action": "login"}}}

    isolated = builder.build(base_query)

    # Result should include bool query with must and filter clauses
    assert "query" in isolated
    assert "bool" in isolated["query"]
    assert "must" in isolated["query"]["bool"]
    assert "filter" in isolated["query"]["bool"]

    # Filter should contain the org_id isolation
    filters = isolated["query"]["bool"]["filter"]
    assert any("term" in f and "kronos.org_id" in f.get("term", {}) for f in filters)


def test_opensearch_query_builder_preserves_original_query() -> None:
    """OpenSearch query builder preserves the original query in must clause."""
    from src.external.middleware.opensearch_isolation import OpenSearchQueryBuilder

    tenant = valid_tenant()
    builder = OpenSearchQueryBuilder(tenant)
    original_query = {"query": {"match": {"field": "value"}}}

    wrapped = builder.build(original_query)

    # Original query should be in must clause
    must_clauses = wrapped["query"]["bool"]["must"]
    assert any(m.get("match") for m in must_clauses)


# ---------------------------------------------------------------------------
# Tests: Request context extraction (tenant_context middleware)
# ---------------------------------------------------------------------------


def test_tenant_context_fields_present() -> None:
    """TenantContext has all required fields."""
    tenant = valid_tenant()
    required_fields = [
        "org_id",
        "org_alias",
        "user_id",
        "username",
        "roles",
        "correlation_id",
        "acr",
    ]
    for field in required_fields:
        assert hasattr(tenant, field), f"TenantContext missing field: {field}"


def test_tenant_context_immutable() -> None:
    """TenantContext is immutable (frozen Pydantic model)."""
    import pydantic

    tenant = valid_tenant()
    assert isinstance(tenant, pydantic.BaseModel)
    with pytest.raises(pydantic.ValidationError):
        tenant.org_id = uuid.uuid4()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Tests: Step-up auth ticket lifecycle
# ---------------------------------------------------------------------------


def test_step_up_ticket_issued_and_consumed() -> None:
    """Step-up ticket is issued for sensitive operations, then consumed."""
    from fastapi import HTTPException

    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    user_id = uuid.uuid4()
    operation = "evidence.delete"
    resource_id = "resource123"

    ticket_id = step_up.issue_ticket(
        user_id=user_id,
        operation=operation,
        resource_id=resource_id,
    )

    assert ticket_id is not None
    assert isinstance(ticket_id, uuid.UUID)

    # First consume succeeds (returns None)
    step_up.consume_ticket(
        ticket_id=ticket_id,
        user_id=user_id,
        operation=operation,
        resource_id=resource_id,
    )

    # Second consume raises (single-use)
    with pytest.raises(HTTPException):
        step_up.consume_ticket(
            ticket_id=ticket_id,
            user_id=user_id,
            operation=operation,
            resource_id=resource_id,
        )


def test_step_up_ticket_wrong_user_rejected() -> None:
    """Step-up ticket issued for user1 cannot be used by user2."""
    from fastapi import HTTPException

    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    user1 = uuid.uuid4()
    user2 = uuid.uuid4()
    operation = "evidence.delete"
    resource_id = "resource123"

    ticket_id = step_up.issue_ticket(
        user_id=user1,
        operation=operation,
        resource_id=resource_id,
    )

    with pytest.raises(HTTPException):
        step_up.consume_ticket(
            ticket_id=ticket_id,
            user_id=user2,
            operation=operation,
            resource_id=resource_id,
        )
