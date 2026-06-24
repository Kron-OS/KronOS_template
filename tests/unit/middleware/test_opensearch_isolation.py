"""Unit tests for OpenSearchQueryBuilder tenant isolation."""

from __future__ import annotations

import uuid

from src.domain.user import Role, TenantContext
from src.external.middleware.opensearch_isolation import OpenSearchQueryBuilder


def _make_tenant(org_id: uuid.UUID | None = None) -> TenantContext:
    return TenantContext(
        org_id=org_id or uuid.uuid4(),
        org_alias="testorg",
        user_id=uuid.uuid4(),
        username="testuser",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def test_build_wraps_empty_query() -> None:
    tenant = _make_tenant()
    builder = OpenSearchQueryBuilder(tenant)
    result = builder.build({})
    assert "query" in result
    assert "bool" in result["query"]
    assert "filter" in result["query"]["bool"]
    iso_filter = result["query"]["bool"]["filter"][0]
    assert iso_filter["term"]["kronos.org_id"] == str(tenant.org_id)


def test_build_preserves_original_query() -> None:
    tenant = _make_tenant()
    builder = OpenSearchQueryBuilder(tenant)
    original = {"query": {"match": {"message": "login"}}, "size": 100}
    result = builder.build(original)
    must = result["query"]["bool"]["must"]
    assert {"match": {"message": "login"}} in must
    assert result["size"] == 100


def test_build_always_includes_org_id_filter() -> None:
    org_id = uuid.uuid4()
    tenant = _make_tenant(org_id=org_id)
    builder = OpenSearchQueryBuilder(tenant)

    # No matter what the query contains, isolation filter is always present.
    for query in [
        {},
        {"query": {"match_all": {}}},
        {"query": {"term": {"event.kind": "event"}}},
    ]:
        result = builder.build(query)
        filters = result["query"]["bool"]["filter"]
        assert any(
            f.get("term", {}).get("kronos.org_id") == str(org_id) for f in filters
        ), f"org_id filter missing for query: {query}"


def test_org_id_filter_property() -> None:
    tenant = _make_tenant()
    builder = OpenSearchQueryBuilder(tenant)
    f = builder.org_id_filter
    assert f == {"term": {"kronos.org_id": str(tenant.org_id)}}


def test_different_orgs_produce_different_filters() -> None:
    org1, org2 = uuid.uuid4(), uuid.uuid4()
    b1 = OpenSearchQueryBuilder(_make_tenant(org1))
    b2 = OpenSearchQueryBuilder(_make_tenant(org2))
    assert b1.org_id_filter != b2.org_id_filter
