"""Regression test for OpenSearchClient.ensure_ism_policy idempotency.

TimelineIngestionService builds a fresh instance per Celery task (see
celery_runtime.py), so ensure_ism_policy() runs on every single ingest, not
just the first ever one. PUT on an already-existing ISM policy (without
if_seq_no/if_primary_term) always 409s in OpenSearch, which crashed every
ingest after the very first one — see docs/access-management-review.md for
the incident this reproduces.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from opensearchpy.exceptions import ConflictError

from src.adapter.opensearch.client import OpenSearchClient


def _make_client() -> OpenSearchClient:
    # AsyncOpenSearch construction performs no network I/O, so this is a
    # safe, deterministic unit-level fixture.
    return OpenSearchClient(
        hosts=[{"host": "opensearch", "port": 9200}],
        http_auth=("admin", "admin"),
        use_ssl=False,
        verify_certs=False,
    )


async def test_ensure_ism_policy_succeeds_on_first_creation() -> None:
    client = _make_client()
    client._client.transport.perform_request = AsyncMock(return_value={})  # type: ignore[method-assign]

    await client.ensure_ism_policy()

    client._client.transport.perform_request.assert_awaited_once()


async def test_ensure_ism_policy_tolerates_already_exists_conflict() -> None:
    client = _make_client()
    client._client.transport.perform_request = AsyncMock(  # type: ignore[method-assign]
        side_effect=ConflictError(
            409, "version_conflict_engine_exception", {"error": "already exists"}
        )
    )

    # Must not raise: a 409 here means the policy already exists, which is
    # exactly the desired end state for an idempotent "ensure" call.
    await client.ensure_ism_policy()


async def test_ensure_ism_policy_reraises_other_errors() -> None:
    from opensearchpy.exceptions import ConnectionError as OSConnectionError

    client = _make_client()
    client._client.transport.perform_request = AsyncMock(  # type: ignore[method-assign]
        side_effect=OSConnectionError("N/A", "connection refused", None)
    )

    with pytest.raises(OSConnectionError):
        await client.ensure_ism_policy()


async def test_ensure_generic_tenant_role_creates_one_role_and_one_mapping() -> None:
    """Verified design (poc/keycloak_opensearch_dls/): ONE org-agnostic role
    templated as ${attr.jwt.org_id}, ONE static mapping to every KronOS realm
    role — never per-org, never per-user. Replaces the old per-org
    ensure_tenant_role(org_id, org_alias), which created a role but never
    mapped anyone to it (poc/opensearch_jwt/README.md result #3).
    """
    client = _make_client()
    client._client.transport.perform_request = AsyncMock(return_value={})  # type: ignore[method-assign]

    await client.ensure_generic_tenant_role()

    assert client._client.transport.perform_request.await_count == 2
    role_call, mapping_call = client._client.transport.perform_request.await_args_list

    assert role_call.args == ("PUT", "/_plugins/_security/api/roles/kronos-generic-tenant")
    dls = role_call.kwargs["body"]["index_permissions"][0]["dls"]
    assert "${attr.jwt.org_id}" in dls
    assert role_call.kwargs["body"]["index_permissions"][0]["index_patterns"] == ["kronos-*"]

    assert mapping_call.args == (
        "PUT", "/_plugins/_security/api/rolesmapping/kronos-generic-tenant",
    )
    assert mapping_call.kwargs["body"]["backend_roles"] == [
        "org-admin", "case-lead", "analyst", "read-only",
    ]


# ============================================================================
# Regression tests for bulk_index partial failure fix (A4)
# ============================================================================
# These tests verify that bulk_index now "fails loudly" (CLAUDE.md §1.8)
# by raising StorageError on any per-document indexing failure, instead of
# silently returning a reduced count. See poc/opensearch_bulk_partial_failure/


async def test_bulk_index_empty_batch_returns_zero() -> None:
    """Empty batch should return 0 without error."""
    from src.adapter.opensearch.client import InMemoryOpenSearchClient

    client = InMemoryOpenSearchClient()
    count = await client.bulk_index([])
    assert count == 0


async def test_bulk_index_all_succeed_returns_count() -> None:
    """All documents succeed → return count, no exception."""
    from src.adapter.opensearch.client import InMemoryOpenSearchClient

    client = InMemoryOpenSearchClient()
    documents = [
        ("kronos-test", "doc-1", {"field": "value1"}),
        ("kronos-test", "doc-2", {"field": "value2"}),
        ("kronos-test", "doc-3", {"field": "value3"}),
    ]
    count = await client.bulk_index(documents)
    assert count == 3


async def test_bulk_index_partial_failure_raises_storage_error() -> None:
    """Partial failure (some docs succeed, some fail) → raise StorageError."""
    from src.exceptions import StorageError

    client = _make_client()
    # Mock the _bulk response with 1 success and 1 error (from the real PoC)
    client._client.bulk = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "took": 3,
            "errors": True,
            "items": [
                {
                    "index": {
                        "_index": "kronos-test",
                        "_id": "doc-1",
                        "status": 201,
                        "result": "created",
                    }
                },
                {
                    "index": {
                        "_index": "kronos-test",
                        "_id": "doc-2",
                        "status": 400,
                        "error": {
                            "type": "mapper_parsing_exception",
                            "reason": "failed to parse field [@timestamp]",
                        },
                    }
                },
            ],
        }
    )

    documents = [
        ("kronos-test", "doc-1", {"@timestamp": "2026-01-01T00:00:00Z"}),
        ("kronos-test", "doc-2", {"@timestamp": "invalid"}),
    ]

    with pytest.raises(StorageError) as exc_info:
        await client.bulk_index(documents)

    exc = exc_info.value
    assert "1 document(s) fail" in str(exc)
    assert exc.context["total_documents"] == 2
    assert exc.context["failed_count"] == 1
    assert exc.context["succeeded_count"] == 1
    assert len(exc.context["failed_documents"]) == 1
    assert exc.context["failed_documents"][0]["doc_id"] == "doc-2"
    assert exc.context["failed_documents"][0]["status"] == 400
    assert "mapper_parsing_exception" in str(exc.context["failed_documents"][0]["error"])


async def test_bulk_index_complete_failure_raises_storage_error() -> None:
    """All documents fail → raise StorageError with all failures in context."""
    from src.exceptions import StorageError

    client = _make_client()
    client._client.bulk = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "took": 2,
            "errors": True,
            "items": [
                {
                    "index": {
                        "_index": "kronos-test",
                        "_id": "doc-1",
                        "status": 400,
                        "error": {"type": "parsing_exception", "reason": "error1"},
                    }
                },
                {
                    "index": {
                        "_index": "kronos-test",
                        "_id": "doc-2",
                        "status": 400,
                        "error": {"type": "parsing_exception", "reason": "error2"},
                    }
                },
            ],
        }
    )

    documents = [
        ("kronos-test", "doc-1", {"data": "x"}),
        ("kronos-test", "doc-2", {"data": "y"}),
    ]

    with pytest.raises(StorageError) as exc_info:
        await client.bulk_index(documents)

    exc = exc_info.value
    assert exc.context["total_documents"] == 2
    assert exc.context["failed_count"] == 2
    assert exc.context["succeeded_count"] == 0


async def test_bulk_index_context_includes_all_failure_details() -> None:
    """Verify that the exception context includes detailed per-document errors."""
    from src.exceptions import StorageError

    client = _make_client()
    client._client.bulk = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "took": 1,
            "errors": True,
            "items": [
                {
                    "index": {
                        "_index": "kronos-org-case-123-202607",
                        "_id": "sha1:abc123",
                        "status": 400,
                        "error": {
                            "type": "mapper_parsing_exception",
                            "reason": "failed to parse field [@timestamp] with format [strict_date_time]",
                        },
                    }
                },
            ],
        }
    )

    documents = [("kronos-org-case-123-202607", "sha1:abc123", {"@timestamp": "bad"})]

    with pytest.raises(StorageError) as exc_info:
        await client.bulk_index(documents)

    failed_doc = exc_info.value.context["failed_documents"][0]
    assert failed_doc["doc_id"] == "sha1:abc123"
    assert failed_doc["index_name"] == "kronos-org-case-123-202607"
    assert failed_doc["status"] == 400
    assert failed_doc["error"]["type"] == "mapper_parsing_exception"
    assert "strict_date_time" in failed_doc["error"]["reason"]
