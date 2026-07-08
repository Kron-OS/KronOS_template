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
