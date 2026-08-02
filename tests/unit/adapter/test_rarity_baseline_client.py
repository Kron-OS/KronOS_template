"""Unit tests for OpenSearchRarityBaselineClient (mocked httpx).

Mirrors tests/unit/adapter/test_correlation_client.py's own shape exactly.
Real captured request/response shapes come from
poc/rarity_baseline_scoring/output.txt (live OpenSearch 2.11.1 cluster).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.opensearch.rarity_baseline_client import OpenSearchRarityBaselineClient


def _resp(json_body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _make_client(post_side_effect) -> MagicMock:
    client = AsyncMock()
    client.post.side_effect = post_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


# Real response shape captured against the live 2.11.1 cluster --
# poc/rarity_baseline_scoring/output.txt "Scenario 1" (small skewed sample:
# svchost.exe x5, mimikatz.exe x1, cobalt.exe x1).
_REAL_RESPONSE = {
    "took": 22,
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    "hits": {"total": {"value": 7, "relation": "eq"}, "max_score": None, "hits": []},
    "aggregations": {
        "distinct_value_count": {"value": 3},
        "value_frequency": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [
                {
                    "key": "cobalt.exe",
                    "doc_count": 1,
                    "first_seen": {
                        "value": 1784170800000.0,
                        "value_as_string": "2026-07-16T03:00:00.000Z",
                    },
                    "last_seen": {
                        "value": 1784170800000.0,
                        "value_as_string": "2026-07-16T03:00:00.000Z",
                    },
                },
                {
                    "key": "mimikatz.exe",
                    "doc_count": 1,
                    "first_seen": {
                        "value": 1784084400000.0,
                        "value_as_string": "2026-07-15T03:00:00.000Z",
                    },
                    "last_seen": {
                        "value": 1784084400000.0,
                        "value_as_string": "2026-07-15T03:00:00.000Z",
                    },
                },
                {
                    "key": "svchost.exe",
                    "doc_count": 5,
                    "first_seen": {
                        "value": 1783641600000.0,
                        "value_as_string": "2026-07-10T00:00:00.000Z",
                    },
                    "last_seen": {
                        "value": 1783987200000.0,
                        "value_as_string": "2026-07-14T00:00:00.000Z",
                    },
                },
            ],
        },
    },
}

# Real, confirmed shape when a wildcard index_pattern matches ZERO real
# indices -- "aggregations" is absent entirely, not an empty dict
# (poc/rarity_baseline_scoring/output.txt "Scenario 3").
_REAL_RESPONSE_NO_MATCHING_INDICES = {
    "took": 0,
    "timed_out": False,
    "_shards": {"total": 0, "successful": 0, "skipped": 0, "failed": 0},
    "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": 0.0, "hits": []},
}


class TestOpenSearchRarityBaselineClient:
    @pytest.mark.asyncio
    async def test_fetch_field_aggregation_builds_real_ascending_terms_query(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url == "https://localhost:9200/kronos-testorg-*/_search"
            body = kwargs["json"]
            assert body["size"] == 0
            assert body["track_total_hits"] is True
            assert body["query"] == {
                "range": {"@timestamp": {"gte": 1000, "lt": 2000, "format": "epoch_millis"}}
            }
            terms = body["aggs"]["value_frequency"]["terms"]
            # Ascending order is the entire point (see module docstring's
            # real, confirmed "ordering gap" finding) -- must never regress
            # to the OpenSearch default (descending).
            assert terms["order"] == {"_count": "asc"}
            assert terms["size"] == 50
            assert terms["field"] == "process.name"
            assert body["aggs"]["distinct_value_count"] == {
                "cardinality": {"field": "process.name"}
            }
            sub_aggs = body["aggs"]["value_frequency"]["aggs"]
            assert sub_aggs["first_seen"] == {"min": {"field": "@timestamp"}}
            assert sub_aggs["last_seen"] == {"max": {"field": "@timestamp"}}
            return _resp(_REAL_RESPONSE)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            client = OpenSearchRarityBaselineClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            result = await client.fetch_field_aggregation(
                "kronos-testorg-*", "process.name", 1000, 2000, max_distinct_values=50
            )

        assert result == _REAL_RESPONSE

    @pytest.mark.asyncio
    async def test_fetch_field_aggregation_passes_through_missing_aggregations_key(self) -> None:
        # Real, confirmed behavior: a wildcard pattern matching zero
        # indices returns 200 with no "aggregations" key at all -- this
        # class must not paper over that; it's the parsing layer's job.
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(_REAL_RESPONSE_NO_MATCHING_INDICES)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            client = OpenSearchRarityBaselineClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            result = await client.fetch_field_aggregation(
                "kronos-brand-new-org-*", "process.name", 0, 1, max_distinct_values=50
            )

        assert "aggregations" not in result
        assert result["hits"]["total"]["value"] == 0

    @pytest.mark.asyncio
    async def test_raises_on_http_error(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({"error": "boom"}, status_code=500)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            client = OpenSearchRarityBaselineClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            with pytest.raises(httpx.HTTPStatusError):
                await client.fetch_field_aggregation(
                    "kronos-testorg-*", "process.name", 0, 1, max_distinct_values=50
                )
