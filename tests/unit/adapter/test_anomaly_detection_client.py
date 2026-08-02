"""Unit tests for OpenSearchAnomalyDetectionResultsClient (mocked httpx).

Mirrors tests/unit/adapter/test_rarity_baseline_client.py's own shape.
Real captured request/response shapes come from
poc/anomaly_detection_baseline/output.txt (live OpenSearch 2.11.1 cluster).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.opensearch.anomaly_detection_client import OpenSearchAnomalyDetectionResultsClient


def _resp(json_body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = str(json_body)
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


# Real, captured result shape (poc/anomaly_detection_baseline/output.txt --
# the top-ranked host-anomalous result from the real historical-analysis run).
_REAL_RESULT = {
    "detector_id": "gcyzxJ8BG52zb-VT4nvS",
    "task_id": "kMyzxJ8BG52zb-VT43sT",
    "anomaly_grade": 1.0,
    "confidence": 0.8801892438983826,
    "anomaly_score": 6.836714971409553,
    "feature_data": [
        {"feature_id": "h8yzxJ8BG52zb-VT4nvw", "feature_name": "avg_bytes_out", "data": 8040.0}
    ],
    "expected_values": [
        {
            "likelihood": 1.0,
            "value_list": [{"feature_id": "h8yzxJ8BG52zb-VT4nvw", "data": 99.95229047436086}],
        }
    ],
    "entity": [{"name": "host.name", "value": "host-anomalous"}],
    "data_start_time": 1785709740000,
    "data_end_time": 1785709800000,
}

_REAL_RESPONSE = {
    "took": 3,
    "timed_out": False,
    "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_source": _REAL_RESULT}]},
}


class TestOpenSearchAnomalyDetectionResultsClient:
    @pytest.mark.asyncio
    async def test_search_results_uses_the_dedicated_plugin_endpoint(self) -> None:
        # Real, load-bearing gap this class exists to route around
        # (README.md "Finding 2"): the raw dot-index is silently
        # unreadable via ordinary _search, even as admin. This must
        # always hit the plugin's own dedicated results endpoint.
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert (
                url
                == "https://localhost:9200/_plugins/_anomaly_detection/detectors/results/_search"
            )
            assert "/.opendistro-anomaly-results" not in url
            return _resp(_REAL_RESPONSE)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            client = OpenSearchAnomalyDetectionResultsClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            result = await client.search_results(detector_id="gcyzxJ8BG52zb-VT4nvS")

        assert result == _REAL_RESPONSE

    @pytest.mark.asyncio
    async def test_search_results_filters_by_detector_id_and_min_grade(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            body = kwargs["json"]
            assert body["query"]["bool"]["filter"] == [
                {"term": {"detector_id": "det-1"}},
                {"range": {"anomaly_grade": {"gt": 0.5}}},
            ]
            assert body["sort"] == [{"anomaly_grade": "desc"}, {"data_end_time": "desc"}]
            assert body["size"] == 200
            return _resp(_REAL_RESPONSE)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            client = OpenSearchAnomalyDetectionResultsClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            await client.search_results(detector_id="det-1", min_grade=0.5, size=200)

    @pytest.mark.asyncio
    async def test_raises_on_http_error(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({"error": "boom"}, status_code=500)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            client = OpenSearchAnomalyDetectionResultsClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            with pytest.raises(httpx.HTTPStatusError):
                await client.search_results(detector_id="det-1")
