"""Unit tests for SecurityAnalyticsCorrelationClient (mocked httpx)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.opensearch.correlation_client import SecurityAnalyticsCorrelationClient


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


def _make_client(get_side_effect) -> MagicMock:
    client = AsyncMock()
    client.get.side_effect = get_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


class TestSecurityAnalyticsCorrelationClient:
    @pytest.mark.asyncio
    async def test_fetch_correlations_returns_real_shaped_pairs(self) -> None:
        # Real shape confirmed against the live 2.11.1 cluster --
        # poc/security_analytics_correlation/output.txt Part 4.
        real_pairs = [
            {
                "finding1": "07b271dc-15b1-410f-a4ee-1ef49afb8a2b",
                "logType1": "network",
                "finding2": "983d593c-a788-46e9-a101-27db87d86eab",
                "logType2": "network",
                "rules": ["DMyUwp8BG52zb-VTmXZK"],
            }
        ]

        async def get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url.endswith("/_plugins/_security_analytics/correlations")
            assert kwargs["params"] == {"start_timestamp": 1000, "end_timestamp": 2000}
            return _resp({"findings": real_pairs})

        with patch("httpx.AsyncClient", return_value=_make_client(get)):
            client = SecurityAnalyticsCorrelationClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            result = await client.fetch_correlations(1000, 2000)

        assert result == real_pairs

    @pytest.mark.asyncio
    async def test_fetch_correlations_empty_when_no_findings_key(self) -> None:
        async def get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({})

        with patch("httpx.AsyncClient", return_value=_make_client(get)):
            client = SecurityAnalyticsCorrelationClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            result = await client.fetch_correlations(0, 1)

        assert result == []

    @pytest.mark.asyncio
    async def test_raises_on_http_error(self) -> None:
        async def get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({"error": "boom"}, status_code=500)

        with patch("httpx.AsyncClient", return_value=_make_client(get)):
            client = SecurityAnalyticsCorrelationClient(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            with pytest.raises(httpx.HTTPStatusError):
                await client.fetch_correlations(0, 1)
