"""Unit tests for SecurityAnalyticsCustomRuleClient (mocked httpx)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.opensearch.custom_rule_client import SecurityAnalyticsCustomRuleClient


def _resp(json_body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError("error", request=MagicMock(), response=resp)
    else:
        resp.raise_for_status.return_value = None
    return resp


def _make_client(post_side_effect=None, delete_side_effect=None) -> MagicMock:
    client = AsyncMock()
    if post_side_effect is not None:
        client.post.side_effect = post_side_effect
    if delete_side_effect is not None:
        client.delete.side_effect = delete_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


class TestCreateRule:
    @pytest.mark.asyncio
    async def test_returns_the_opensearch_assigned_id(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url.endswith("/_plugins/_security_analytics/rules")
            assert kwargs["params"] == {"category": "network"}
            assert kwargs["content"] == b"sigma: yaml"
            return _resp({"_id": "real-generated-id"}, status_code=201)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            client = SecurityAnalyticsCustomRuleClient("https://localhost:9200", "admin", "admin")
            result = await client.create_rule("sigma: yaml", "network")

        assert result == "real-generated-id"


class TestDeleteRule:
    @pytest.mark.asyncio
    async def test_deletes_without_a_category_param(self) -> None:
        async def delete(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url.endswith("/_plugins/_security_analytics/rules/rule-1")
            assert "params" not in kwargs
            return _resp({}, status_code=200)

        with patch("httpx.AsyncClient", return_value=_make_client(delete_side_effect=delete)):
            client = SecurityAnalyticsCustomRuleClient("https://localhost:9200", "admin", "admin")
            await client.delete_rule("rule-1")

    @pytest.mark.asyncio
    async def test_deleting_an_already_gone_rule_is_not_an_error(self) -> None:
        async def delete(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({}, status_code=404)

        with patch("httpx.AsyncClient", return_value=_make_client(delete_side_effect=delete)):
            client = SecurityAnalyticsCustomRuleClient("https://localhost:9200", "admin", "admin")
            await client.delete_rule("already-gone")  # must not raise
