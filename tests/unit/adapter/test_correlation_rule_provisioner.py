"""Unit tests for SecurityAnalyticsCorrelationRuleProvisioner (mocked httpx)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.adapter.opensearch.correlation_rule_provisioner import (
    CorrelationCategoryQuery,
    SecurityAnalyticsCorrelationRuleProvisioner,
)

_LEGS = (
    CorrelationCategoryQuery(category="windows", query="HostName:*"),
    CorrelationCategoryQuery(category="network", query="id.orig_h:8.8.8.8"),
)


def _resp(json_body: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = json_body
    resp.raise_for_status.return_value = None
    return resp


def _make_client(post_side_effect=None, put_side_effect=None) -> MagicMock:
    client = AsyncMock()
    if post_side_effect is not None:
        client.post.side_effect = post_side_effect
    if put_side_effect is not None:
        client.put.side_effect = put_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


class TestEnsureOrgRule:
    @pytest.mark.asyncio
    async def test_creates_a_rule_when_none_exists(self) -> None:
        created = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/correlation/rules/_search"):
                return _resp({"hits": {"hits": []}})
            if url.endswith("/correlation/rules"):
                created.append(kwargs["json"])
                return _resp({"_id": "new-id", "rule": kwargs["json"]})
            raise AssertionError(url)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsCorrelationRuleProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.ensure_org_rule("acme", "lateral-movement", _LEGS)

        assert len(created) == 1
        body = created[0]
        assert body["name"] == "kronos-acme-lateral-movement"
        # Tenant scoping computed by the provisioner, never from the caller's
        # own leg content -- both legs get the SAME kronos-{org_alias}-*
        # index pattern (roadmap invariant #3).
        assert all(leg["index"] == "kronos-acme-*" for leg in body["correlate"])
        assert body["correlate"][0]["category"] == "windows"
        assert body["correlate"][1]["category"] == "network"

    @pytest.mark.asyncio
    async def test_noop_when_desired_rule_already_current(self) -> None:
        expected_body = {
            "name": "kronos-acme-lateral-movement",
            "correlate": [
                {"index": "kronos-acme-*", "query": "HostName:*", "category": "windows"},
                {"index": "kronos-acme-*", "query": "id.orig_h:8.8.8.8", "category": "network"},
            ],
        }

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/correlation/rules/_search"):
                return _resp({"hits": {"hits": [{"_id": "existing-id", "_source": expected_body}]}})
            raise AssertionError(f"must not create/update when already current: {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsCorrelationRuleProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.ensure_org_rule("acme", "lateral-movement", _LEGS)

    @pytest.mark.asyncio
    async def test_updates_via_put_when_rule_exists_but_differs(self) -> None:
        stale_body = {
            "name": "kronos-acme-lateral-movement",
            "correlate": [
                {"index": "kronos-acme-*", "query": "HostName:old-query", "category": "windows"},
                {"index": "kronos-acme-*", "query": "id.orig_h:8.8.8.8", "category": "network"},
            ],
        }
        updated = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/correlation/rules/_search"):
                return _resp({"hits": {"hits": [{"_id": "existing-id", "_source": stale_body}]}})
            raise AssertionError(f"must PUT-update, not POST-create: {url}")

        async def put(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url.endswith("/correlation/rules/existing-id")
            updated.append(kwargs["json"])
            return _resp({"_id": "existing-id", "rule": kwargs["json"]})

        with patch("httpx.AsyncClient", return_value=_make_client(post, put)):
            provisioner = SecurityAnalyticsCorrelationRuleProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.ensure_org_rule("acme", "lateral-movement", _LEGS)

        assert len(updated) == 1
        assert updated[0]["correlate"][0]["query"] == "HostName:*"

    @pytest.mark.asyncio
    async def test_rule_name_derived_from_org_alias_and_scenario_name(self) -> None:
        created = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/correlation/rules/_search"):
                return _resp({"hits": {"hits": []}})
            created.append(kwargs["json"]["name"])
            return _resp({"_id": "new-id"})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsCorrelationRuleProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.ensure_org_rule("other-org", "scenario-x", _LEGS)

        assert created == ["kronos-other-org-scenario-x"]
