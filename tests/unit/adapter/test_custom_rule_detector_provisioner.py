"""Unit tests for SecurityAnalyticsCustomRuleDetectorProvisioner (mocked httpx)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.adapter.opensearch.custom_rule_detector_provisioner import (
    SecurityAnalyticsCustomRuleDetectorProvisioner,
)


def _resp(json_body: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = json_body
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


class TestSyncCustomDetector:
    @pytest.mark.asyncio
    async def test_creates_a_detector_when_none_exists(self) -> None:
        calls: list[str] = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(url)
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"hits": []}})
            if url.endswith("/detectors"):
                assert kwargs["json"]["inputs"][0]["detector_input"]["indices"] == ["kronos-acme-*"]
                assert kwargs["json"]["inputs"][0]["detector_input"]["custom_rules"] == [
                    {"id": "rule-1"}
                ]
                return _resp({"_id": "new-id"})
            raise AssertionError(url)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsCustomRuleDetectorProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.sync_custom_detector("acme", "network", ("rule-1",))

        assert any(c.endswith("/detectors") for c in calls)

    @pytest.mark.asyncio
    async def test_noop_when_desired_set_already_matches(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp(
                    {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "existing-id",
                                    "_source": {
                                        "inputs": [
                                            {
                                                "detector_input": {
                                                    "custom_rules": [
                                                        {"id": "rule-1"},
                                                        {"id": "rule-2"},
                                                    ]
                                                }
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    }
                )
            raise AssertionError(f"unexpected create/delete call: {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsCustomRuleDetectorProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.sync_custom_detector("acme", "network", ("rule-2", "rule-1"))

    @pytest.mark.asyncio
    async def test_deletes_and_recreates_when_desired_set_differs(self) -> None:
        deleted = []
        created = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp(
                    {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "existing-id",
                                    "_source": {
                                        "inputs": [
                                            {
                                                "detector_input": {
                                                    "custom_rules": [{"id": "old-rule"}]
                                                }
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    }
                )
            if url.endswith("/detectors"):
                created.append(kwargs["json"])
                return _resp({"_id": "new-id"})
            raise AssertionError(url)

        async def delete(url: str, **kwargs):  # type: ignore[no-untyped-def]
            deleted.append(url)
            return _resp({})

        with patch("httpx.AsyncClient", return_value=_make_client(post, delete)):
            provisioner = SecurityAnalyticsCustomRuleDetectorProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.sync_custom_detector("acme", "network", ("new-rule",))

        assert any("existing-id" in d for d in deleted)
        assert len(created) == 1

    @pytest.mark.asyncio
    async def test_empty_rule_set_deletes_existing_detector_without_recreating(self) -> None:
        deleted = []
        created = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp(
                    {
                        "hits": {
                            "hits": [
                                {
                                    "_id": "existing-id",
                                    "_source": {
                                        "inputs": [
                                            {
                                                "detector_input": {
                                                    "custom_rules": [{"id": "old-rule"}]
                                                }
                                            }
                                        ]
                                    },
                                }
                            ]
                        }
                    }
                )
            created.append(url)
            raise AssertionError("must not create a new detector for an empty rule set")

        async def delete(url: str, **kwargs):  # type: ignore[no-untyped-def]
            deleted.append(url)
            return _resp({})

        with patch("httpx.AsyncClient", return_value=_make_client(post, delete)):
            provisioner = SecurityAnalyticsCustomRuleDetectorProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.sync_custom_detector("acme", "network", ())

        assert any("existing-id" in d for d in deleted)
        assert created == []

    @pytest.mark.asyncio
    async def test_empty_rule_set_with_no_existing_detector_is_a_noop(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"hits": []}})
            raise AssertionError("must not touch OpenSearch further")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsCustomRuleDetectorProvisioner(
                "https://localhost:9200", "admin", "admin"
            )
            await provisioner.sync_custom_detector("acme", "network", ())  # must not raise
