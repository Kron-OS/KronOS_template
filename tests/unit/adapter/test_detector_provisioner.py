"""Unit tests for SecurityAnalyticsDetectorProvisioner (mocked httpx)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.opensearch.detector_provisioner import (
    SecurityAnalyticsDetectorProvisioner,
    get_default_log_types,
)


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


class TestGetDefaultLogTypes:
    def test_returns_the_three_c1_verified_log_types(self) -> None:
        assert get_default_log_types() == ("windows", "cloudtrail", "network")


class TestSecurityAnalyticsDetectorProvisioner:
    @pytest.mark.asyncio
    async def test_creates_a_detector_per_log_type_when_none_exist(self) -> None:
        calls: list[str] = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(url)
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"total": {"value": 0}}})
            if url.endswith("/rules/_search"):
                return _resp({"hits": {"hits": [{"_id": "rule-1"}, {"_id": "rule-2"}]}})
            if url.endswith("/detectors"):
                return _resp({"_id": "new-detector-id"}, status_code=201)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsDetectorProvisioner(
                base_url="https://localhost:9200",
                admin_username="admin",
                admin_password="admin",
                log_types=("windows", "network"),
            )
            await provisioner.ensure_org_detectors("acme")

        create_calls = [c for c in calls if c.endswith("/detectors")]
        assert len(create_calls) == 2  # one per log type

    @pytest.mark.asyncio
    async def test_idempotent_skips_creation_when_detector_already_exists(self) -> None:
        create_attempted = False

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal create_attempted
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"total": {"value": 1}}})
            if url.endswith("/detectors"):
                create_attempted = True
                return _resp({"_id": "should-not-be-created"}, status_code=201)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsDetectorProvisioner(
                base_url="https://localhost:9200",
                admin_username="admin",
                admin_password="admin",
                log_types=("windows",),
            )
            await provisioner.ensure_org_detectors("acme")

        assert create_attempted is False

    @pytest.mark.asyncio
    async def test_skips_log_type_with_no_available_rules(self) -> None:
        create_attempted = False

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal create_attempted
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"total": {"value": 0}}})
            if url.endswith("/rules/_search"):
                return _resp({"hits": {"hits": []}})
            if url.endswith("/detectors"):
                create_attempted = True
                return _resp({}, status_code=201)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsDetectorProvisioner(
                base_url="https://localhost:9200",
                admin_username="admin",
                admin_password="admin",
                log_types=("windows",),
            )
            await provisioner.ensure_org_detectors("acme")

        assert create_attempted is False

    @pytest.mark.asyncio
    async def test_one_log_type_failure_does_not_block_the_others(self) -> None:
        created_for: list[str] = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            body = kwargs.get("json", {})
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"total": {"value": 0}}})
            if url.endswith("/rules/_search"):
                # Fail the rule lookup for "network" specifically.
                query = str(body)
                if "network" in query:
                    return _resp({"error": "boom"}, status_code=500)
                return _resp({"hits": {"hits": [{"_id": "rule-1"}]}})
            if url.endswith("/detectors"):
                created_for.append(body["detector_type"])
                return _resp({"_id": "id"}, status_code=201)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsDetectorProvisioner(
                base_url="https://localhost:9200",
                admin_username="admin",
                admin_password="admin",
                log_types=("windows", "network", "cloudtrail"),
            )
            # Must not raise even though "network" fails.
            await provisioner.ensure_org_detectors("acme")

        assert set(created_for) == {"windows", "cloudtrail"}

    @pytest.mark.asyncio
    async def test_detector_name_is_org_and_log_type_scoped(self) -> None:
        captured_bodies: list[dict] = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"total": {"value": 0}}})
            if url.endswith("/rules/_search"):
                return _resp({"hits": {"hits": [{"_id": "rule-1"}]}})
            if url.endswith("/detectors"):
                captured_bodies.append(kwargs["json"])
                return _resp({"_id": "id"}, status_code=201)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = SecurityAnalyticsDetectorProvisioner(
                base_url="https://localhost:9200",
                admin_username="admin",
                admin_password="admin",
                log_types=("windows",),
            )
            await provisioner.ensure_org_detectors("acme-corp")

        assert len(captured_bodies) == 1
        body = captured_bodies[0]
        assert body["name"] == "kronos-acme-corp-windows-detector"
        assert body["inputs"][0]["detector_input"]["indices"] == ["kronos-acme-corp-*"]
