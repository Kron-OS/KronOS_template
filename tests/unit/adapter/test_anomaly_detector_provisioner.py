"""Unit tests for OpenSearchAnomalyDetectorProvisioner (mocked httpx).

Mirrors tests/unit/adapter/test_detector_provisioner.py's own shape.
Real request/response shapes come from
poc/anomaly_detection_baseline/README.md's "Finding 3/4/5" and
output.txt (live OpenSearch 2.11.1 cluster).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.opensearch.anomaly_detector_provisioner import (
    AnomalyDetectorProvisioner,
    OpenSearchAnomalyDetectorProvisioner,
)


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


class TestDetectorName:
    def test_detector_name_is_org_scoped_and_sanitized(self) -> None:
        assert (
            AnomalyDetectorProvisioner.detector_name("Acme Corp")
            == "kronos-acme-corp-behavioral-ad-detector"
        )


class TestOpenSearchAnomalyDetectorProvisioner:
    @pytest.mark.asyncio
    async def test_returns_existing_detector_id_without_creating(self) -> None:
        create_attempted = False

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal create_attempted
            if url.endswith("/detectors/_search"):
                assert kwargs["json"]["query"] == {
                    "term": {"name.keyword": "kronos-acme-behavioral-ad-detector"}
                }
                return _resp({"hits": {"hits": [{"_id": "existing-id"}]}})
            if url.endswith("/_plugins/_anomaly_detection/detectors"):
                create_attempted = True
                return _resp({"_id": "should-not-be-created"}, status_code=201)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = OpenSearchAnomalyDetectorProvisioner(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            detector_id = await provisioner.ensure_org_detector("acme")

        assert detector_id == "existing-id"
        assert create_attempted is False

    @pytest.mark.asyncio
    async def test_creates_detector_with_org_scoped_index_pattern_and_event_volume_feature(
        self,
    ) -> None:
        captured_body: dict = {}

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"hits": []}})
            if url.endswith("/_plugins/_anomaly_detection/detectors"):
                captured_body.update(kwargs["json"])
                return _resp({"_id": "new-id"}, status_code=201)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = OpenSearchAnomalyDetectorProvisioner(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            detector_id = await provisioner.ensure_org_detector("acme")

        assert detector_id == "new-id"
        assert captured_body["name"] == "kronos-acme-behavioral-ad-detector"
        assert captured_body["indices"] == ["kronos-acme-*"]
        assert captured_body["time_field"] == "@timestamp"
        feature = captured_body["feature_attributes"][0]
        assert feature["aggregation_query"] == {
            "event_volume": {"value_count": {"field": "@timestamp"}}
        }
        # Tenant boundary is the index pattern, never a category_field --
        # see module docstring's "per-org scoping is INDEX PATTERN" design
        # decision. v1 does not set category_field at all.
        assert "category_field" not in captured_body

    @pytest.mark.asyncio
    async def test_returns_none_when_org_has_no_ingested_data_yet(self) -> None:
        # Real, confirmed-live error shape (README.md "Finding 3"/"Finding 4"):
        # HTTP 500 "... returning empty aggregated data ..." when the
        # org's index pattern matches no real indices/time-field mapping yet.
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"hits": []}})
            if url.endswith("/_plugins/_anomaly_detection/detectors"):
                return _resp(
                    {"error": {"reason": "Feature invalid, returning empty aggregated data: x"}},
                    status_code=500,
                )
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = OpenSearchAnomalyDetectorProvisioner(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            detector_id = await provisioner.ensure_org_detector("brand-new-org")

        assert detector_id is None

    @pytest.mark.asyncio
    async def test_returns_none_when_timestamp_field_not_yet_mapped(self) -> None:
        # Real, confirmed-live error shape from the idempotency probe: a
        # brand-new org's index pattern matches zero real indices at all.
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"hits": []}})
            if url.endswith("/_plugins/_anomaly_detection/detectors"):
                return _resp(
                    {
                        "error": {
                            "reason": "Timestamp field: (@timestamp) is not found in index mapping"
                        }
                    },
                    status_code=500,
                )
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = OpenSearchAnomalyDetectorProvisioner(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            detector_id = await provisioner.ensure_org_detector("brand-new-org")

        assert detector_id is None

    @pytest.mark.asyncio
    async def test_handles_concurrent_creation_race_honestly(self) -> None:
        # Real, confirmed-live error shape (README.md "Finding 5"): AD
        # enforces detector-name uniqueness server-side. A concurrent
        # caller winning the race is treated as success, not a failure.
        find_calls = 0

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal find_calls
            if url.endswith("/detectors/_search"):
                find_calls += 1
                if find_calls == 1:
                    return _resp({"hits": {"hits": []}})
                return _resp({"hits": {"hits": [{"_id": "raced-in-id"}]}})
            if url.endswith("/_plugins/_anomaly_detection/detectors"):
                return _resp(
                    {"error": {"reason": "detector [x] already used by detector [raced-in-id]"}},
                    status_code=500,
                )
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = OpenSearchAnomalyDetectorProvisioner(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            detector_id = await provisioner.ensure_org_detector("acme")

        assert detector_id == "raced-in-id"

    @pytest.mark.asyncio
    async def test_reraises_genuinely_unexpected_errors(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/detectors/_search"):
                return _resp({"hits": {"hits": []}})
            if url.endswith("/_plugins/_anomaly_detection/detectors"):
                return _resp({"error": {"reason": "cluster_block_exception"}}, status_code=500)
            raise AssertionError(f"unexpected URL {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            provisioner = OpenSearchAnomalyDetectorProvisioner(
                base_url="https://localhost:9200", admin_username="admin", admin_password="admin"
            )
            with pytest.raises(httpx.HTTPStatusError):
                await provisioner.ensure_org_detector("acme")
