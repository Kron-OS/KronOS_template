"""Unit tests for OpenSearchIsmLifecycleManager (mocked httpx)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.opensearch.ism_manager import OpenSearchIsmLifecycleManager
from src.exceptions import StorageError


def _resp(json_body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = str(json_body)
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError("error", request=MagicMock(), response=resp)
    else:
        resp.raise_for_status.return_value = None
    return resp


def _make_client(post_side_effect=None, get_side_effect=None) -> MagicMock:
    client = AsyncMock()
    if post_side_effect is not None:
        client.post.side_effect = post_side_effect
    if get_side_effect is not None:
        client.get.side_effect = get_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


class TestEnsureManaged:
    @pytest.mark.asyncio
    async def test_calls_remove_then_add_unconditionally(self) -> None:
        calls: list[str] = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(url)
            if url.endswith("/remove/idx1"):
                return _resp({"updated_indices": 1, "failures": False})
            if url.endswith("/add/idx1"):
                return _resp({"updated_indices": 1, "failures": False})
            raise AssertionError(f"unexpected {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            await manager.ensure_managed("idx1", "kronos-rollover")

        assert calls == [
            "https://localhost:9200/_plugins/_ism/remove/idx1",
            "https://localhost:9200/_plugins/_ism/add/idx1",
        ]

    @pytest.mark.asyncio
    async def test_raises_storage_error_when_body_reports_failure_despite_200(self) -> None:
        """The real bug this method exists to catch: HTTP 200 with
        failures=true in the body (confirmed against the live OpenSearch
        2.11.1 cluster in poc/ism_tiering_legal_hold/)."""

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            if url.endswith("/remove/idx1"):
                return _resp({"updated_indices": 1, "failures": False})
            if url.endswith("/add/idx1"):
                return _resp(
                    {
                        "updated_indices": 0,
                        "failures": True,
                        "failed_indices": [{"index_name": "idx1", "reason": "still broken"}],
                    }
                )
            raise AssertionError(f"unexpected {url}")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            with pytest.raises(StorageError):
                await manager.ensure_managed("idx1", "kronos-rollover")


class TestPlaceAndReleaseLegalHold:
    @pytest.mark.asyncio
    async def test_place_legal_hold_calls_remove(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url.endswith("/_plugins/_ism/remove/held-index")
            return _resp({"updated_indices": 1, "failures": False})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            await manager.place_legal_hold("held-index")

    @pytest.mark.asyncio
    async def test_place_legal_hold_raises_on_body_failure(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({"updated_indices": 0, "failures": True, "failed_indices": []})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            with pytest.raises(StorageError):
                await manager.place_legal_hold("held-index")

    @pytest.mark.asyncio
    async def test_release_legal_hold_reuses_ensure_managed(self) -> None:
        calls: list[str] = []

        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(url)
            return _resp({"updated_indices": 1, "failures": False})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            await manager.release_legal_hold("held-index", "kronos-rollover")

        assert calls == [
            "https://localhost:9200/_plugins/_ism/remove/held-index",
            "https://localhost:9200/_plugins/_ism/add/held-index",
        ]


class TestResolveIndices:
    @pytest.mark.asyncio
    async def test_returns_real_index_names_from_resolve_api(self) -> None:
        async def get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            assert url.endswith("/_resolve/index/kronos-acme-case-1-*")
            return _resp({"indices": [{"name": "kronos-acme-case-1-202607"}, {"name": "kronos-acme-case-1-202608"}]})

        with patch("httpx.AsyncClient", return_value=_make_client(get_side_effect=get)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            names = await manager.resolve_indices("kronos-acme-case-1-*")

        assert names == ["kronos-acme-case-1-202607", "kronos-acme-case-1-202608"]


class TestIsManagedAndEnabled:
    @pytest.mark.asyncio
    async def test_true_when_a_matching_managed_index_doc_is_enabled(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({"hits": {"hits": [{"_source": {"managed_index": {"name": "idx1", "enabled": True}}}]}})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            assert await manager.is_managed_and_enabled("idx1") is True

    @pytest.mark.asyncio
    async def test_false_when_no_managed_index_doc_exists(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({"hits": {"hits": []}})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            assert await manager.is_managed_and_enabled("idx1") is False

    @pytest.mark.asyncio
    async def test_false_when_matching_doc_is_disabled(self) -> None:
        async def post(url: str, **kwargs):  # type: ignore[no-untyped-def]
            return _resp({"hits": {"hits": [{"_source": {"managed_index": {"name": "idx1", "enabled": False}}}]}})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            manager = OpenSearchIsmLifecycleManager("https://localhost:9200", "admin", "admin")
            assert await manager.is_managed_and_enabled("idx1") is False
