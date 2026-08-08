"""Unit tests for GenericPollSource (mocked httpx.AsyncClient per CLAUDE.md
SS B.5 -- the real HTTP round trip is proven in
poc/integration_source_foundation/) (roadmap Q1)."""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest

from src.application.integration_source import IntegrationSourceError
from src.domain.integration_source import (
    IntegrationDeliveryMode,
    IntegrationSourceIdentity,
    SourceCursor,
)
from src.external.integration_sources.generic_poll import GenericPollSource
from src.external.middleware.integration_source_auth import ApiKeyOutboundAuthStrategy


def _identity() -> IntegrationSourceIdentity:
    return IntegrationSourceIdentity(
        org_id=uuid.uuid4(), source_id="s1", source_type="generic-poll", auth_method="api-key"
    )


def _mock_response(status_code: int, body: dict) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json=body,
        request=httpx.Request("GET", "https://api.example/events"),
    )


class TestGenericPollSource:
    def test_identity_properties(self) -> None:
        source = GenericPollSource(
            AsyncMock(spec=httpx.AsyncClient),
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )
        assert source.source_type == "generic-poll"
        assert source.delivery_mode == IntegrationDeliveryMode.POLL

    @pytest.mark.asyncio
    async def test_first_poll_sends_no_cursor_param(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"events": [], "next_cursor": None})
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )

        await source.poll(_identity(), None)

        params = client.get.await_args[1]["params"]
        assert "cursor" not in params

    @pytest.mark.asyncio
    async def test_subsequent_poll_sends_cursor_param(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"events": [], "next_cursor": None})
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )
        cursor = SourceCursor(
            org_id=uuid.uuid4(),
            source_id="s1",
            cursor_value="page-2-token",
            updated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        )

        await source.poll(_identity(), cursor)

        params = client.get.await_args[1]["params"]
        assert params["cursor"] == "page-2-token"

    @pytest.mark.asyncio
    async def test_events_decoded_and_next_cursor_returned(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(
            200, {"events": [{"id": 1}, {"id": 2}], "next_cursor": "page-3-token"}
        )
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )

        result = await source.poll(_identity(), None)

        assert len(result.raw_events) == 2
        assert json.loads(result.raw_events[0]) == {"id": 1}
        assert result.next_cursor == "page-3-token"

    @pytest.mark.asyncio
    async def test_empty_page_forces_next_cursor_to_none_even_if_server_echoes_one(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(
            200, {"events": [], "next_cursor": "unchanged-token"}
        )
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )

        result = await source.poll(_identity(), None)

        assert result.raw_events == []
        assert result.next_cursor is None

    @pytest.mark.asyncio
    async def test_auth_headers_are_attached_to_the_request(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"events": [], "next_cursor": None})
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("Authorization", "Bearer tok"),
        )

        await source.poll(_identity(), None)

        headers = client.get.await_args[1]["headers"]
        assert headers == {"Authorization": "Bearer tok"}

    @pytest.mark.asyncio
    async def test_non_200_response_raises_integration_source_error(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(503, {"error": "unavailable"})
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_malformed_response_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"no_events_field": True})
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_connection_error_raises_integration_source_error(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.side_effect = httpx.ConnectError("refused")
        source = GenericPollSource(
            client,
            base_url="https://api.example",
            auth_strategy=ApiKeyOutboundAuthStrategy("X-Key", "k"),
        )

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)
