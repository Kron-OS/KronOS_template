"""Unit tests for DefenderPollSource (mocked httpx.AsyncClient per CLAUDE.md
SS B.5 -- the real HTTP round trip, real OAuth2 token exchange, real
pagination, and real Postgres cursor persistence are proven in
poc/integration_source_defender/) (roadmap Q4).

Fixture alert shapes mirror the real ``alert`` resource fields captured in
that PoC's own output (in turn verified against Microsoft's own documented
resource shape -- see that PoC's README.md for doc URLs)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest

from src.application.integration_source import IntegrationSourceError
from src.domain.integration_source import (
    IntegrationDeliveryMode,
    IntegrationSourceIdentity,
    SourceCursor,
)
from src.external.integration_sources.defender import DefenderPollSource
from src.external.middleware.integration_source_auth import ApiKeyOutboundAuthStrategy


def _identity() -> IntegrationSourceIdentity:
    return IntegrationSourceIdentity(
        org_id=uuid.uuid4(),
        source_id="defender-1",
        source_type="ms-defender-alerts",
        auth_method="oauth2-client-credentials",
    )


def _cursor(value: str) -> SourceCursor:
    return SourceCursor(
        org_id=uuid.uuid4(),
        source_id="defender-1",
        cursor_value=value,
        updated_at=datetime.now(UTC),
    )


def _alert(alert_id: str, last_update: str) -> dict:
    return {
        "@odata.type": "#microsoft.graph.security.alert",
        "id": alert_id,
        "providerAlertId": alert_id,
        "status": "new",
        "severity": "medium",
        "classification": "unknown",
        "determination": "unknown",
        "serviceSource": "microsoftDefenderForEndpoint",
        "title": "Suspicious execution",
        "createdDateTime": last_update,
        "lastUpdateDateTime": last_update,
        "evidence": [],
        "categories": [],
        "mitreTechniques": [],
    }


def _mock_response(status_code: int, body: dict) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json=body,
        request=httpx.Request("GET", "https://graph.microsoft.com/v1.0/security/alerts_v2"),
    )


def _source(client: AsyncMock) -> DefenderPollSource:
    return DefenderPollSource(
        client,
        base_url="https://graph.example/v1.0",
        auth_strategy=ApiKeyOutboundAuthStrategy("Authorization", "Bearer tok"),
    )


class TestDefenderPollSource:
    def test_identity_properties(self) -> None:
        source = _source(AsyncMock(spec=httpx.AsyncClient))
        assert source.source_type == "ms-defender-alerts"
        assert source.source_version == "1.0.0"
        assert source.delivery_mode == IntegrationDeliveryMode.POLL

    @pytest.mark.asyncio
    async def test_first_poll_sends_no_filter_param(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"value": []})
        source = _source(client)

        await source.poll(_identity(), None)

        params = client.get.await_args.kwargs["params"]
        assert params is None

    @pytest.mark.asyncio
    async def test_subsequent_poll_sends_lastupdatedatetime_filter(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"value": []})
        source = _source(client)

        await source.poll(_identity(), _cursor("2026-08-01T00:15:00.0000000Z"))

        params = client.get.await_args.kwargs["params"]
        assert params == {"$filter": "lastUpdateDateTime gt 2026-08-01T00:15:00.0000000Z"}

    @pytest.mark.asyncio
    async def test_alerts_decoded_into_raw_events(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(
            200,
            {
                "value": [
                    _alert("a1", "2026-08-01T00:00:00.0000000Z"),
                    _alert("a2", "2026-08-01T00:05:00.0000000Z"),
                ]
            },
        )
        source = _source(client)

        result = await source.poll(_identity(), None)

        assert len(result.raw_events) == 2
        assert json.loads(result.raw_events[0])["id"] == "a1"
        assert json.loads(result.raw_events[1])["id"] == "a2"

    @pytest.mark.asyncio
    async def test_next_cursor_is_max_lastupdatedatetime_not_last_processed(self) -> None:
        """The newest alert by real datetime value, not by list/page order,
        must become the cursor -- a page whose alerts arrive out of
        chronological order must not silently regress the watermark."""
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(
            200,
            {
                "value": [
                    _alert("newer", "2026-08-05T00:00:00.0000000Z"),
                    _alert("older", "2026-08-01T00:00:00.0000000Z"),
                ]
            },
        )
        source = _source(client)

        result = await source.poll(_identity(), None)

        assert result.next_cursor == "2026-08-05T00:00:00.0000000Z"

    @pytest.mark.asyncio
    async def test_empty_page_forces_next_cursor_to_none(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"value": []})
        source = _source(client)

        result = await source.poll(_identity(), None)

        assert result.raw_events == []
        assert result.next_cursor is None

    @pytest.mark.asyncio
    async def test_follows_odata_next_link_across_multiple_pages(self) -> None:
        page1 = _mock_response(
            200,
            {
                "value": [_alert("a1", "2026-08-01T00:00:00.0000000Z")],
                "@odata.nextLink": "https://graph.example/v1.0/security/alerts_v2?$skip=1",
            },
        )
        page2 = _mock_response(200, {"value": [_alert("a2", "2026-08-01T00:05:00.0000000Z")]})
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.side_effect = [page1, page2]
        source = _source(client)

        result = await source.poll(_identity(), None)

        assert len(result.raw_events) == 2
        assert result.next_cursor == "2026-08-01T00:05:00.0000000Z"
        # Second call must hit the exact nextLink URL, with no re-attached
        # params -- Microsoft's own paging docs require using the whole
        # returned URL verbatim.
        second_call = client.get.await_args_list[1]
        assert second_call.args[0] == "https://graph.example/v1.0/security/alerts_v2?$skip=1"
        assert second_call.kwargs["params"] is None

    @pytest.mark.asyncio
    async def test_pagination_exceeding_max_pages_with_real_backlog_truncates_and_returns_partial(
        self,
    ) -> None:
        """A real, legitimate backlog larger than the 50-page cap must not be
        discarded: poll() should stop paginating, log a warning, and return
        the partial-but-valid result (events fetched so far + the newest
        watermark seen) exactly like a clean success -- so the caller
        (``run_poll_cycle``) persists the advanced cursor and the *next*
        poll cycle drains the next slice of backlog incrementally."""
        timestamps = [
            (datetime(2026, 8, 1, tzinfo=UTC) + timedelta(minutes=i)).strftime(
                "%Y-%m-%dT%H:%M:%S.0000000Z"
            )
            for i in range(50)
        ]
        next_link_base = "https://graph.example/v1.0/security/alerts_v2"
        pages = [
            _mock_response(
                200,
                {
                    "value": [_alert(f"a{i}", timestamps[i])],
                    "@odata.nextLink": f"{next_link_base}?$skip={i + 1}",
                },
            )
            for i in range(50)
        ]
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.side_effect = pages
        source = _source(client)

        result = await source.poll(_identity(), None)

        assert len(result.raw_events) == 50
        assert result.next_cursor == timestamps[-1]
        # Pagination stopped at the cap -- the 51st page (which would have
        # been requested via that last page's own nextLink) is never fetched.
        assert client.get.await_count == 50

    @pytest.mark.asyncio
    async def test_pagination_exceeding_max_pages_with_zero_progress_raises(self) -> None:
        """If the entire capped run produces zero real alerts, that is not a
        legitimate backlog (a real backlog still yields real alerts on every
        page) -- it looks like a malformed/looping response, so this must
        still fail loudly rather than being silently truncated."""
        looping_page = _mock_response(
            200,
            {
                "value": [],
                "@odata.nextLink": "https://graph.example/v1.0/security/alerts_v2?$skip=999",
            },
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = looping_page  # same response forever -> infinite nextLink loop
        source = _source(client)

        with pytest.raises(IntegrationSourceError, match="without fetching a single alert"):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_auth_headers_are_attached(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"value": []})
        source = _source(client)

        await source.poll(_identity(), None)

        headers = client.get.await_args.kwargs["headers"]
        assert headers == {"Authorization": "Bearer tok"}

    @pytest.mark.asyncio
    async def test_non_200_response_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(
            401, {"error": {"code": "InvalidAuthenticationToken"}}
        )
        source = _source(client)

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_missing_value_key_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"no_value_field": True})
        source = _source(client)

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_value_not_a_list_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"value": "not-a-list"})
        source = _source(client)

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_alert_entry_not_an_object_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(200, {"value": ["not-an-object"]})
        source = _source(client)

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_alert_missing_required_field_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(
            200, {"value": [{"id": "a1"}]}  # missing lastUpdateDateTime
        )
        source = _source(client)

        with pytest.raises(IntegrationSourceError, match="missing required"):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_alert_with_malformed_lastupdatedatetime_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.return_value = _mock_response(
            200, {"value": [_alert("a1", "not-a-real-timestamp")]}
        )
        source = _source(client)

        with pytest.raises(IntegrationSourceError, match="malformed lastUpdateDateTime"):
            await source.poll(_identity(), None)

    @pytest.mark.asyncio
    async def test_connection_error_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get.side_effect = httpx.ConnectError("refused")
        source = _source(client)

        with pytest.raises(IntegrationSourceError):
            await source.poll(_identity(), None)
