"""Unit tests for WebhookTicketingSystem (mocked httpx, roadmap M7/H4).

Mirrors test_keycloak_admin_client.py's own httpx-mocking idiom. Response
shapes asserted here (2xx with a real ``ticket_id``/``url`` JSON body) were
independently confirmed against a REAL local HTTP receiver first -- see
poc/detection_ticket_integration/.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.ticketing.ticketing_system import WebhookTicketingSystem
from src.exceptions import TicketingError


def _resp(status_code: int, json_body: object = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = text
    return resp


def _make_client(post_side_effect) -> MagicMock:
    client = AsyncMock()
    client.post.side_effect = post_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


class TestWebhookTicketingSystemCreateTicket:
    @pytest.mark.asyncio
    async def test_201_with_ticket_id_returns_real_ticket_ref(self) -> None:
        async def post(url, json, **kwargs):  # type: ignore[no-untyped-def]
            assert url == "http://localhost:9999/webhook"
            assert json["event"] == "kronos.ticket.create"
            assert json["title"] == "t"
            return _resp(201, {"ticket_id": "TICKET-1", "url": "http://itsm.invalid/TICKET-1"})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            system = WebhookTicketingSystem("http://localhost:9999/webhook")
            ref = await system.create_ticket(
                title="t", description="d", severity="high", metadata={"k": "v"}
            )

        assert ref.ticket_id == "TICKET-1"
        assert ref.url == "http://itsm.invalid/TICKET-1"

    @pytest.mark.asyncio
    async def test_200_without_url_field_is_still_valid(self) -> None:
        async def post(url, json, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"ticket_id": "TICKET-2"})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            system = WebhookTicketingSystem("http://localhost:9999/webhook")
            ref = await system.create_ticket(title="t", description="d", severity=None, metadata={})

        assert ref.ticket_id == "TICKET-2"
        assert ref.url is None

    @pytest.mark.asyncio
    async def test_non_2xx_raises_ticketing_error(self) -> None:
        async def post(url, json, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(500, text="internal error")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            system = WebhookTicketingSystem("http://localhost:9999/webhook")
            with pytest.raises(TicketingError):
                await system.create_ticket(title="t", description="d", severity=None, metadata={})

    @pytest.mark.asyncio
    async def test_missing_ticket_id_in_2xx_body_raises_never_fabricates(self) -> None:
        async def post(url, json, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"status": "ok"})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            system = WebhookTicketingSystem("http://localhost:9999/webhook")
            with pytest.raises(TicketingError):
                await system.create_ticket(title="t", description="d", severity=None, metadata={})

    @pytest.mark.asyncio
    async def test_non_json_body_raises_ticketing_error(self) -> None:
        async def post(url, json, **kwargs):  # type: ignore[no-untyped-def]
            resp = _resp(200, text="not json")
            resp.json.side_effect = ValueError("no JSON object could be decoded")
            return resp

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            system = WebhookTicketingSystem("http://localhost:9999/webhook")
            with pytest.raises(TicketingError):
                await system.create_ticket(title="t", description="d", severity=None, metadata={})

    @pytest.mark.asyncio
    async def test_unreachable_backend_raises_ticketing_error_not_silent(self) -> None:
        async def post(url, json, **kwargs):  # type: ignore[no-untyped-def]
            raise httpx.ConnectError("connection refused")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            system = WebhookTicketingSystem("http://localhost:9999/webhook")
            with pytest.raises(TicketingError):
                await system.create_ticket(title="t", description="d", severity=None, metadata={})


class TestWebhookTicketingSystemUpdateTicket:
    @pytest.mark.asyncio
    async def test_update_posts_correct_envelope_and_returns_ref(self) -> None:
        async def post(url, json, **kwargs):  # type: ignore[no-untyped-def]
            assert json["event"] == "kronos.ticket.update"
            assert json["ticket_id"] == "TICKET-1"
            assert json["note"] == "n"
            return _resp(200, {"ticket_id": "TICKET-1"})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            system = WebhookTicketingSystem("http://localhost:9999/webhook")
            ref = await system.update_ticket("TICKET-1", note="n", metadata={})

        assert ref.ticket_id == "TICKET-1"
