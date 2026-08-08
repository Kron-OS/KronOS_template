"""Unit tests for HttpJsonIntegrationSink (mocked httpx, roadmap R1).

Response shapes asserted here (2xx with a real "accepted" count JSON body)
were independently confirmed against a REAL local HTTP receiver first --
see poc/integration_sink_foundation/. Mirrors test_ticketing_system.py's
own httpx-mocking idiom exactly.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.integration_sink.http_json_sink import HttpJsonIntegrationSink
from src.adapter.integration_sink.sink_authenticator import (
    NullAuthenticator,
    StaticTokenAuthenticator,
)
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAckStatus
from src.exceptions import IntegrationSinkError


def _resp(status_code: int, json_body: object = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = text
    return resp


def _make_client(post_side_effect) -> MagicMock:  # type: ignore[no-untyped-def]
    client = AsyncMock()
    client.post.side_effect = post_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


def _events(n: int) -> list[MappedSinkEvent]:
    return [MappedSinkEvent(source_detection_id=str(i), payload={"i": i}) for i in range(n)]


class TestHttpJsonIntegrationSinkSuccess:
    @pytest.mark.asyncio
    async def test_2xx_with_matching_accepted_count_returns_acknowledged(self) -> None:
        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            assert url == "http://localhost:9999/hec"
            assert json == {"events": [{"i": 0}, {"i": 1}]}
            return _resp(200, {"text": "Success", "code": 0, "accepted": 2})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
            ack = await sink.push_events(_events(2))

        assert ack.status == SinkAckStatus.ACKNOWLEDGED
        assert ack.detail["status_code"] == 200
        assert ack.detail["accepted"] == 2

    @pytest.mark.asyncio
    async def test_auth_headers_applied_to_the_real_request(self) -> None:
        seen_headers = {}

        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            seen_headers.update(headers)
            return _resp(200, {"accepted": 1})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink(
                "http://localhost:9999/hec", StaticTokenAuthenticator("tok", scheme="Splunk")
            )
            await sink.push_events(_events(1))

        assert seen_headers == {"Authorization": "Splunk tok"}

    @pytest.mark.asyncio
    async def test_prepare_called_before_every_push_supports_refreshable_auth(self) -> None:
        fake_authenticator = AsyncMock()
        fake_authenticator.prepare.return_value = MagicMock(headers={}, cert=None, verify=True)

        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"accepted": 1})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink("http://localhost:9999/hec", fake_authenticator)
            await sink.push_events(_events(1))
            await sink.push_events(_events(1))

        assert fake_authenticator.prepare.call_count == 2


class TestHttpJsonIntegrationSinkFailure:
    @pytest.mark.asyncio
    async def test_empty_batch_raises(self) -> None:
        sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
        with pytest.raises(IntegrationSinkError):
            await sink.push_events([])

    @pytest.mark.asyncio
    async def test_raw_text_event_raises_wrong_transport_family(self) -> None:
        sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
        with pytest.raises(IntegrationSinkError):
            await sink.push_events([MappedSinkEvent(source_detection_id="1", raw_text="CEF:0|...")])

    @pytest.mark.asyncio
    async def test_non_2xx_response_raises_never_fabricates_ack(self) -> None:
        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(500, text="internal error")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_unreachable_backend_raises_never_silent(self) -> None:
        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            raise httpx.ConnectError("connection refused")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_2xx_with_no_json_body_raises_never_fabricates(self) -> None:
        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            resp = _resp(200, text="not json")
            resp.json.side_effect = ValueError("no JSON object could be decoded")
            return resp

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_2xx_missing_accepted_field_raises_never_fabricates(self) -> None:
        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"text": "Success", "code": 0})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_2xx_mismatched_accepted_count_raises_treats_partial_as_failure(self) -> None:
        async def post(url, json, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"accepted": 1})  # only 1 of the 2 sent

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(2))


class TestHttpJsonIntegrationSinkBatchCeilings:
    def test_defaults_to_no_documented_ceiling(self) -> None:
        sink = HttpJsonIntegrationSink("http://localhost:9999/hec", NullAuthenticator())
        assert sink.max_batch_events is None
        assert sink.max_batch_bytes is None

    def test_explicit_ceilings_are_surfaced(self) -> None:
        sink = HttpJsonIntegrationSink(
            "http://localhost:9999/hec",
            NullAuthenticator(),
            max_batch_events=500,
            max_batch_bytes=5_000_000,
        )
        assert sink.max_batch_events == 500
        assert sink.max_batch_bytes == 5_000_000
