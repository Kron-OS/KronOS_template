"""Unit tests for SplunkHecSink (mocked httpx, roadmap R2).

Response shapes and wire-format assertions here (real HEC "code"/"text"
body, concatenated-JSON batch body, "Authorization: Splunk <token>" header)
were independently verified against the real official Splunk docs first --
see poc/integration_sink_splunk_hec/README.md for the exact quotes/sources
-- and against a real local HEC-protocol-accurate stand-in receiver in that
same PoC. Mirrors test_http_json_sink.py's own httpx-mocking idiom.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.integration_sink.sink_authenticator import (
    NullAuthenticator,
    StaticTokenAuthenticator,
)
from src.adapter.integration_sink.splunk_hec_sink import SplunkHecSink
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAckStatus
from src.exceptions import IntegrationSinkError

_HEC_URL = "https://splunk.example.com:8088/services/collector/event"


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
    return [
        MappedSinkEvent(source_detection_id=str(i), payload={"event": {"i": i}, "time": 1.0})
        for i in range(n)
    ]


class TestSplunkHecSinkSuccess:
    @pytest.mark.asyncio
    async def test_2xx_with_real_success_body_returns_acknowledged(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            assert url == _HEC_URL
            # Real HEC batch wire format: concatenated standalone JSON
            # objects, never a JSON array / never {"events": [...]}.
            assert content == b'{"event": {"i": 0}, "time": 1.0}{"event": {"i": 1}, "time": 1.0}'
            return _resp(200, {"text": "Success", "code": 0})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            ack = await sink.push_events(_events(2))

        assert ack.status == SinkAckStatus.ACKNOWLEDGED
        assert ack.detail["code"] == 0
        assert ack.detail["text"] == "Success"
        assert ack.detail["event_count"] == 2

    @pytest.mark.asyncio
    async def test_real_splunk_auth_header_scheme_applied(self) -> None:
        seen_headers = {}

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            seen_headers.update(headers)
            return _resp(200, {"text": "Success", "code": 0})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, StaticTokenAuthenticator("tok-123", scheme="Splunk"))
            await sink.push_events(_events(1))

        # HEC's real, documented header is literally "Splunk <token>" --
        # NOT the more common "Bearer" scheme.
        assert seen_headers["Authorization"] == "Splunk tok-123"

    @pytest.mark.asyncio
    async def test_content_type_header_set(self) -> None:
        seen_headers = {}

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            seen_headers.update(headers)
            return _resp(200, {"text": "Success", "code": 0})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            await sink.push_events(_events(1))

        assert seen_headers["Content-Type"] == "application/json"


class TestSplunkHecSinkFailure:
    @pytest.mark.asyncio
    async def test_empty_batch_raises(self) -> None:
        sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
        with pytest.raises(IntegrationSinkError):
            await sink.push_events([])

    @pytest.mark.asyncio
    async def test_raw_text_event_raises_wrong_transport_family(self) -> None:
        sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
        with pytest.raises(IntegrationSinkError):
            await sink.push_events([MappedSinkEvent(source_detection_id="1", raw_text="CEF:0|...")])

    @pytest.mark.asyncio
    async def test_non_2xx_response_raises_never_fabricates_ack(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(500, text="internal error")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_unreachable_backend_raises_never_silent(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            raise httpx.ConnectError("connection refused")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_2xx_with_no_json_body_raises_never_fabricates(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            resp = _resp(200, text="not json")
            resp.json.side_effect = ValueError("no JSON object could be decoded")
            return resp

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_2xx_missing_code_field_raises_never_fabricates(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"text": "Success"})  # missing "code"

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_nonzero_code_raises_real_auth_failure_case(self) -> None:
        """A real, deliberate auth-failure case: wrong token -> HEC's own
        documented HTTP 403 + {"text": "Invalid token", "code": 4}."""

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(403, {"text": "Invalid token", "code": 4})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, StaticTokenAuthenticator("wrong-token", scheme="Splunk"))
            with pytest.raises(IntegrationSinkError) as excinfo:
                await sink.push_events(_events(1))

        # Real HEC's own documented {"text", "code"} pair is surfaced even
        # for a non-2xx response, not just the raw status code.
        assert excinfo.value.context["status_code"] == 403
        assert excinfo.value.context["code"] == 4
        assert excinfo.value.context["text"] == "Invalid token"

    @pytest.mark.asyncio
    async def test_non_2xx_non_json_body_falls_back_gracefully(self) -> None:
        """A non-2xx response with a non-JSON body (e.g. a proxy's own HTML
        error page, not real HEC itself) must not raise a second, confusing
        exception while building the first -- code/text are simply absent."""

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            resp = _resp(502, text="<html>Bad Gateway</html>")
            resp.json.side_effect = ValueError("no JSON object could be decoded")
            return resp

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            with pytest.raises(IntegrationSinkError) as excinfo:
                await sink.push_events(_events(1))

        assert excinfo.value.context["status_code"] == 502
        assert "code" not in excinfo.value.context

    @pytest.mark.asyncio
    async def test_2xx_with_nonzero_code_raises_never_fabricates_partial(self) -> None:
        """Even a 2xx HTTP status with a non-zero real HEC code must not be
        treated as success -- HEC gives no per-event breakdown to salvage a
        partial ack from, unlike HttpJsonIntegrationSink's accepted-count
        check."""

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"text": "Incorrect index", "code": 7})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            with pytest.raises(IntegrationSinkError):
                await sink.push_events(_events(1))

    @pytest.mark.asyncio
    async def test_oversized_event_rejected_before_any_real_call(self) -> None:
        """A real deliberate size-limit-adjacent case: one mapped event
        larger than a (deliberately tiny, for test purposes) max_event_bytes
        ceiling is rejected client-side, never sent."""
        sink = SplunkHecSink(_HEC_URL, NullAuthenticator(), max_event_bytes=10)
        oversized_payload = {"event": {"data": "x" * 100}}
        with patch("httpx.AsyncClient") as mock_client_cls:
            with pytest.raises(IntegrationSinkError) as excinfo:
                await sink.push_events(
                    [MappedSinkEvent(source_detection_id="1", payload=oversized_payload)]
                )
            mock_client_cls.assert_not_called()
        assert excinfo.value.context["max_event_bytes"] == 10


class TestSplunkHecSinkBatchCeilings:
    def test_defaults_to_real_documented_max_content_length(self) -> None:
        sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
        # HEC documents no per-request event-COUNT ceiling (byte-size only).
        assert sink.max_batch_events is None
        # Real limits.conf [http_input] max_content_length default (~800MB).
        assert sink.max_batch_bytes == 838_860_800

    def test_explicit_ceilings_are_surfaced(self) -> None:
        sink = SplunkHecSink(
            _HEC_URL,
            NullAuthenticator(),
            max_batch_events=100,
            max_batch_bytes=1_000_000,
        )
        assert sink.max_batch_events == 100
        assert sink.max_batch_bytes == 1_000_000

    @pytest.mark.asyncio
    async def test_batch_wire_format_is_concatenated_not_array(self) -> None:
        """Independently re-derives the exact real HEC batch wire format
        (concatenated standalone JSON objects) from json.dumps, rather than
        hardcoding the expected byte string twice."""
        captured = {}

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            captured["content"] = content
            return _resp(200, {"text": "Success", "code": 0})

        events = _events(3)
        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = SplunkHecSink(_HEC_URL, NullAuthenticator())
            await sink.push_events(events)

        expected = "".join(json.dumps(e.payload) for e in events).encode("utf-8")
        assert captured["content"] == expected
        # Never a JSON array wrapper.
        assert not captured["content"].startswith(b"[")
        assert not captured["content"].startswith(b'{"events"')
