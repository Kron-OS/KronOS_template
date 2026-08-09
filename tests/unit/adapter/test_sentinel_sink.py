"""Unit tests for SentinelHttpSink (mocked httpx, roadmap R4).

Response shapes and wire-format assertions here (real Logs Ingestion API
bare-JSON-array request body, real 204-no-body success contract, the
general Azure REST API error envelope) were independently verified against
Microsoft's own real, current docs first -- see
poc/integration_sink_sentinel/README.md for the exact quotes/sources cited
-- and against a real local DCE-protocol-accurate stand-in receiver in that
same PoC. Mirrors test_splunk_hec_sink.py's own httpx-mocking idiom.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.integration_sink.sentinel_sink import SentinelHttpSink
from src.adapter.integration_sink.sink_authenticator import (
    NullAuthenticator,
    StaticTokenAuthenticator,
)
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAckStatus
from src.exceptions import IntegrationSinkError

_DCE_ENDPOINT = "https://my-dce-5kyl.eastus-1.ingest.monitor.azure.com"
_DCR_ID = "dcr-000a00a000a00000a000000aa000a0aa"
_STREAM = "Custom-KronOSDetection"
_EXPECTED_URL = (
    f"{_DCE_ENDPOINT}/dataCollectionRules/{_DCR_ID}/streams/{_STREAM}?api-version=2023-01-01"
)


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
        MappedSinkEvent(source_detection_id=str(i), payload={"DetectionId": str(i), "i": i})
        for i in range(n)
    ]


def _sink(authenticator=None, **kwargs) -> SentinelHttpSink:  # type: ignore[no-untyped-def]
    return SentinelHttpSink(
        _DCE_ENDPOINT, _DCR_ID, _STREAM, authenticator or NullAuthenticator(), **kwargs
    )


class TestSentinelHttpSinkSuccess:
    @pytest.mark.asyncio
    async def test_204_no_body_returns_acknowledged(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            assert url == _EXPECTED_URL
            # Real Logs Ingestion API wire format: a bare top-level JSON
            # array of records, never {"events": [...]} and never
            # concatenated standalone objects (Splunk HEC's own shape).
            assert content == json.dumps([{"DetectionId": "0", "i": 0}]).encode("utf-8")
            return _resp(204)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = _sink()
            ack = await sink.push_events(_events(1))

        assert ack.status == SinkAckStatus.ACKNOWLEDGED
        assert ack.detail["status_code"] == 204
        assert ack.detail["event_count"] == 1

    @pytest.mark.asyncio
    async def test_real_bearer_auth_header_applied(self) -> None:
        seen_headers = {}

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            seen_headers.update(headers)
            return _resp(204)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            sink = _sink(StaticTokenAuthenticator("tok-123", scheme="Bearer"))
            await sink.push_events(_events(1))

        assert seen_headers["Authorization"] == "Bearer tok-123"

    @pytest.mark.asyncio
    async def test_content_type_header_set(self) -> None:
        seen_headers = {}

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            seen_headers.update(headers)
            return _resp(204)

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            await _sink().push_events(_events(1))

        assert seen_headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_batch_wire_format_is_bare_array(self) -> None:
        captured = {}

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            captured["content"] = content
            return _resp(204)

        events = _events(3)
        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            await _sink().push_events(events)

        expected = json.dumps([e.payload for e in events]).encode("utf-8")
        assert captured["content"] == expected
        assert captured["content"].startswith(b"[")
        assert not captured["content"].startswith(b'{"events"')


class TestSentinelHttpSinkFailure:
    @pytest.mark.asyncio
    async def test_empty_batch_raises(self) -> None:
        with pytest.raises(IntegrationSinkError):
            await _sink().push_events([])

    @pytest.mark.asyncio
    async def test_raw_text_event_raises_wrong_transport_family(self) -> None:
        with pytest.raises(IntegrationSinkError):
            await _sink().push_events(
                [MappedSinkEvent(source_detection_id="1", raw_text="not json family")]
            )

    @pytest.mark.asyncio
    async def test_200_is_not_treated_as_success(self) -> None:
        """Real, explicitly documented success is 204 -- a stray 200 (never
        observed as a real Logs Ingestion API response) must still be
        treated as a real failure, never silently accepted."""

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, text="")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            with pytest.raises(IntegrationSinkError):
                await _sink().push_events(_events(1))

    @pytest.mark.asyncio
    async def test_real_documented_403_permission_failure(self) -> None:
        """Real documented case: app registration lacks the DCR's
        Monitoring Metrics Publisher role."""

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(
                403,
                {
                    "error": {
                        "code": "Forbidden",
                        "message": "The provided credentials do not "
                        "have access to the resource.",
                    }
                },
            )

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            with pytest.raises(IntegrationSinkError) as excinfo:
                await _sink().push_events(_events(1))

        assert excinfo.value.context["status_code"] == 403
        assert excinfo.value.context["error_code"] == "Forbidden"

    @pytest.mark.asyncio
    async def test_real_documented_429_throttle_failure(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(
                429, {"error": {"code": "RateLimitExceeded", "message": "Too many requests"}}
            )

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            with pytest.raises(IntegrationSinkError) as excinfo:
                await _sink().push_events(_events(1))

        assert excinfo.value.context["status_code"] == 429
        assert excinfo.value.context["error_code"] == "RateLimitExceeded"

    @pytest.mark.asyncio
    async def test_401_invalid_token_failure(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(401, text="")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            with pytest.raises(IntegrationSinkError) as excinfo:
                await _sink().push_events(_events(1))

        assert excinfo.value.context["status_code"] == 401

    @pytest.mark.asyncio
    async def test_non_json_error_body_falls_back_gracefully(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            resp = _resp(500, text="<html>Internal Server Error</html>")
            resp.json.side_effect = ValueError("no JSON object could be decoded")
            return resp

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            with pytest.raises(IntegrationSinkError) as excinfo:
                await _sink().push_events(_events(1))

        assert excinfo.value.context["status_code"] == 500
        assert "error_code" not in excinfo.value.context

    @pytest.mark.asyncio
    async def test_error_body_that_is_valid_json_but_not_a_dict_does_not_crash(self) -> None:
        """Defends against SplunkHecSink's own first-real-run bug (AttributeError
        on a non-dict JSON error body) from the start, for the same class of
        real-world malformed-proxy-response case."""

        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(502, None, text="null")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            with pytest.raises(IntegrationSinkError) as excinfo:
                await _sink().push_events(_events(1))

        assert excinfo.value.context["status_code"] == 502
        assert "error_code" not in excinfo.value.context

    @pytest.mark.asyncio
    async def test_unreachable_backend_raises_never_silent(self) -> None:
        async def post(url, content, headers, **kwargs):  # type: ignore[no-untyped-def]
            raise httpx.ConnectError("connection refused")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            with pytest.raises(IntegrationSinkError):
                await _sink().push_events(_events(1))

    @pytest.mark.asyncio
    async def test_oversized_batch_rejected_before_any_real_call(self) -> None:
        """A real deliberate size-limit case: a batch larger than a
        (deliberately tiny, for test purposes) max_batch_bytes ceiling is
        rejected client-side, mirroring the real documented 1MB/call
        ceiling and its real 413 failure mode -- never sent."""
        with patch("httpx.AsyncClient") as mock_client_cls:
            with pytest.raises(IntegrationSinkError) as excinfo:
                await _sink(max_batch_bytes=10).push_events(_events(5))
            mock_client_cls.assert_not_called()
        assert excinfo.value.context["max_batch_bytes"] == 10


class TestSentinelHttpSinkBatchCeilings:
    def test_defaults_to_real_documented_1mb_ceiling(self) -> None:
        sink = _sink()
        # Logs Ingestion API documents no per-request event-COUNT ceiling
        # (byte-size only, mirrors Splunk HEC's own identical shape).
        assert sink.max_batch_events is None
        assert sink.max_batch_bytes == 1_000_000

    def test_explicit_ceilings_are_surfaced(self) -> None:
        sink = _sink(max_batch_events=50, max_batch_bytes=500_000)
        assert sink.max_batch_events == 50
        assert sink.max_batch_bytes == 500_000

    def test_url_uses_real_documented_uri_template(self) -> None:
        sink = _sink()
        assert sink._url == _EXPECTED_URL  # noqa: SLF001 -- white-box wire-shape check

    def test_custom_api_version_is_used(self) -> None:
        sink = _sink(api_version="2024-02-01")
        assert "api-version=2024-02-01" in sink._url  # noqa: SLF001
