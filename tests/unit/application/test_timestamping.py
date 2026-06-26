"""Unit tests for RFC 3161 timestamping service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.application.timestamping import RFC3161TimestampService, _build_timestamp_request, _der_length
from src.exceptions import StorageError


class TestDerLength:
    def test_short_form(self):
        assert _der_length(0) == b"\x00"
        assert _der_length(1) == b"\x01"
        assert _der_length(127) == b"\x7f"

    def test_long_form_one_byte(self):
        result = _der_length(128)
        assert result[0] == 0x81
        assert result[1] == 128

    def test_long_form_two_bytes(self):
        result = _der_length(300)
        assert result[0] == 0x82
        assert int.from_bytes(result[1:], "big") == 300


class TestBuildTimestampRequest:
    def test_returns_bytes(self):
        digest = b"\xab" * 32
        result = _build_timestamp_request(digest)
        assert isinstance(result, bytes)
        assert len(result) > 10

    def test_starts_with_sequence(self):
        digest = b"\xcd" * 32
        result = _build_timestamp_request(digest)
        assert result[0] == 0x30  # SEQUENCE tag

    def test_contains_digest(self):
        digest = b"\xef" * 32
        result = _build_timestamp_request(digest)
        assert digest in result


class TestRFC3161TimestampService:
    @pytest.fixture
    def svc(self):
        return RFC3161TimestampService(tsa_url="http://tsa.example.com/tsa")

    @pytest.mark.asyncio
    async def test_timestamp_happy_path(self, svc):
        mock_response = MagicMock()
        mock_response.content = b"\x30\x01\x00"
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await svc.timestamp(b"\xaa" * 32)

        assert result == b"\x30\x01\x00"

    @pytest.mark.asyncio
    async def test_timestamp_raises_storage_error_on_http_error(self, svc):
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(StorageError, match="TSA unreachable"):
                await svc.timestamp(b"\xaa" * 32)

    @pytest.mark.asyncio
    async def test_timestamp_raises_on_http_status_error(self, svc):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "400", request=MagicMock(), response=MagicMock()
            )
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(StorageError):
                await svc.timestamp(b"\xbb" * 32)

    @pytest.mark.asyncio
    async def test_verify_without_rfc3161ng_returns_datetime(self, svc):
        """When rfc3161ng is unavailable, verify() returns current datetime."""
        token = b"\x00" * 10
        digest = b"\xaa" * 32
        result = await svc.verify(token, digest)
        from datetime import datetime
        assert isinstance(result, datetime)

    @pytest.mark.asyncio
    async def test_verify_with_rfc3161ng(self, svc):
        """When rfc3161ng IS available, use it to parse the token."""
        from datetime import datetime, UTC

        expected_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        digest = b"\xaa" * 32

        mock_rfc3161ng = MagicMock()
        mock_ts_resp = MagicMock()
        mock_tst = {
            "tst_info": {
                "gen_time": MagicMock(native=expected_time),
                "message_imprint": {"hashed_message": MagicMock(native=digest)},
            }
        }
        mock_ts_resp.time_stamp_token = mock_tst
        mock_rfc3161ng.decode_timestamp_response = MagicMock(return_value=mock_ts_resp)

        import sys
        sys.modules["rfc3161ng"] = mock_rfc3161ng
        try:
            result = await svc.verify(b"\x30\x01\x00", digest)
            assert result == expected_time
        finally:
            del sys.modules["rfc3161ng"]
