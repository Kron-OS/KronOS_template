"""Unit tests for HashService — correctness verified against known digests."""

from __future__ import annotations

import hashlib

import pytest

from src.application.hashing import HashService


def _make_stream(data: bytes):  # type: ignore[no-untyped-def]
    async def _gen():  # type: ignore[no-untyped-def]
        chunk_size = 256
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]

    return _gen()


class TestHashService:
    service = HashService()

    @pytest.mark.asyncio
    async def test_known_sha256(self) -> None:
        data = b"hello kronos"
        result = await self.service.compute_from_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert result.sha256 == expected

    @pytest.mark.asyncio
    async def test_known_md5(self) -> None:
        data = b"hello kronos"
        result = await self.service.compute_from_bytes(data)
        expected = hashlib.md5(data).hexdigest()  # noqa: S324
        assert result.md5 == expected

    @pytest.mark.asyncio
    async def test_stream_matches_bytes(self) -> None:
        data = b"forensic evidence content " * 1000
        from_bytes = await self.service.compute_from_bytes(data)
        from_stream = await self.service.compute_from_stream(_make_stream(data))
        assert from_bytes.sha256 == from_stream.sha256
        assert from_bytes.md5 == from_stream.md5

    @pytest.mark.asyncio
    async def test_empty_data(self) -> None:
        result = await self.service.compute_from_bytes(b"")
        assert result.sha256 == hashlib.sha256(b"").hexdigest()

    @pytest.mark.asyncio
    async def test_result_is_frozen(self) -> None:
        result = await self.service.compute_from_bytes(b"test")
        with pytest.raises((AttributeError, TypeError)):
            result.sha256 = "tampered"  # type: ignore[misc]

    @pytest.mark.asyncio
    async def test_large_stream(self) -> None:
        data = b"x" * 10_000_000  # 10 MB
        from_stream = await self.service.compute_from_stream(_make_stream(data))
        expected = hashlib.sha256(data).hexdigest()
        assert from_stream.sha256 == expected
