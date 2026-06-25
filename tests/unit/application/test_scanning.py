"""Unit tests for antivirus scanning layer."""

from __future__ import annotations

import pytest

from src.application.scanning import NoOpScanner, ScanResult


def _stream(data: bytes):  # type: ignore[no-untyped-def]
    async def _gen():  # type: ignore[no-untyped-def]
        yield data

    return _gen()


class TestScanResult:
    def test_clean_result(self) -> None:
        r = ScanResult(is_clean=True)
        assert r.is_clean
        assert r.threat_name is None

    def test_infected_result(self) -> None:
        r = ScanResult(is_clean=False, threat_name="Win.Eicar")
        assert not r.is_clean
        assert r.threat_name == "Win.Eicar"

    def test_clean_with_threat_name_raises(self) -> None:
        with pytest.raises(ValueError):
            ScanResult(is_clean=True, threat_name="should-not-exist")

    def test_frozen(self) -> None:
        r = ScanResult(is_clean=True)
        with pytest.raises((AttributeError, TypeError)):
            r.is_clean = False  # type: ignore[misc]


class TestNoOpScanner:
    @pytest.mark.asyncio
    async def test_returns_clean(self) -> None:
        scanner = NoOpScanner()
        result = await scanner.scan_stream(_stream(b"harmless content"))
        assert result.is_clean

    @pytest.mark.asyncio
    async def test_drains_stream(self) -> None:
        consumed: list[bytes] = []

        async def tracking_stream():  # type: ignore[no-untyped-def]
            for chunk in [b"part1", b"part2", b"part3"]:
                consumed.append(chunk)
                yield chunk

        scanner = NoOpScanner()
        await scanner.scan_stream(tracking_stream())
        assert len(consumed) == 3
