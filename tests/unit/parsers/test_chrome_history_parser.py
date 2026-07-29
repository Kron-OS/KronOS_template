"""Unit tests for ChromeHistoryParser.

Builds a real Chrome/Chromium 'History' SQLite database (the genuine urls +
visits schema, with authentic WebKit-epoch timestamps) in a temp file and
drives the real parse path against it — no hand-massaged fixture that just
echoes the parser's assumptions.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from src.application.parser_registry import ParserRegistry
from src.domain.timeline import TimelineRecord
from src.external.parsers.chrome_history import ChromeHistoryParser
from tests.fixtures.factories import make_evidence, make_tenant_context

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def _chrome_ts(dt: datetime) -> int:
    return int((dt - _WEBKIT_EPOCH).total_seconds() * 1_000_000)


# Two real visits at known times so we can assert exact round-trip conversion.
_V1 = datetime(2024, 3, 15, 12, 30, 0, tzinfo=UTC)
_V2 = datetime(2024, 3, 15, 12, 45, 30, tzinfo=UTC)


def _build_history_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE urls(
            id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
            visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0);
        CREATE TABLE visits(
            id INTEGER PRIMARY KEY, url INTEGER NOT NULL, visit_time INTEGER NOT NULL,
            from_visit INTEGER, transition INTEGER DEFAULT 0, visit_duration INTEGER DEFAULT 0);
        """)
    conn.execute(
        "INSERT INTO urls VALUES(1,'https://example.com/path','Example Domain',3,1,?,0)",
        (_chrome_ts(_V2),),
    )
    conn.execute(
        "INSERT INTO urls VALUES(2,'https://news.ycombinator.com/','Hacker News',1,0,?,0)",
        (_chrome_ts(_V1),),
    )
    # transition 0x01 (core=typed), duration 1.5s
    conn.execute("INSERT INTO visits VALUES(1,2,?,0,1,1500000)", (_chrome_ts(_V1),))
    # transition 0x00 (core=link)
    conn.execute("INSERT INTO visits VALUES(2,1,?,1,0,0)", (_chrome_ts(_V2),))
    conn.commit()
    conn.close()


@pytest.fixture
def history_db(tmp_path):
    path = tmp_path / "History"
    _build_history_db(str(path))
    return path


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


class TestSupports:
    def test_detects_chrome_history_by_schema(self, history_db) -> None:
        header = history_db.read_bytes()[:8192]
        assert ChromeHistoryParser().supports("History", "application/octet-stream", header)

    def test_rejects_non_sqlite(self) -> None:
        assert not ChromeHistoryParser().supports(
            "History", "application/octet-stream", b"regf\x00"
        )

    def test_rejects_sqlite_without_chrome_tables(self, tmp_path) -> None:
        # A Firefox-style places.sqlite (moz_places, not urls/visits) must NOT
        # be claimed here — it should fall through to the Plaso path.
        path = tmp_path / "places.sqlite"
        conn = sqlite3.connect(str(path))
        conn.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, place_url TEXT)")
        conn.commit()
        conn.close()
        header = path.read_bytes()[:8192]
        assert not ChromeHistoryParser().supports(
            "places.sqlite", "application/octet-stream", header
        )

    def test_registry_prefers_chrome_over_plaso(self, history_db) -> None:
        from src.external.parsers.plaso import PlasoParser

        registry = ParserRegistry()
        registry.register(ChromeHistoryParser())
        registry.register(PlasoParser())
        header = history_db.read_bytes()[:8192]
        parser = registry.get_parser("History", "application/octet-stream", header)
        assert isinstance(parser, ChromeHistoryParser)


class TestParse:
    @pytest.mark.asyncio
    async def test_yields_one_record_per_visit(self, history_db) -> None:
        records = await _drain(
            ChromeHistoryParser().parse(
                _bytes_stream(history_db.read_bytes()), make_evidence(), make_tenant_context()
            )
        )
        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_records_ordered_by_visit_time_with_correct_timestamps(self, history_db) -> None:
        records = await _drain(
            ChromeHistoryParser().parse(
                _bytes_stream(history_db.read_bytes()), make_evidence(), make_tenant_context()
            )
        )
        # ORDER BY visit_time ASC: first the _V1 (Hacker News) visit, then _V2.
        assert records[0].timestamp == _V1
        assert records[1].timestamp == _V2
        assert records[0].extra["url.full"] == "https://news.ycombinator.com/"
        assert records[1].extra["url.full"] == "https://example.com/path"

    @pytest.mark.asyncio
    async def test_maps_ecs_and_chrome_fields(self, history_db) -> None:
        records = await _drain(
            ChromeHistoryParser().parse(
                _bytes_stream(history_db.read_bytes()), make_evidence(), make_tenant_context()
            )
        )
        first = records[0]
        assert first.event_category == ["web"]
        assert first.event_type == ["access"]
        assert first.extra["url.domain"] == "news.ycombinator.com"
        assert first.extra["chrome.page_transition"] == "typed"
        assert first.extra["chrome.title"] == "Hacker News"
        assert first.extra["event.duration"] == 1_500_000 * 1000  # µs -> ns
        assert "Hacker News" in (first.message or "")

    @pytest.mark.asyncio
    async def test_provenance_and_sequential_index(self, history_db) -> None:
        evidence = make_evidence()
        records = await _drain(
            ChromeHistoryParser().parse(
                _bytes_stream(history_db.read_bytes()), evidence, make_tenant_context()
            )
        )
        assert [r.kronos.record_index for r in records] == [0, 1]
        assert all(r.kronos.parser == "chrome-history" for r in records)
        assert all(r.kronos.evidence_id == evidence.evidence_id for r in records)

    @pytest.mark.asyncio
    async def test_empty_history_yields_no_records(self, tmp_path) -> None:
        path = tmp_path / "History"
        conn = sqlite3.connect(str(path))
        conn.executescript("""
            CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
            CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
            """)
        conn.commit()
        conn.close()
        records = await _drain(
            ChromeHistoryParser().parse(
                _bytes_stream(path.read_bytes()), make_evidence(), make_tenant_context()
            )
        )
        assert records == []

    @pytest.mark.asyncio
    async def test_corrupt_sqlite_raises_parsing_error(self) -> None:
        from src.exceptions import ParsingError

        # SQLite magic present (so it reached parse) but the body is garbage.
        data = b"SQLite format 3\x00" + b"\xff" * 4000
        with pytest.raises(ParsingError):
            await _drain(
                ChromeHistoryParser().parse(
                    _bytes_stream(data), make_evidence(), make_tenant_context()
                )
            )
