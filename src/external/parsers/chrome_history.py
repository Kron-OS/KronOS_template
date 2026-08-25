"""ChromeHistoryParser: parses Chromium/Chrome/Edge 'History' SQLite databases.

Chromium-family browsers (Chrome, Edge, Brave, Opera) store browsing history
in a SQLite database named ``History`` with ``urls`` and ``visits`` tables.
Each row in ``visits`` is one page load; joined to ``urls`` it yields the URL,
title, and visit metadata. This is a high-signal forensic artifact (user web
activity timeline) that previously dead-ended at the heavy Plaso path and only
ever produced a ``plaso:placeholder`` stub.

This is a native, dependency-free FAST parser (Python stdlib ``sqlite3`` only),
so it is fully unit-testable and needs no sandboxed subprocess. It is
registered *before* PlasoParser so genuine Chrome History DBs are handled here
while any other SQLite database still falls through to Plaso.
"""

from __future__ import annotations

import logging
import sqlite3
import tempfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import KronosProvenance, TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import ParsingError

logger = logging.getLogger(__name__)

_SQLITE_MAGIC = b"SQLite format 3\x00"

# The WebKit/Chrome epoch is 1601-01-01 UTC; timestamps are microseconds since.
_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

# Chromium page-transition core types (low byte of `visits.transition`).
# https://source.chromium.org/chromium/chromium/src/+/main:ui/base/page_transition_types.h
_TRANSITION_CORE: dict[int, str] = {
    0: "link",
    1: "typed",
    2: "auto_bookmark",
    3: "auto_subframe",
    4: "manual_subframe",
    5: "generated",
    6: "start_page",
    7: "form_submit",
    8: "reload",
    9: "keyword",
    10: "keyword_generated",
}
_TRANSITION_CORE_MASK = 0xFF

# Bounded page over the join so one pathological DB can't stream unboundedly;
# History DBs are user-scoped and realistically well under this.
_MAX_ROWS = 5_000_000


def _webkit_to_datetime(microseconds: int) -> datetime | None:
    """Convert a Chrome/WebKit timestamp (µs since 1601) to a UTC datetime."""
    if microseconds <= 0:
        return None
    try:
        return _WEBKIT_EPOCH + timedelta(microseconds=microseconds)
    except (OverflowError, ValueError):
        return None


class ChromeHistoryParser(ForensicParser):
    """Parses Chromium-family 'History' SQLite DBs into per-visit records."""

    @property
    def parser_name(self) -> str:
        return "chrome-history"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Accept SQLite DBs whose schema page declares Chrome's urls+visits tables.

        Keys on the SQLite magic plus both ``urls`` and ``visits`` table names
        appearing in the first schema page (sqlite_master lives in page 1, well
        inside the detection window). This is specific enough not to claim
        other SQLite artifacts — Firefox's ``places.sqlite`` uses ``moz_places``
        / ``moz_historyvisits``, not these names — so they still fall through to
        the Plaso path.
        """
        if header_bytes[: len(_SQLITE_MAGIC)] != _SQLITE_MAGIC:
            return False
        return b"urls" in header_bytes and b"visits" in header_bytes

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Buffer the DB to a temp file, then yield one record per visit."""
        # sqlite3 needs a seekable file path, so buffer the stream to disk (the
        # same pattern PlasoParser uses). suffix keeps it recognizable in a
        # crash dump; delete=False so we control cleanup after the connection
        # closes on all platforms.
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
            async for chunk in stream:
                tmp.write(chunk)
            tmp_path = tmp.name

        try:
            for record in self._read_visits(tmp_path, evidence):
                yield record
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_visits(self, db_path: str, evidence: Evidence) -> list[TimelineRecord]:
        # Open read-only + immutable: we never mutate evidence, and immutable
        # avoids acquiring locks or creating -wal/-shm side files next to the
        # (WORM) evidence copy. immutable is safe here because the temp file is
        # ours and no other writer exists.
        uri = f"file:{db_path}?mode=ro&immutable=1"
        try:
            conn = sqlite3.connect(uri, uri=True)
        except sqlite3.Error as exc:
            raise ParsingError(
                "Failed to open Chrome History database",
                context={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
            ) from exc

        records: list[TimelineRecord] = []
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    SELECT v.visit_time     AS visit_time,
                           v.transition     AS transition,
                           v.visit_duration AS visit_duration,
                           u.url            AS url,
                           u.title          AS title,
                           u.visit_count    AS visit_count,
                           u.typed_count    AS typed_count
                    FROM visits v
                    JOIN urls u ON u.id = v.url
                    ORDER BY v.visit_time ASC
                    """
                )
            except sqlite3.Error as exc:
                # Detection matched the magic + table names, but the actual
                # schema isn't Chrome's — surface it rather than silently
                # producing zero records.
                raise ParsingError(
                    "Chrome History schema not found (urls/visits join failed)",
                    context={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
                ) from exc

            idx = 0
            for row in cursor:
                if idx >= _MAX_ROWS:
                    logger.warning(
                        "chrome_history_row_cap_reached",
                        extra={"evidence_id": str(evidence.evidence_id), "cap": _MAX_ROWS},
                    )
                    break
                record = self._row_to_record(row, idx, evidence)
                if record is not None:
                    records.append(record)
                    idx += 1
        finally:
            conn.close()
        return records

    def _row_to_record(
        self, row: sqlite3.Row, idx: int, evidence: Evidence
    ) -> TimelineRecord | None:
        ts = _webkit_to_datetime(row["visit_time"])
        if ts is None:
            # A visit with no usable time is not a useful timeline record.
            return None

        url: str = row["url"] or ""
        title: str | None = row["title"] or None
        transition_core = int(row["transition"] or 0) & _TRANSITION_CORE_MASK
        transition_name = _TRANSITION_CORE.get(transition_core, f"unknown({transition_core})")

        domain = urlsplit(url).hostname or None

        extra: dict[str, Any] = {
            "event.module": "chrome",
            "event.dataset": "chrome.history",
            "url.full": url,
            "chrome.page_transition": transition_name,
            "chrome.visit_count": int(row["visit_count"] or 0),
            "chrome.typed_count": int(row["typed_count"] or 0),
        }
        if domain is not None:
            extra["url.domain"] = domain
        if title is not None:
            extra["chrome.title"] = title
        # visit_duration is microseconds; expose seconds as ECS event.duration ns.
        duration_us = int(row["visit_duration"] or 0)
        if duration_us > 0:
            extra["event.duration"] = duration_us * 1000  # µs -> ns

        provenance = KronosProvenance(
            evidence_id=evidence.evidence_id,
            case_id=evidence.metadata.case_id,
            org_id=evidence.metadata.org_id,
            sha256=evidence.sha256 or "",
            parser=self.parser_name,
            parser_version=self.parser_version,
            record_index=idx,
            ingest_timestamp=datetime.now(UTC),
        )

        message = f"Visited {url}" + (f" ({title})" if title else "")
        return TimelineRecord(
            **{
                "@timestamp": ts,
                "message": message,
                "event.kind": "event",
                "event.category": ["web"],
                "event.type": ["access"],
                "event.original": url[:32768],
            },
            extra=extra,
            kronos=provenance,
        )
