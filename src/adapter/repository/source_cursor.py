"""Abstract and in-memory SourceCursor repository (roadmap Q1).

Mirrors ``OrgQuotaRepository``/``SealedBatchRepository``'s own pattern
exactly: an ABC + a thread-unsafe in-memory default so DI wiring never
hard-fails before Postgres is configured, plus a real Postgres
implementation (``postgres_source_cursor.py``) for production.

``SourceCursor`` (``src/domain/integration_source.py``) is the durable
per-(org, source) watermark a POLL-mode ``IntegrationSource`` resumes from
-- see that module's own docstring for why this is genuinely new state
(distinct from ``EventDedupChecker``'s content-hash dedup).
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.integration_source import SourceCursor


class SourceCursorRepository(ABC):
    """Per-(org_id, source_id) watermark persistence, one row per pair that
    has ever completed a poll cycle. Absence of a row means "never polled
    before" -- callers must not default to a magic/empty cursor string."""

    @abstractmethod
    async def get(self, org_id: uuid.UUID, source_id: str) -> SourceCursor | None:
        """Return the (org, source)'s current cursor, or None if it has
        never completed a poll cycle."""

    @abstractmethod
    async def upsert(self, cursor: SourceCursor) -> SourceCursor:
        """Insert or replace the (org, source)'s cursor row."""


class InMemorySourceCursorRepository(SourceCursorRepository):
    """Thread-unsafe in-memory double for unit tests and as the DI default."""

    def __init__(self) -> None:
        self._store: dict[tuple[uuid.UUID, str], SourceCursor] = {}

    async def get(self, org_id: uuid.UUID, source_id: str) -> SourceCursor | None:
        return self._store.get((org_id, source_id))

    async def upsert(self, cursor: SourceCursor) -> SourceCursor:
        self._store[(cursor.org_id, cursor.source_id)] = cursor
        return cursor
