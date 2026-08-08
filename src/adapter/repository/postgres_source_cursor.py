"""PostgreSQL implementation of SourceCursorRepository using SQLAlchemy Core.

Mirrors ``postgres_quota.py``'s row<->domain mapping shape exactly (dict
``_asdict()`` + a shared ``_ensure_utc`` helper) -- same rationale: avoids
``postgres_sealed_batch.py``'s known, already-accepted mypy false positive
on the inline ``dict[str, object]`` idiom.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.source_cursor import SourceCursorRepository
from src.domain.integration_source import SourceCursor
from src.exceptions import StorageError

_metadata = sa.MetaData()

source_cursors_table = sa.Table(
    "integration_source_cursors",
    _metadata,
    sa.Column("org_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("source_id", sa.String, primary_key=True),
    sa.Column("cursor_value", sa.String, nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresSourceCursorRepository(SourceCursorRepository):
    """Persists and retrieves SourceCursor domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def get(self, org_id: uuid.UUID, source_id: str) -> SourceCursor | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    source_cursors_table.select().where(
                        source_cursors_table.c.org_id == org_id,
                        source_cursors_table.c.source_id == source_id,
                    )
                )
            ).one_or_none()
        return None if row is None else self._from_row(row._asdict())

    async def upsert(self, cursor: SourceCursor) -> SourceCursor:
        async with self._engine.begin() as conn:
            try:
                stmt = pg_insert(source_cursors_table).values(
                    org_id=cursor.org_id,
                    source_id=cursor.source_id,
                    cursor_value=cursor.cursor_value,
                    updated_at=cursor.updated_at,
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=[
                        source_cursors_table.c.org_id,
                        source_cursors_table.c.source_id,
                    ],
                    set_={
                        "cursor_value": stmt.excluded.cursor_value,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                await conn.execute(stmt)
            except Exception as exc:
                raise StorageError(
                    "Failed to persist source cursor",
                    context={
                        "org_id": str(cursor.org_id),
                        "source_id": cursor.source_id,
                        "error": str(exc),
                    },
                ) from exc
        return cursor

    @staticmethod
    def _from_row(row: dict[str, Any]) -> SourceCursor:
        return SourceCursor(
            org_id=row["org_id"],
            source_id=row["source_id"],
            cursor_value=row["cursor_value"],
            updated_at=_ensure_utc(row["updated_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware UTC (mirrors postgres_quota.py's helper)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
