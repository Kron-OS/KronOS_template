"""PostgreSQL implementation of DeadLetterSink using SQLAlchemy Core.

Mirrors src/adapter/repository/postgres_sealed_batch.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.dead_letter import DeadLetterSink
from src.domain.dead_letter import DeadLetterEvent
from src.exceptions import StorageError

_metadata = sa.MetaData()

dead_letter_events_table = sa.Table(
    "dead_letter_events",
    _metadata,
    sa.Column("dead_letter_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("source_id", sa.String(256), nullable=False, index=True),
    sa.Column("batch_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("event_offset", sa.Integer, nullable=False),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    sa.Column("error_type", sa.String(256), nullable=False),
    sa.Column("error_message", sa.Text, nullable=False),
    sa.Column("dead_lettered_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresDeadLetterSink(DeadLetterSink):
    """Persists and retrieves DeadLetterEvent domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def record(self, event: DeadLetterEvent) -> DeadLetterEvent:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(dead_letter_events_table.insert().values(**self._to_row(event)))
            except Exception as exc:
                raise StorageError(
                    "Failed to persist dead-lettered event",
                    context={
                        "dead_letter_id": str(event.dead_letter_id),
                        "batch_id": str(event.batch_id),
                        "error": str(exc),
                    },
                ) from exc
        return event

    async def list_for_batch(self, org_id: uuid.UUID, batch_id: uuid.UUID) -> list[DeadLetterEvent]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    dead_letter_events_table.select()
                    .where(
                        dead_letter_events_table.c.org_id == org_id,
                        dead_letter_events_table.c.batch_id == batch_id,
                    )
                    .order_by(dead_letter_events_table.c.event_offset.asc())
                )
            ).all()
        return [self._from_row(row._asdict()) for row in rows]

    @staticmethod
    def _to_row(event: DeadLetterEvent) -> dict[str, object]:
        return {
            "dead_letter_id": event.dead_letter_id,
            "org_id": event.org_id,
            "source_id": event.source_id,
            "batch_id": event.batch_id,
            "event_offset": event.event_offset,
            "payload": event.payload,
            "error_type": event.error_type,
            "error_message": event.error_message,
            "dead_lettered_at": event.dead_lettered_at,
        }

    @staticmethod
    def _from_row(row: dict[str, Any]) -> DeadLetterEvent:
        dead_lettered_at: datetime = row["dead_lettered_at"]
        if dead_lettered_at.tzinfo is None:
            dead_lettered_at = dead_lettered_at.replace(tzinfo=UTC)
        return DeadLetterEvent(
            dead_letter_id=row["dead_letter_id"],
            org_id=row["org_id"],
            source_id=row["source_id"],
            batch_id=row["batch_id"],
            event_offset=row["event_offset"],
            payload=row["payload"],
            error_type=row["error_type"],
            error_message=row["error_message"],
            dead_lettered_at=dead_lettered_at,
        )
