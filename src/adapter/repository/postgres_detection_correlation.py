"""PostgreSQL implementation of DetectionCorrelationRepository using
SQLAlchemy Core. Mirrors src/adapter/repository/postgres_detection.py.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import or_
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.detection_correlation import DetectionCorrelationRepository
from src.domain.detection import DetectionCorrelation
from src.exceptions import StorageError

_metadata = sa.MetaData()

detection_correlations_table = sa.Table(
    "detection_correlations",
    _metadata,
    sa.Column("correlation_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("detection_id_a", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("detection_id_b", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("finding_id_a", sa.String(128), nullable=False),
    sa.Column("finding_id_b", sa.String(128), nullable=False),
    sa.Column("rule_ids", sa.ARRAY(sa.Text), nullable=False, server_default="{}"),
    sa.Column("synced_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # SA reports a pair without a stable ordering (see the ABC's own
    # docstring) -- this partial-order-independent uniqueness is enforced
    # in application code (exists_for_pair checks both orderings) rather
    # than a DB constraint, since Postgres has no portable "unordered pair"
    # unique index without a generated/normalized column.
)


class PostgresDetectionCorrelationRepository(DetectionCorrelationRepository):
    """Persists and retrieves DetectionCorrelation domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def save(self, correlation: DetectionCorrelation) -> DetectionCorrelation:
        if await self.exists_for_pair(
            correlation.org_id, correlation.finding_id_a, correlation.finding_id_b
        ):
            raise StorageError(
                "Correlation link already exists for this finding pair",
                context={
                    "org_id": str(correlation.org_id),
                    "finding_id_a": correlation.finding_id_a,
                    "finding_id_b": correlation.finding_id_b,
                },
            )
        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    detection_correlations_table.insert().values(**self._to_row(correlation))
                )
            except Exception as exc:
                raise StorageError(
                    "Failed to persist detection correlation",
                    context={
                        "finding_id_a": correlation.finding_id_a,
                        "finding_id_b": correlation.finding_id_b,
                        "error": str(exc),
                    },
                ) from exc
        return correlation

    async def exists_for_pair(
        self, org_id: uuid.UUID, finding_id_a: str, finding_id_b: str
    ) -> bool:
        c = detection_correlations_table.c
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(c.correlation_id).where(
                        c.org_id == org_id,
                        or_(
                            sa.and_(c.finding_id_a == finding_id_a, c.finding_id_b == finding_id_b),
                            sa.and_(c.finding_id_a == finding_id_b, c.finding_id_b == finding_id_a),
                        ),
                    )
                )
            ).one_or_none()
        return row is not None

    async def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[DetectionCorrelation]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                detection_correlations_table.select()
                .where(detection_correlations_table.c.org_id == org_id)
                .order_by(detection_correlations_table.c.synced_at)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def stream_by_detection(
        self, detection_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[DetectionCorrelation]:
        c = detection_correlations_table.c
        async with self._engine.connect() as conn:
            result = await conn.execute(
                detection_correlations_table.select()
                .where(
                    c.org_id == org_id,
                    or_(c.detection_id_a == detection_id, c.detection_id_b == detection_id),
                )
                .order_by(c.synced_at)
            )
            for row in result:
                yield self._from_row(row._asdict())

    @staticmethod
    def _to_row(c: DetectionCorrelation) -> dict[str, Any]:
        return {
            "correlation_id": c.correlation_id,
            "org_id": c.org_id,
            "detection_id_a": c.detection_id_a,
            "detection_id_b": c.detection_id_b,
            "finding_id_a": c.finding_id_a,
            "finding_id_b": c.finding_id_b,
            "rule_ids": list(c.rule_ids),
            "synced_at": c.synced_at,
        }

    @staticmethod
    def _from_row(row: dict[str, Any]) -> DetectionCorrelation:
        return DetectionCorrelation(
            correlation_id=row["correlation_id"],
            org_id=row["org_id"],
            detection_id_a=row["detection_id_a"],
            detection_id_b=row["detection_id_b"],
            finding_id_a=row["finding_id_a"],
            finding_id_b=row["finding_id_b"],
            rule_ids=tuple(row.get("rule_ids") or []),
            synced_at=_ensure_utc(row["synced_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
