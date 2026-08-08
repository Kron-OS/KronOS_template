"""PostgreSQL implementation of OrgQuotaRepository using SQLAlchemy Core.

Mirrors src/adapter/repository/postgres_evidence.py's row<->domain mapping
shape specifically (dict[str, Any] + a shared _ensure_utc helper) rather
than postgres_sealed_batch.py's inline dict[str, object] + per-field
type:ignore idiom -- the latter has a known, already-accepted mypy false
positive (object has no attribute "tzinfo"/"replace") that the Any-typed
shape avoids entirely.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.quota import OrgQuotaRepository
from src.domain.quota import OrgQuota
from src.exceptions import StorageError

_metadata = sa.MetaData()

org_quotas_table = sa.Table(
    "org_quotas",
    _metadata,
    sa.Column("org_id", sa.UUID(as_uuid=True), primary_key=True),
    # Nullable = unlimited (see OrgQuota's own docstring) -- never a magic
    # sentinel int, so the column itself must allow NULL.
    sa.Column("storage_quota_bytes", sa.BigInteger, nullable=True),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresOrgQuotaRepository(OrgQuotaRepository):
    """Persists and retrieves OrgQuota domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def get(self, org_id: uuid.UUID) -> OrgQuota | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    org_quotas_table.select().where(org_quotas_table.c.org_id == org_id)
                )
            ).one_or_none()
        return None if row is None else self._from_row(row._asdict())

    async def upsert(self, quota: OrgQuota) -> OrgQuota:
        async with self._engine.begin() as conn:
            try:
                stmt = pg_insert(org_quotas_table).values(
                    org_id=quota.org_id,
                    storage_quota_bytes=quota.storage_quota_bytes,
                    updated_at=quota.updated_at,
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=[org_quotas_table.c.org_id],
                    set_={
                        "storage_quota_bytes": stmt.excluded.storage_quota_bytes,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                await conn.execute(stmt)
            except Exception as exc:
                raise StorageError(
                    "Failed to persist org quota",
                    context={"org_id": str(quota.org_id), "error": str(exc)},
                ) from exc
        return quota

    @staticmethod
    def _from_row(row: dict[str, Any]) -> OrgQuota:
        return OrgQuota(
            org_id=row["org_id"],
            storage_quota_bytes=row["storage_quota_bytes"],
            updated_at=_ensure_utc(row["updated_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware UTC (mirrors postgres_evidence.py's helper)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
