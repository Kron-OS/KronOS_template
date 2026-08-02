"""PostgreSQL implementation of AssetRepository using SQLAlchemy Core.

Mirrors ``src/adapter/repository/postgres_yara_rule_pack.py``'s shape,
except ``upsert`` is a real ``INSERT ... ON CONFLICT DO UPDATE`` (not an
append-only insert) -- see ``src/domain/asset.py``'s own docstring for why
an asset row is legitimately mutable, unlike this codebase's other
org-scoped Postgres tables.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.asset import AssetRepository
from src.domain.asset import Asset
from src.exceptions import StorageError

_metadata = sa.MetaData()

assets_table = sa.Table(
    "assets",
    _metadata,
    sa.Column("asset_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("hostname", sa.String(255), nullable=False),
    sa.Column("hostname_lower", sa.String(255), nullable=False),
    sa.Column("criticality", sa.String(64), nullable=False),
    sa.Column("owner", sa.String(255), nullable=True),
    sa.Column("environment", sa.String(64), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("org_id", "hostname_lower", name="uq_assets_org_hostname"),
)


class PostgresAssetRepository(AssetRepository):
    """Persists Asset domain objects via PostgreSQL, keyed by (org_id, hostname)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def upsert(self, asset: Asset) -> Asset:
        now = datetime.now(UTC)
        try:
            async with self._engine.begin() as conn:
                insert_stmt = pg_insert(assets_table).values(
                    asset_id=asset.asset_id,
                    org_id=asset.org_id,
                    hostname=asset.hostname,
                    hostname_lower=asset.hostname.lower(),
                    criticality=asset.criticality,
                    owner=asset.owner,
                    environment=asset.environment,
                    created_at=asset.created_at,
                    updated_at=now,
                )
                upsert_stmt = insert_stmt.on_conflict_do_update(
                    index_elements=["org_id", "hostname_lower"],
                    set_={
                        "hostname": insert_stmt.excluded.hostname,
                        "criticality": insert_stmt.excluded.criticality,
                        "owner": insert_stmt.excluded.owner,
                        "environment": insert_stmt.excluded.environment,
                        "updated_at": insert_stmt.excluded.updated_at,
                    },
                )
                await conn.execute(upsert_stmt)
                # Separate SELECT rather than chaining .returning() onto the
                # upsert -- mirrors postgres_yara_rule_pack.py's own
                # get_published_version pattern (a real row's exact
                # asset_id/created_at aren't otherwise knowable from just the
                # values we sent on an UPDATE branch, since asset_id keeps
                # the ORIGINAL row's value, not this call's new one).
                row = (
                    await conn.execute(
                        assets_table.select().where(
                            assets_table.c.org_id == asset.org_id,
                            assets_table.c.hostname_lower == asset.hostname.lower(),
                        )
                    )
                ).one()
        except Exception as exc:
            raise StorageError(
                "Failed to upsert asset",
                context={
                    "org_id": str(asset.org_id),
                    "hostname": asset.hostname,
                    "error": str(exc),
                },
            ) from exc
        return self._from_row(row._asdict())

    async def get_by_hostname(self, org_id: uuid.UUID, hostname: str) -> Asset | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    assets_table.select().where(
                        assets_table.c.org_id == org_id,
                        assets_table.c.hostname_lower == hostname.lower(),
                    )
                )
            ).one_or_none()
        return None if row is None else self._from_row(row._asdict())

    @staticmethod
    def _from_row(row: dict[str, Any]) -> Asset:
        return Asset(
            asset_id=row["asset_id"],
            org_id=row["org_id"],
            hostname=row["hostname"],
            criticality=row["criticality"],
            owner=row.get("owner"),
            environment=row.get("environment"),
            created_at=_ensure_utc(row["created_at"]),
            updated_at=_ensure_utc(row["updated_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
