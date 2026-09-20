"""PostgreSQL implementation of ConnectorConfigRepository using SQLAlchemy Core.

Mirrors ``postgres_integration_source_key.py``'s shape exactly (composite
PK on ``(org_id, source_type)``, ``pg_insert(...).on_conflict_do_update(...)``
for idempotent upsert). Only non-secret fields + which field names are
secret-backed live here -- actual secret values live in Vault via
``VaultSecretStore`` (``src/adapter/secret/vault_secret_store.py``), never
in this table (plain ``sa.JSON``, matching ``postgres_audit_log.py``'s
``details`` column convention -- not JSONB, since nothing here is queried
by key).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.connector_config import ConnectorConfigRepository
from src.domain.connector import ConnectorConfigSummary
from src.exceptions import StorageError

_metadata = sa.MetaData()

connector_configs_table = sa.Table(
    "connector_configs",
    _metadata,
    sa.Column("org_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("source_type", sa.String(64), primary_key=True),
    sa.Column("enabled", sa.Boolean, nullable=False, default=True),
    sa.Column("non_secret_fields", sa.JSON, nullable=False, default=dict),
    sa.Column("secret_field_names", sa.JSON, nullable=False, default=list),
    sa.Column("consecutive_failure_count", sa.Integer, nullable=False, default=0),
    sa.Column("auto_disabled_at", sa.TIMESTAMP(timezone=True), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresConnectorConfigRepository(ConnectorConfigRepository):
    """Persists per-org connector configuration (non-secret half) via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def upsert(
        self,
        org_id: uuid.UUID,
        source_type: str,
        non_secret_fields: dict[str, str],
        secret_field_names: tuple[str, ...],
        *,
        enabled: bool = True,
    ) -> ConnectorConfigSummary:
        now = datetime.now(UTC)
        async with self._engine.begin() as conn:
            try:
                stmt = pg_insert(connector_configs_table).values(
                    org_id=org_id,
                    source_type=source_type,
                    enabled=enabled,
                    non_secret_fields=non_secret_fields,
                    secret_field_names=list(secret_field_names),
                    consecutive_failure_count=0,
                    auto_disabled_at=None,
                    created_at=now,
                    updated_at=now,
                )
                # A fresh set_config is an explicit admin action that
                # supersedes any prior circuit-breaker state -- reset
                # consecutive_failure_count/auto_disabled_at on every upsert,
                # same as InMemoryConnectorConfigRepository.upsert.
                stmt = stmt.on_conflict_do_update(
                    index_elements=[
                        connector_configs_table.c.org_id,
                        connector_configs_table.c.source_type,
                    ],
                    set_={
                        "enabled": stmt.excluded.enabled,
                        "non_secret_fields": stmt.excluded.non_secret_fields,
                        "secret_field_names": stmt.excluded.secret_field_names,
                        "consecutive_failure_count": 0,
                        "auto_disabled_at": None,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                await conn.execute(stmt)
            except Exception as exc:
                raise StorageError(
                    "Failed to upsert connector config",
                    context={"org_id": str(org_id), "source_type": source_type, "error": str(exc)},
                ) from exc
        result = await self.get(org_id, source_type)
        assert result is not None  # just upserted, must exist
        return result

    async def get(self, org_id: uuid.UUID, source_type: str) -> ConnectorConfigSummary | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    connector_configs_table.select().where(
                        connector_configs_table.c.org_id == org_id,
                        connector_configs_table.c.source_type == source_type,
                    )
                )
            ).one_or_none()
        return self._summary_from_row(row._asdict()) if row is not None else None

    async def list_by_org(self, org_id: uuid.UUID) -> list[ConnectorConfigSummary]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                connector_configs_table.select()
                .where(connector_configs_table.c.org_id == org_id)
                .order_by(connector_configs_table.c.created_at.asc())
            )
            return [self._summary_from_row(row._asdict()) for row in result]

    async def list_all_enabled_by_source_type(self, source_type: str) -> list[ConnectorConfigSummary]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                connector_configs_table.select().where(
                    connector_configs_table.c.source_type == source_type,
                    connector_configs_table.c.enabled.is_(True),
                )
            )
            return [self._summary_from_row(row._asdict()) for row in result]

    async def delete(self, org_id: uuid.UUID, source_type: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                connector_configs_table.delete().where(
                    connector_configs_table.c.org_id == org_id,
                    connector_configs_table.c.source_type == source_type,
                )
            )

    async def set_enabled(
        self, org_id: uuid.UUID, source_type: str, enabled: bool
    ) -> ConnectorConfigSummary | None:
        async with self._engine.begin() as conn:
            values: dict[str, Any] = {"enabled": enabled, "updated_at": datetime.now(UTC)}
            if enabled:
                values["auto_disabled_at"] = None
                values["consecutive_failure_count"] = 0
            await conn.execute(
                connector_configs_table.update()
                .where(
                    connector_configs_table.c.org_id == org_id,
                    connector_configs_table.c.source_type == source_type,
                )
                .values(**values)
            )
        return await self.get(org_id, source_type)

    async def record_success(self, org_id: uuid.UUID, source_type: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                connector_configs_table.update()
                .where(
                    connector_configs_table.c.org_id == org_id,
                    connector_configs_table.c.source_type == source_type,
                )
                .values(consecutive_failure_count=0, updated_at=datetime.now(UTC))
            )

    async def record_failure(
        self, org_id: uuid.UUID, source_type: str, *, auto_disable_threshold: int
    ) -> ConnectorConfigSummary | None:
        existing = await self.get(org_id, source_type)
        if existing is None:
            return None
        new_count = existing.consecutive_failure_count + 1
        should_disable = new_count >= auto_disable_threshold and existing.enabled
        now = datetime.now(UTC)
        async with self._engine.begin() as conn:
            values: dict[str, Any] = {"consecutive_failure_count": new_count, "updated_at": now}
            if should_disable:
                values["enabled"] = False
                values["auto_disabled_at"] = now
            await conn.execute(
                connector_configs_table.update()
                .where(
                    connector_configs_table.c.org_id == org_id,
                    connector_configs_table.c.source_type == source_type,
                )
                .values(**values)
            )
        return await self.get(org_id, source_type)

    @staticmethod
    def _summary_from_row(row: dict[str, Any]) -> ConnectorConfigSummary:
        return ConnectorConfigSummary(
            org_id=row["org_id"],
            source_type=row["source_type"],
            enabled=row["enabled"],
            non_secret_fields=row["non_secret_fields"],
            secret_field_names=tuple(row["secret_field_names"]),
            consecutive_failure_count=row["consecutive_failure_count"],
            auto_disabled_at=_ensure_utc(row["auto_disabled_at"]) if row["auto_disabled_at"] else None,
            created_at=_ensure_utc(row["created_at"]),
            updated_at=_ensure_utc(row["updated_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
