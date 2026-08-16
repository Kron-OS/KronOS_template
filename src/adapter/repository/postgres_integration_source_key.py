"""PostgreSQL implementation of IntegrationSourceKeyRepository using
SQLAlchemy Core.

Mirrors ``postgres_source_cursor.py``'s shape (single-table, ``org_id`` +
a natural per-connector key as the primary key, ``pg_insert(...)
.on_conflict_do_update(...)`` for idempotent provision/rotate). Only the
SHA-256 hash of the API key is ever persisted (``key_hash``) -- see
``integration_source_key.py``'s own module docstring for the full hashing
rationale; this module never constructs a plaintext column or index.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.integration_source_key import (
    IntegrationSourceKeyRepository,
    generate_api_key,
    hash_api_key,
)
from src.domain.integration_source import ProvisionedApiKeySummary, StaticApiKeyProvisioning
from src.exceptions import StorageError

_metadata = sa.MetaData()

integration_source_keys_table = sa.Table(
    "integration_source_keys",
    _metadata,
    sa.Column("org_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("source_id", sa.String(256), primary_key=True),
    sa.Column("source_type", sa.String(128), nullable=False),
    # SHA-256 hex digest (64 chars) -- the plaintext key is NEVER a column
    # here. Unique so get_by_key's lookup is a real indexed exact match,
    # not a table scan.
    sa.Column("key_hash", sa.String(64), nullable=False, unique=True, index=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
)


class PostgresIntegrationSourceKeyRepository(IntegrationSourceKeyRepository):
    """Persists provisioned API-key hashes via PostgreSQL; the real
    per-request ``get_by_key`` lookup path makes admin-provisioned keys
    take effect without a backend restart (Milestone W8, Gap Audit P1-7)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def provision(
        self, org_id: uuid.UUID, source_id: str, source_type: str
    ) -> StaticApiKeyProvisioning:
        api_key = generate_api_key()
        created_at = datetime.now(UTC)
        async with self._engine.begin() as conn:
            try:
                stmt = pg_insert(integration_source_keys_table).values(
                    org_id=org_id,
                    source_id=source_id,
                    source_type=source_type,
                    key_hash=hash_api_key(api_key),
                    created_at=created_at,
                    revoked_at=None,
                )
                # Rotation: provisioning again for the same (org_id,
                # source_id) replaces the hash/created_at and clears any
                # prior revocation -- the previous key stops resolving via
                # get_by_key the instant this commits.
                stmt = stmt.on_conflict_do_update(
                    index_elements=[
                        integration_source_keys_table.c.org_id,
                        integration_source_keys_table.c.source_id,
                    ],
                    set_={
                        "source_type": stmt.excluded.source_type,
                        "key_hash": stmt.excluded.key_hash,
                        "created_at": stmt.excluded.created_at,
                        "revoked_at": None,
                    },
                )
                await conn.execute(stmt)
            except Exception as exc:
                raise StorageError(
                    "Failed to provision integration source API key",
                    context={"org_id": str(org_id), "source_id": source_id, "error": str(exc)},
                ) from exc
        return StaticApiKeyProvisioning(
            api_key=api_key,
            org_id=org_id,
            source_id=source_id,
            source_type=source_type,
            created_at=created_at,
            revoked_at=None,
        )

    async def get_by_key(self, api_key: str) -> StaticApiKeyProvisioning | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    integration_source_keys_table.select().where(
                        integration_source_keys_table.c.key_hash == hash_api_key(api_key),
                        integration_source_keys_table.c.revoked_at.is_(None),
                    )
                )
            ).one_or_none()
        if row is None:
            return None
        data = row._asdict()
        return StaticApiKeyProvisioning(
            api_key=api_key,
            org_id=data["org_id"],
            source_id=data["source_id"],
            source_type=data["source_type"],
            created_at=_ensure_utc(data["created_at"]),
            revoked_at=None,
        )

    async def list_by_org(self, org_id: uuid.UUID) -> list[ProvisionedApiKeySummary]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                integration_source_keys_table.select()
                .where(integration_source_keys_table.c.org_id == org_id)
                .order_by(integration_source_keys_table.c.created_at.asc())
            )
            return [self._summary_from_row(row._asdict()) for row in result]

    async def revoke(self, org_id: uuid.UUID, source_id: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                integration_source_keys_table.update()
                .where(
                    integration_source_keys_table.c.org_id == org_id,
                    integration_source_keys_table.c.source_id == source_id,
                    integration_source_keys_table.c.revoked_at.is_(None),
                )
                .values(revoked_at=datetime.now(UTC))
            )

    @staticmethod
    def _summary_from_row(row: dict[str, Any]) -> ProvisionedApiKeySummary:
        return ProvisionedApiKeySummary(
            org_id=row["org_id"],
            source_id=row["source_id"],
            source_type=row["source_type"],
            created_at=_ensure_utc(row["created_at"]),
            revoked_at=_ensure_utc(row["revoked_at"]) if row["revoked_at"] is not None else None,
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
