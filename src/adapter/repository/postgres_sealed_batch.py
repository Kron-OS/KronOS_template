"""PostgreSQL implementation of SealedBatchRepository using SQLAlchemy Core.

Mirrors src/adapter/repository/postgres_detection.py / postgres_audit_log.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.sealed_batch import SealedBatchRepository
from src.domain.sealed_batch import SealedBatch
from src.exceptions import StorageError

_metadata = sa.MetaData()

sealed_batches_table = sa.Table(
    "sealed_batches",
    _metadata,
    sa.Column("batch_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("source_id", sa.String(256), nullable=False, index=True),
    sa.Column("sealed_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("event_count", sa.Integer, nullable=False),
    # JSON, not ARRAY: order matters (leaf index <-> Merkle proof position)
    # and must round-trip exactly -- ARRAY(String) is fine for that too, but
    # JSON keeps this table's shape consistent with detections.rule_matches'
    # own precedent for "ordered structured data that isn't queried by SQL".
    sa.Column("leaf_hashes", sa.JSON, nullable=False),
    sa.Column("message_ids", sa.JSON, nullable=False),
    sa.Column("merkle_root", sa.String(64), nullable=False),
    sa.Column("worm_bucket", sa.String(256), nullable=False),
    sa.Column("worm_object_key", sa.String(1024), nullable=False),
    sa.Column("tsa_token", sa.LargeBinary),
    sa.Column("first_message_id", sa.String(64), nullable=False),
    sa.Column("last_message_id", sa.String(64), nullable=False, index=True),
)


class PostgresSealedBatchRepository(SealedBatchRepository):
    """Persists and retrieves SealedBatch domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def save(self, batch: SealedBatch) -> SealedBatch:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(sealed_batches_table.insert().values(**self._to_row(batch)))
            except Exception as exc:
                raise StorageError(
                    "Failed to persist sealed batch",
                    context={"batch_id": str(batch.batch_id), "error": str(exc)},
                ) from exc
        return batch

    async def get_by_id(self, batch_id: uuid.UUID, org_id: uuid.UUID) -> SealedBatch | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    sealed_batches_table.select().where(
                        sealed_batches_table.c.batch_id == batch_id,
                        sealed_batches_table.c.org_id == org_id,
                    )
                )
            ).one_or_none()
        return None if row is None else self._from_row(row._asdict())

    async def get_last_sealed(self, org_id: uuid.UUID, source_id: str) -> SealedBatch | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    sealed_batches_table.select()
                    .where(
                        sealed_batches_table.c.org_id == org_id,
                        sealed_batches_table.c.source_id == source_id,
                    )
                    .order_by(sealed_batches_table.c.sealed_at.desc())
                    .limit(1)
                )
            ).one_or_none()
        return None if row is None else self._from_row(row._asdict())

    async def list_source_ids_for_org(self, org_id: uuid.UUID) -> list[str]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                sa.select(sealed_batches_table.c.source_id)
                .where(sealed_batches_table.c.org_id == org_id)
                .distinct()
            )
            return sorted(row[0] for row in result)

    @staticmethod
    def _to_row(batch: SealedBatch) -> dict[str, object]:
        return {
            "batch_id": batch.batch_id,
            "org_id": batch.org_id,
            "source_id": batch.source_id,
            "sealed_at": batch.sealed_at,
            "event_count": batch.event_count,
            "leaf_hashes": list(batch.leaf_hashes),
            "message_ids": list(batch.message_ids),
            "merkle_root": batch.merkle_root,
            "worm_bucket": batch.worm_bucket,
            "worm_object_key": batch.worm_object_key,
            "tsa_token": batch.tsa_token,
            "first_message_id": batch.first_message_id,
            "last_message_id": batch.last_message_id,
        }

    @staticmethod
    def _from_row(row: dict[str, object]) -> SealedBatch:
        sealed_at = row["sealed_at"]
        if sealed_at.tzinfo is None:  # type: ignore[union-attr]
            sealed_at = sealed_at.replace(tzinfo=UTC)  # type: ignore[union-attr]
        return SealedBatch(
            batch_id=row["batch_id"],
            org_id=row["org_id"],
            source_id=row["source_id"],
            sealed_at=sealed_at,
            event_count=row["event_count"],
            leaf_hashes=tuple(row["leaf_hashes"]),  # type: ignore[arg-type]
            message_ids=tuple(row["message_ids"]),  # type: ignore[arg-type]
            merkle_root=row["merkle_root"],
            worm_bucket=row["worm_bucket"],
            worm_object_key=row["worm_object_key"],
            tsa_token=row["tsa_token"],
            first_message_id=row["first_message_id"],
            last_message_id=row["last_message_id"],
        )
