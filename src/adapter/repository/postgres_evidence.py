"""PostgreSQL implementation of EvidenceRepository using SQLAlchemy Core."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository.evidence import EvidenceRepository
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState
from src.exceptions import StorageError

# ---------------------------------------------------------------------------
# Schema definition (SQLAlchemy Core — no ORM)
# ---------------------------------------------------------------------------

_metadata = sa.MetaData()

evidence_table = sa.Table(
    "evidence",
    _metadata,
    sa.Column("evidence_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("case_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("org_alias", sa.String(128), nullable=False),
    sa.Column("state", sa.String(32), nullable=False),
    sa.Column("original_filename", sa.String(1024), nullable=False),
    sa.Column("content_type", sa.String(256), nullable=False),
    sa.Column("size_bytes", sa.BigInteger, nullable=False),
    sa.Column("uploader_user_id", sa.UUID(as_uuid=True), nullable=False),
    sa.Column("sha256", sa.String(64)),
    sa.Column("md5", sa.String(32)),
    sa.Column("minio_quarantine_key", sa.Text),
    sa.Column("minio_evidence_key", sa.Text),
    sa.Column("error_reason", sa.Text),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresEvidenceRepository(EvidenceRepository):
    """Persists and retrieves Evidence domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        """Create tables if they do not already exist.  Call once at startup."""
        async with engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)

    # ------------------------------------------------------------------
    # EvidenceRepository interface
    # ------------------------------------------------------------------

    async def save(self, evidence: Evidence) -> Evidence:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(evidence_table.insert().values(**self._to_row(evidence)))
            except Exception as exc:
                raise StorageError(
                    "Failed to persist evidence",
                    context={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
                ) from exc
        return evidence

    async def update(self, evidence: Evidence) -> Evidence:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                evidence_table.update()
                .where(
                    evidence_table.c.evidence_id == evidence.evidence_id,
                    evidence_table.c.org_id == evidence.metadata.org_id,
                )
                .values(**self._to_row(evidence))
            )
            if result.rowcount == 0:
                raise StorageError(
                    "Evidence not found for update",
                    context={"evidence_id": str(evidence.evidence_id)},
                )
        return evidence

    async def get_by_id(self, evidence_id: uuid.UUID, org_id: uuid.UUID) -> Evidence | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    evidence_table.select().where(
                        evidence_table.c.evidence_id == evidence_id,
                        evidence_table.c.org_id == org_id,
                    )
                )
            ).one_or_none()
        if row is None:
            return None
        return self._from_row(row._asdict())

    async def stream_by_case(
        self, case_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[Evidence]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                evidence_table.select()
                .where(
                    evidence_table.c.case_id == case_id,
                    evidence_table.c.org_id == org_id,
                )
                .order_by(evidence_table.c.created_at)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def stream_by_state(
        self, state: EvidenceState, org_id: uuid.UUID
    ) -> AsyncIterator[Evidence]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                evidence_table.select()
                .where(
                    evidence_table.c.state == state.value,
                    evidence_table.c.org_id == org_id,
                )
                .order_by(evidence_table.c.created_at)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def delete_by_id(self, evidence_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        """Delete evidence metadata scoped to org_id. Returns True if a row was deleted."""
        async with self._engine.begin() as conn:
            result = await conn.execute(
                evidence_table.delete().where(
                    evidence_table.c.evidence_id == evidence_id,
                    evidence_table.c.org_id == org_id,
                )
            )
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Row ↔ domain mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _to_row(ev: Evidence) -> dict[str, Any]:
        return {
            "evidence_id": ev.evidence_id,
            "org_id": ev.metadata.org_id,
            "case_id": ev.metadata.case_id,
            "org_alias": ev.metadata.org_alias,
            "state": ev.state.value,
            "original_filename": ev.metadata.original_filename,
            "content_type": ev.metadata.content_type,
            "size_bytes": ev.metadata.size_bytes,
            "uploader_user_id": ev.metadata.uploader_user_id,
            "sha256": ev.sha256,
            "md5": ev.md5,
            "minio_quarantine_key": ev.minio_quarantine_key,
            "minio_evidence_key": ev.minio_evidence_key,
            "error_reason": ev.error_reason,
            "created_at": ev.created_at,
            "updated_at": ev.updated_at,
        }

    @staticmethod
    def _from_row(row: dict[str, Any]) -> Evidence:
        metadata = EvidenceMetadata(
            original_filename=row["original_filename"],
            content_type=row["content_type"],
            size_bytes=row["size_bytes"],
            uploader_user_id=row["uploader_user_id"],
            case_id=row["case_id"],
            org_id=row["org_id"],
            org_alias=row["org_alias"],
        )
        return Evidence(
            evidence_id=row["evidence_id"],
            metadata=metadata,
            state=EvidenceState(row["state"]),
            sha256=row["sha256"],
            md5=row["md5"],
            minio_quarantine_key=row["minio_quarantine_key"],
            minio_evidence_key=row["minio_evidence_key"],
            error_reason=row["error_reason"],
            created_at=_ensure_utc(row["created_at"]),
            updated_at=_ensure_utc(row["updated_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
