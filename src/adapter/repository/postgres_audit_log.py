"""PostgreSQL implementation of AuditLogRepository using SQLAlchemy Core."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository.audit_log import AuditLogRepository
from src.domain.audit import AuditEvent, AuditEventType
from src.exceptions import AuditLogError

_metadata = sa.MetaData()

audit_log_table = sa.Table(
    "audit_log",
    _metadata,
    sa.Column("event_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("event_type", sa.String(128), nullable=False),
    sa.Column("actor_user_id", sa.UUID(as_uuid=True)),
    sa.Column("actor_username", sa.String(256)),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("case_id", sa.UUID(as_uuid=True), index=True),
    sa.Column("evidence_id", sa.UUID(as_uuid=True), index=True),
    sa.Column("details", sa.JSON, nullable=False, default={}),
    sa.Column("occurred_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("sequence_number", sa.BigInteger, nullable=False),
    sa.Column("prev_row_hash", sa.String(64)),
    sa.Column("row_hash", sa.String(64)),
    sa.UniqueConstraint("org_id", "sequence_number", name="uq_audit_log_org_seq"),
)


class PostgresAuditLogRepository(AuditLogRepository):
    """Append-only audit log stored in PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)

    async def append(self, event: AuditEvent) -> AuditEvent:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(audit_log_table.insert().values(**self._to_row(event)))
            except Exception as exc:
                raise AuditLogError(
                    "Failed to persist audit event",
                    context={"event_id": str(event.event_id), "error": str(exc)},
                ) from exc
        return event

    async def get_latest_hash(self, org_id: uuid.UUID) -> str | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(audit_log_table.c.row_hash)
                    .where(audit_log_table.c.org_id == org_id)
                    .order_by(audit_log_table.c.sequence_number.desc())
                    .limit(1)
                )
            ).one_or_none()
        return row[0] if row else None

    async def get_latest_sequence(self, org_id: uuid.UUID) -> int:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    sa.select(sa.func.max(audit_log_table.c.sequence_number)).where(
                        audit_log_table.c.org_id == org_id
                    )
                )
            ).one_or_none()
        return row[0] if (row and row[0] is not None) else 0

    async def stream_by_evidence(  # type: ignore[override]
        self, evidence_id: uuid.UUID
    ) -> AsyncIterator[AuditEvent]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                audit_log_table.select()
                .where(audit_log_table.c.evidence_id == evidence_id)
                .order_by(audit_log_table.c.sequence_number)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def stream_by_case(  # type: ignore[override]
        self, case_id: uuid.UUID
    ) -> AsyncIterator[AuditEvent]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                audit_log_table.select()
                .where(audit_log_table.c.case_id == case_id)
                .order_by(audit_log_table.c.sequence_number)
            )
            for row in result:
                yield self._from_row(row._asdict())

    @staticmethod
    def _to_row(event: AuditEvent) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "actor_user_id": event.actor_user_id,
            "actor_username": event.actor_username,
            "org_id": event.org_id,
            "case_id": event.case_id,
            "evidence_id": event.evidence_id,
            "details": event.details,
            "occurred_at": event.occurred_at,
            "sequence_number": event.sequence_number,
            "prev_row_hash": event.prev_row_hash,
            "row_hash": event.row_hash,
        }

    @staticmethod
    def _from_row(row: dict[str, Any]) -> AuditEvent:
        return AuditEvent(
            event_id=row["event_id"],
            event_type=AuditEventType(row["event_type"]),
            actor_user_id=row["actor_user_id"],
            actor_username=row["actor_username"],
            org_id=row["org_id"],
            case_id=row["case_id"],
            evidence_id=row["evidence_id"],
            details=row["details"] or {},
            occurred_at=_ensure_utc(row["occurred_at"]),
            sequence_number=row["sequence_number"],
            prev_row_hash=row["prev_row_hash"],
            row_hash=row["row_hash"],
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
