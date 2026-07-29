"""PostgreSQL implementation of AuditLogRepository using SQLAlchemy Core."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.audit_log import AnchorRepository, EventBuilder
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

# Daily Merkle-root anchors (AUDIT-01/02/03). org_id is nullable to allow a
# genuine system-level/cross-org anchor row; in practice the daily beat task
# anchors one row per org that had activity that day (see
# AuditLogService.anchor_day — the hash chain's sequence_number is per-org,
# so a "day" root only makes sense computed over one org's events at a time).
audit_anchor_table = sa.Table(
    "audit_anchor",
    _metadata,
    sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=True, index=True),
    sa.Column("anchor_date", sa.Date, nullable=False, index=True),
    sa.Column("root_hash", sa.String(64), nullable=False),
    sa.Column("tsa_token", sa.LargeBinary),
    sa.Column("event_count", sa.Integer, nullable=False, default=0),
    sa.Column(
        "created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.func.now()
    ),
    sa.UniqueConstraint("org_id", "anchor_date", name="uq_audit_anchor_org_date"),
)


class PostgresAuditLogRepository(AnchorRepository):
    """Append-only audit log stored in PostgreSQL, with daily Merkle anchoring."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

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

    async def append_atomic(self, org_id: uuid.UUID, build_event: EventBuilder) -> AuditEvent:
        """Serialize per-org writers with a Postgres session-level advisory lock.

        ``pg_advisory_xact_lock`` blocks other transactions taking the same
        key until this transaction commits or rolls back — including on
        connections from other backend replicas, unlike an in-process lock.
        The tip read, event build, and insert all happen inside the same
        transaction that holds the lock, so no other writer can observe or
        extend the chain until this append is fully durable.
        """
        async with self._engine.begin() as conn:
            await conn.execute(sa.select(sa.func.pg_advisory_xact_lock(_org_lock_key(org_id))))

            row = (
                await conn.execute(
                    sa.select(
                        audit_log_table.c.row_hash,
                        audit_log_table.c.sequence_number,
                    )
                    .where(audit_log_table.c.org_id == org_id)
                    .order_by(audit_log_table.c.sequence_number.desc())
                    .limit(1)
                )
            ).one_or_none()
            prev_hash = row[0] if row else None
            latest_seq = row[1] if row else 0

            event = build_event(prev_hash, latest_seq)

            try:
                await conn.execute(audit_log_table.insert().values(**self._to_row(event)))
            except Exception as exc:
                raise AuditLogError(
                    "Failed to persist audit event",
                    context={"event_id": str(event.event_id), "error": str(exc)},
                ) from exc
        return event

    async def stream_by_evidence(self, evidence_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                audit_log_table.select()
                .where(audit_log_table.c.evidence_id == evidence_id)
                .order_by(audit_log_table.c.sequence_number)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def stream_by_case(self, case_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                audit_log_table.select()
                .where(audit_log_table.c.case_id == case_id)
                .order_by(audit_log_table.c.sequence_number)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                audit_log_table.select()
                .where(audit_log_table.c.org_id == org_id)
                .order_by(audit_log_table.c.sequence_number)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def list_by_date_range(self, start: datetime, end: datetime) -> list[AuditEvent]:
        """Real ``WHERE occurred_at BETWEEN`` query (AUDIT-01).

        Crosses org boundaries by design — used by the daily anchor beat task
        to discover which orgs had activity on a given day (CLAUDE.md §E.5's
        "system-task only" rule applies the same way here: never call this
        from a request handler).
        """
        async with self._engine.connect() as conn:
            result = await conn.execute(
                audit_log_table.select()
                .where(
                    audit_log_table.c.occurred_at >= start,
                    audit_log_table.c.occurred_at < end,
                )
                .order_by(audit_log_table.c.org_id, audit_log_table.c.sequence_number)
            )
            return [self._from_row(row._asdict()) for row in result]

    async def save_anchor(
        self,
        anchor_date: date,
        root_hash: str,
        tsa_token: bytes | None,
        *,
        org_id: uuid.UUID | None = None,
        event_count: int = 0,
    ) -> None:
        """Upsert the (org_id, anchor_date) anchor row — idempotent on re-run."""
        async with self._engine.begin() as conn:
            stmt = pg_insert(audit_anchor_table).values(
                org_id=org_id,
                anchor_date=anchor_date,
                root_hash=root_hash,
                tsa_token=tsa_token,
                event_count=event_count,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_audit_anchor_org_date",
                set_={
                    "root_hash": stmt.excluded.root_hash,
                    "tsa_token": stmt.excluded.tsa_token,
                    "event_count": stmt.excluded.event_count,
                },
            )
            try:
                await conn.execute(stmt)
            except Exception as exc:
                raise AuditLogError(
                    "Failed to persist Merkle anchor",
                    context={"anchor_date": anchor_date.isoformat(), "error": str(exc)},
                ) from exc

    async def get_anchor(
        self, anchor_date: date, *, org_id: uuid.UUID | None = None
    ) -> tuple[str, bytes | None] | None:
        async with self._engine.connect() as conn:
            conditions = [audit_anchor_table.c.anchor_date == anchor_date]
            conditions.append(
                audit_anchor_table.c.org_id == org_id
                if org_id is not None
                else audit_anchor_table.c.org_id.is_(None)
            )
            row = (
                await conn.execute(
                    sa.select(audit_anchor_table.c.root_hash, audit_anchor_table.c.tsa_token).where(
                        *conditions
                    )
                )
            ).one_or_none()
        return (row[0], row[1]) if row else None

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


def _org_lock_key(org_id: uuid.UUID) -> int:
    """Map an org_id to a signed 64-bit key for pg_advisory_xact_lock(bigint).

    Truncating to the UUID's first 8 bytes is fine here: the lock only needs
    to serialize writers for the *same* org_id, and any accidental collision
    with a different org merely causes extra (harmless) lock contention, not
    a correctness issue.
    """
    return int.from_bytes(org_id.bytes[:8], byteorder="big", signed=True)
