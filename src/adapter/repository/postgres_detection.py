"""PostgreSQL implementation of DetectionRepository using SQLAlchemy Core.

Mirrors src/adapter/repository/postgres_evidence.py / postgres_case.py.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.detection import DetectionRepository
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState
from src.domain.risk import RiskFactor
from src.exceptions import StorageError

_metadata = sa.MetaData()

detections_table = sa.Table(
    "detections",
    _metadata,
    sa.Column("detection_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("org_alias", sa.String(128), nullable=False),
    sa.Column("case_id", sa.UUID(as_uuid=True), index=True),
    # The real SA finding document's own top-level `_id` (confirmed flat,
    # not nested -- see src/domain/detection.py's docstring). Unique per
    # org: this is the idempotency dedup key DetectionSyncService relies on.
    sa.Column("finding_id", sa.String(128), nullable=False),
    sa.Column("detector_name", sa.String(256), nullable=False),
    sa.Column("source_index", sa.String(512), nullable=False),
    sa.Column("rule_matches", sa.JSON, nullable=False, default=list),
    sa.Column("matched_document_ids", sa.ARRAY(sa.Text), nullable=False, server_default="{}"),
    sa.Column("finding_timestamp", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("triage_state", sa.String(32), nullable=False, server_default="NEW"),
    sa.Column("synced_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
    # Risk scoring (roadmap M5/F4) -- computed once at sync time by
    # DetectionSyncService, frozen here alongside every other
    # captured-once-at-sync column above (rule_matches, matched_document_ids).
    # Nullable: None is the honest "could not be scored at all" case (see
    # RiskScoreBreakdown.score's own docstring), not a missing-column default.
    # Additive columns, same caveat as postgres_evidence.py's own precedent:
    # `create_all` only adds missing TABLES, not columns to an existing one
    # -- safe on a fresh schema, but an already-running deployment's
    # `detections` table (this repo's own live dev Postgres included, at the
    # moment this landed) needs a real, one-time manual
    # `ALTER TABLE detections ADD COLUMN risk_score double precision;
    #  ALTER TABLE detections ADD COLUMN risk_factors json NOT NULL DEFAULT '[]';`
    # since no migration tool is wired yet.
    sa.Column("risk_score", sa.Float, nullable=True),
    sa.Column("risk_factors", sa.JSON, nullable=False, default=list),
    # External ticket traceability (roadmap M7/H4) -- same additive-column
    # caveat as risk_score/risk_factors immediately above: `create_all` only
    # adds missing TABLES, not columns to an existing one, so an
    # already-running deployment's `detections` table needs a real,
    # one-time manual
    # `ALTER TABLE detections ADD COLUMN external_ticket_id varchar(256);`
    # since no migration tool is wired yet. Nullable: None until the first
    # successful SyncDetectionTicketAction run.
    sa.Column("external_ticket_id", sa.String(256), nullable=True),
    sa.UniqueConstraint("org_id", "finding_id", name="uq_detections_org_finding"),
)


class PostgresDetectionRepository(DetectionRepository):
    """Persists and retrieves Detection domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def save(self, detection: Detection) -> Detection:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(detections_table.insert().values(**self._to_row(detection)))
            except Exception as exc:
                # Covers the real (org_id, finding_id) unique-constraint
                # violation under a concurrent sync race -- the caller
                # (DetectionSyncService) treats this as "already synced by
                # someone else", not a hard failure.
                raise StorageError(
                    "Failed to persist detection",
                    context={"finding_id": detection.finding_id, "error": str(exc)},
                ) from exc
        return detection

    async def get_by_id(self, detection_id: uuid.UUID, org_id: uuid.UUID) -> Detection | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    detections_table.select().where(
                        detections_table.c.detection_id == detection_id,
                        detections_table.c.org_id == org_id,
                    )
                )
            ).one_or_none()
        return None if row is None else self._from_row(row._asdict())

    async def get_by_finding_id(self, finding_id: str, org_id: uuid.UUID) -> Detection | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    detections_table.select().where(
                        detections_table.c.finding_id == finding_id,
                        detections_table.c.org_id == org_id,
                    )
                )
            ).one_or_none()
        return None if row is None else self._from_row(row._asdict())

    async def update(
        self, detection: Detection, *, expected_state: DetectionTriageState | None = None
    ) -> Detection:
        async with self._engine.begin() as conn:
            conditions = [
                detections_table.c.detection_id == detection.detection_id,
                detections_table.c.org_id == detection.org_id,
            ]
            if expected_state is not None:
                conditions.append(detections_table.c.triage_state == expected_state.value)
            result = await conn.execute(
                detections_table.update().where(*conditions).values(**self._to_row(detection))
            )
            if result.rowcount == 0:
                raise StorageError(
                    "Detection not found for update, or its triage state changed concurrently",
                    context={
                        "detection_id": str(detection.detection_id),
                        "expected_state": expected_state.value if expected_state else None,
                    },
                )
        return detection

    async def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[Detection]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                detections_table.select()
                .where(detections_table.c.org_id == org_id)
                .order_by(detections_table.c.synced_at)
            )
            for row in result:
                yield self._from_row(row._asdict())

    async def stream_by_case(
        self, case_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[Detection]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                detections_table.select()
                .where(
                    detections_table.c.case_id == case_id,
                    detections_table.c.org_id == org_id,
                )
                .order_by(detections_table.c.synced_at)
            )
            for row in result:
                yield self._from_row(row._asdict())

    @staticmethod
    def _to_row(d: Detection) -> dict[str, Any]:
        return {
            "detection_id": d.detection_id,
            "org_id": d.org_id,
            "org_alias": d.org_alias,
            "case_id": d.case_id,
            "finding_id": d.finding_id,
            "detector_name": d.detector_name,
            "source_index": d.source_index,
            "rule_matches": [
                {"rule_id": m.rule_id, "rule_name": m.rule_name, "tags": list(m.tags)}
                for m in d.rule_matches
            ],
            "matched_document_ids": list(d.matched_document_ids),
            "finding_timestamp": d.finding_timestamp,
            "triage_state": d.triage_state.value,
            "synced_at": d.synced_at,
            "updated_at": d.updated_at,
            "risk_score": d.risk_score,
            "risk_factors": [
                {
                    "name": f.name,
                    "weight": f.weight,
                    "normalized_value": f.normalized_value,
                    "detail": f.detail,
                }
                for f in d.risk_factors
            ],
            "external_ticket_id": d.external_ticket_id,
        }

    @staticmethod
    def _from_row(row: dict[str, Any]) -> Detection:
        return Detection(
            detection_id=row["detection_id"],
            org_id=row["org_id"],
            org_alias=row["org_alias"],
            case_id=row["case_id"],
            finding_id=row["finding_id"],
            detector_name=row["detector_name"],
            source_index=row["source_index"],
            rule_matches=tuple(
                DetectionRuleMatch(
                    rule_id=m["rule_id"],
                    rule_name=m.get("rule_name"),
                    tags=tuple(m.get("tags", [])),
                )
                for m in (row["rule_matches"] or [])
            ),
            matched_document_ids=tuple(row.get("matched_document_ids") or []),
            finding_timestamp=_ensure_utc(row["finding_timestamp"]),
            triage_state=DetectionTriageState(row["triage_state"]),
            synced_at=_ensure_utc(row["synced_at"]),
            updated_at=_ensure_utc(row["updated_at"]),
            risk_score=row.get("risk_score"),
            risk_factors=tuple(
                RiskFactor(
                    name=f["name"],
                    weight=f["weight"],
                    normalized_value=f.get("normalized_value"),
                    detail=f["detail"],
                )
                for f in (row.get("risk_factors") or [])
            ),
            external_ticket_id=row.get("external_ticket_id"),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
