"""PostgreSQL implementation of CaseRepository using SQLAlchemy Core."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository.case_repository import CaseRepository
from src.domain.case import Case, CaseMetadata, CaseStatus
from src.exceptions import StorageError

_metadata = sa.MetaData()

cases_table = sa.Table(
    "cases",
    _metadata,
    sa.Column("case_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("org_alias", sa.String(128), nullable=False),
    sa.Column("owner_user_id", sa.UUID(as_uuid=True), nullable=False),
    sa.Column("title", sa.String(255), nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("reference_number", sa.String(255)),
    sa.Column("classification", sa.String(64), nullable=False, server_default="UNCLASSIFIED"),
    sa.Column("status", sa.String(32), nullable=False, server_default="open"),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresCaseRepository(CaseRepository):
    """Persists and retrieves Case domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await conn.run_sync(_metadata.create_all)

    async def save(self, case: Case) -> Case:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(cases_table.insert().values(**self._to_row(case)))
            except Exception as exc:
                raise StorageError(
                    "Failed to persist case",
                    context={"case_id": str(case.case_id), "error": str(exc)},
                ) from exc
        return case

    async def get_by_id(self, case_id: uuid.UUID, org_id: uuid.UUID) -> Case | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    cases_table.select().where(
                        cases_table.c.case_id == case_id,
                        cases_table.c.org_id == org_id,
                    )
                )
            ).one_or_none()
        if row is None:
            return None
        return self._from_row(row._asdict())

    async def list_by_org(
        self, org_id: uuid.UUID, page: int = 1, page_size: int = 50
    ) -> tuple[list[Case], int]:
        async with self._engine.connect() as conn:
            count_row = await conn.execute(
                sa.select(sa.func.count()).select_from(cases_table).where(
                    cases_table.c.org_id == org_id
                )
            )
            total: int = count_row.scalar_one()

            offset = (page - 1) * page_size
            rows = (
                await conn.execute(
                    cases_table.select()
                    .where(cases_table.c.org_id == org_id)
                    .order_by(cases_table.c.created_at.desc())
                    .limit(page_size)
                    .offset(offset)
                )
            ).fetchall()

        return [self._from_row(r._asdict()) for r in rows], total

    async def update(self, case: Case) -> Case:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                cases_table.update()
                .where(
                    cases_table.c.case_id == case.case_id,
                    cases_table.c.org_id == case.org_id,
                )
                .values(**self._to_row(case))
            )
            if result.rowcount == 0:
                raise StorageError(
                    "Case not found for update",
                    context={"case_id": str(case.case_id)},
                )
        return case

    async def delete(self, case_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                cases_table.delete().where(
                    cases_table.c.case_id == case_id,
                    cases_table.c.org_id == org_id,
                )
            )
        return result.rowcount > 0

    @staticmethod
    def _to_row(case: Case) -> dict[str, Any]:
        return {
            "case_id": case.case_id,
            "org_id": case.org_id,
            "org_alias": case.org_alias,
            "owner_user_id": case.owner_user_id,
            "title": case.metadata.title,
            "description": case.metadata.description,
            "reference_number": case.metadata.reference_number,
            "classification": case.metadata.classification,
            "status": case.status.value,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
        }

    @staticmethod
    def _from_row(row: dict[str, Any]) -> Case:
        return Case(
            case_id=row["case_id"],
            org_id=row["org_id"],
            org_alias=row["org_alias"],
            owner_user_id=row["owner_user_id"],
            metadata=CaseMetadata(
                title=row["title"],
                description=row["description"],
                reference_number=row["reference_number"],
                classification=row["classification"] or "UNCLASSIFIED",
            ),
            status=CaseStatus(row["status"]),
            created_at=_ensure_utc(row["created_at"]),
            updated_at=_ensure_utc(row["updated_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
