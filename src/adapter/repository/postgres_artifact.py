"""PostgreSQL implementation of ArtifactRepository using SQLAlchemy Core."""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.artifact_repository import ArtifactRepository
from src.domain.artifact import StructuredArtifact
from src.domain.timeline import KronosProvenance
from src.exceptions import StorageError

_metadata = sa.MetaData()

# JSONB (not plain JSON, unlike audit_log.details): content is queried by
# containment (`@>`) once a presentation layer exists, per
# reviews/Data_Source_Module_System.md §9 -- JSONB is the type that
# actually supports that operator.
structured_artifacts_table = sa.Table(
    "structured_artifacts",
    _metadata,
    sa.Column("artifact_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("evidence_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("case_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("kind", sa.String(255), nullable=False, index=True),
    sa.Column("sha256", sa.String(64), nullable=False),
    sa.Column("parser", sa.String(128), nullable=False),
    sa.Column("parser_version", sa.String(64), nullable=False),
    sa.Column("source_path", sa.Text),
    sa.Column("container_sha256", sa.String(64)),
    sa.Column("record_index", sa.Integer, nullable=False),
    sa.Column("content", JSONB, nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresArtifactRepository(ArtifactRepository):
    """Persists and retrieves StructuredArtifact domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def save(self, artifact: StructuredArtifact) -> StructuredArtifact:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    structured_artifacts_table.insert().values(**self._to_row(artifact))
                )
            except Exception as exc:
                raise StorageError(
                    "Failed to persist structured artifact",
                    context={"artifact_id": str(artifact.artifact_id), "error": str(exc)},
                ) from exc
        return artifact

    async def get_by_id(
        self, artifact_id: uuid.UUID, org_id: uuid.UUID
    ) -> StructuredArtifact | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    structured_artifacts_table.select().where(
                        structured_artifacts_table.c.artifact_id == artifact_id,
                        structured_artifacts_table.c.org_id == org_id,
                    )
                )
            ).first()
        return self._from_row(row._asdict()) if row is not None else None

    async def list_by_evidence(
        self, evidence_id: uuid.UUID, org_id: uuid.UUID
    ) -> list[StructuredArtifact]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    structured_artifacts_table.select()
                    .where(
                        structured_artifacts_table.c.evidence_id == evidence_id,
                        structured_artifacts_table.c.org_id == org_id,
                    )
                    .order_by(structured_artifacts_table.c.created_at)
                )
            ).all()
        return [self._from_row(row._asdict()) for row in rows]

    async def list_by_case(self, case_id: uuid.UUID, org_id: uuid.UUID) -> list[StructuredArtifact]:
        # Real, live-verified bug (Milestone FFFFF): no ORDER BY here meant
        # Postgres was free to return rows in any physical order -- the
        # frontend's kind-nav (CaseDetailPage.tsx ArtifactsTab) implicitly
        # depends on "first returned kind" being a stable default selection
        # (originally always windows.pstree in practice, purely by luck of
        # insertion order matching physical storage order on an
        # uncontended table). Adding more on-demand artifact rows for the
        # same evidence file (Milestone EEEEE/FFFFF) was what actually
        # surfaced this via a live a11y run -- the default selection
        # silently became Command Lines instead of Process Tree. Ordering
        # by created_at restores the real, intended "earliest analysis
        # result first" semantic deterministically.
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    structured_artifacts_table.select()
                    .where(
                        structured_artifacts_table.c.case_id == case_id,
                        structured_artifacts_table.c.org_id == org_id,
                    )
                    .order_by(structured_artifacts_table.c.created_at)
                )
            ).all()
        return [self._from_row(row._asdict()) for row in rows]

    @staticmethod
    def _to_row(artifact: StructuredArtifact) -> dict[str, Any]:
        k = artifact.kronos
        return {
            "artifact_id": artifact.artifact_id,
            "evidence_id": k.evidence_id,
            "case_id": k.case_id,
            "org_id": k.org_id,
            "kind": artifact.kind,
            "sha256": k.sha256,
            "parser": k.parser,
            "parser_version": k.parser_version,
            "source_path": k.source_path,
            "container_sha256": k.container_sha256,
            "record_index": k.record_index,
            "content": artifact.content,
            "created_at": k.ingest_timestamp,
        }

    @staticmethod
    def _from_row(row: dict[str, Any]) -> StructuredArtifact:
        return StructuredArtifact(
            artifact_id=row["artifact_id"],
            kind=row["kind"],
            content=row["content"],
            kronos=KronosProvenance(
                evidence_id=row["evidence_id"],
                case_id=row["case_id"],
                org_id=row["org_id"],
                sha256=row["sha256"],
                parser=row["parser"],
                parser_version=row["parser_version"],
                record_index=row["record_index"],
                ingest_timestamp=row["created_at"],
                source_path=row["source_path"],
                container_sha256=row["container_sha256"],
            ),
        )
