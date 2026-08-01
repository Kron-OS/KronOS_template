"""PostgreSQL implementation of YaraRulePackRepository using SQLAlchemy Core.

Mirrors ``src/adapter/repository/postgres_rule_pack.py``'s shape. Rule
content (``rules``) is stored as a JSON array snapshot per version row --
append-only, never mutated: a UNIQUE(pack_id, version) constraint is the
enforcement mechanism behind ``YaraRulePackRepository``'s "versions are
never overwritten" contract (roadmap invariant #6).

``yara_rule_pack_published`` is a separate, genuinely-mutable pointer table
(unlike ``rule_pack_versions``/``yara_rule_pack_versions``, which are
insert-only) -- it upserts via
``sqlalchemy.dialects.postgresql.insert(...).on_conflict_do_update``, the
same pattern already used by ``postgres_audit_log.py``'s TSA-anchor
upsert. Repointing which version is published never touches the immutable
version rows themselves.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.yara_rule_pack import YaraRulePackRepository
from src.domain.rule_pack import RulePackSourceTier
from src.domain.yara_rule_pack import YaraRule, YaraRulePack, YaraRulePackVersion
from src.exceptions import StorageError

_metadata = sa.MetaData()

yara_rule_packs_table = sa.Table(
    "yara_rule_packs",
    _metadata,
    sa.Column("pack_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("org_id", "name", name="uq_yara_rule_packs_org_name"),
)

yara_rule_pack_versions_table = sa.Table(
    "yara_rule_pack_versions",
    _metadata,
    sa.Column("pack_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("version", sa.Integer, nullable=False),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("source_tier", sa.String(32), nullable=False),
    sa.Column("rules", sa.JSON, nullable=False, default=list),
    sa.Column("signature_verified", sa.Boolean, nullable=False, default=False),
    sa.Column("content_sha256", sa.String(64), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint("pack_id", "version", name="pk_yara_rule_pack_versions"),
)

yara_rule_pack_published_table = sa.Table(
    "yara_rule_pack_published",
    _metadata,
    sa.Column("pack_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("version", sa.Integer, nullable=False),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresYaraRulePackRepository(YaraRulePackRepository):
    """Persists YaraRulePack/YaraRulePackVersion domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def get_or_create_pack(self, org_id: uuid.UUID, name: str) -> YaraRulePack:
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    yara_rule_packs_table.select().where(
                        yara_rule_packs_table.c.org_id == org_id,
                        yara_rule_packs_table.c.name == name,
                    )
                )
            ).one_or_none()
            if row is not None:
                return self._pack_from_row(row._asdict())

            pack = YaraRulePack(org_id=org_id, name=name)
            try:
                await conn.execute(
                    yara_rule_packs_table.insert().values(
                        pack_id=pack.pack_id,
                        org_id=pack.org_id,
                        name=pack.name,
                        created_at=pack.created_at,
                    )
                )
            except Exception:
                # Race: another writer created the same (org_id, name) pack
                # concurrently -- re-read rather than fail the caller.
                row = (
                    await conn.execute(
                        yara_rule_packs_table.select().where(
                            yara_rule_packs_table.c.org_id == org_id,
                            yara_rule_packs_table.c.name == name,
                        )
                    )
                ).one()
                return self._pack_from_row(row._asdict())
            return pack

    async def save_version(self, version: YaraRulePackVersion) -> YaraRulePackVersion:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    yara_rule_pack_versions_table.insert().values(**self._version_to_row(version))
                )
            except Exception as exc:
                raise StorageError(
                    "YaraRulePackVersion already exists for this (pack_id, version)",
                    context={
                        "pack_id": str(version.pack_id),
                        "version": version.version,
                        "error": str(exc),
                    },
                ) from exc
        return version

    async def get_latest_version(self, pack_id: uuid.UUID) -> YaraRulePackVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    yara_rule_pack_versions_table.select()
                    .where(yara_rule_pack_versions_table.c.pack_id == pack_id)
                    .order_by(yara_rule_pack_versions_table.c.version.desc())
                    .limit(1)
                )
            ).one_or_none()
        return None if row is None else self._version_from_row(row._asdict())

    async def list_versions(self, pack_id: uuid.UUID) -> list[YaraRulePackVersion]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                yara_rule_pack_versions_table.select()
                .where(yara_rule_pack_versions_table.c.pack_id == pack_id)
                .order_by(yara_rule_pack_versions_table.c.version.asc())
            )
            return [self._version_from_row(row._asdict()) for row in result]

    async def publish_version(self, pack_id: uuid.UUID, version: int) -> None:
        async with self._engine.begin() as conn:
            pack_row = (
                await conn.execute(
                    yara_rule_packs_table.select().where(yara_rule_packs_table.c.pack_id == pack_id)
                )
            ).one()
            org_id = pack_row._asdict()["org_id"]
            stmt = pg_insert(yara_rule_pack_published_table).values(
                pack_id=pack_id,
                version=version,
                org_id=org_id,
                updated_at=datetime.now(UTC),
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["pack_id"],
                set_={
                    "version": stmt.excluded.version,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
            await conn.execute(stmt)

    async def get_published_version(self, pack_id: uuid.UUID) -> YaraRulePackVersion | None:
        async with self._engine.connect() as conn:
            pointer_row = (
                await conn.execute(
                    yara_rule_pack_published_table.select().where(
                        yara_rule_pack_published_table.c.pack_id == pack_id
                    )
                )
            ).one_or_none()
            if pointer_row is None:
                return None
            published_version = pointer_row._asdict()["version"]
            row = (
                await conn.execute(
                    yara_rule_pack_versions_table.select().where(
                        yara_rule_pack_versions_table.c.pack_id == pack_id,
                        yara_rule_pack_versions_table.c.version == published_version,
                    )
                )
            ).one_or_none()
        return None if row is None else self._version_from_row(row._asdict())

    async def list_published_versions_for_org(self, org_id: uuid.UUID) -> list[YaraRulePackVersion]:
        async with self._engine.connect() as conn:
            pointer_rows = (
                await conn.execute(
                    yara_rule_pack_published_table.select().where(
                        yara_rule_pack_published_table.c.org_id == org_id
                    )
                )
            ).all()
            results: list[YaraRulePackVersion] = []
            for pointer_row in pointer_rows:
                pointer = pointer_row._asdict()
                row = (
                    await conn.execute(
                        yara_rule_pack_versions_table.select().where(
                            yara_rule_pack_versions_table.c.pack_id == pointer["pack_id"],
                            yara_rule_pack_versions_table.c.version == pointer["version"],
                        )
                    )
                ).one_or_none()
                if row is not None:
                    results.append(self._version_from_row(row._asdict()))
        return results

    @staticmethod
    def _pack_from_row(row: dict[str, Any]) -> YaraRulePack:
        return YaraRulePack(
            pack_id=row["pack_id"],
            org_id=row["org_id"],
            name=row["name"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _version_to_row(v: YaraRulePackVersion) -> dict[str, Any]:
        return {
            "pack_id": v.pack_id,
            "version": v.version,
            "org_id": v.org_id,
            "source_tier": v.source_tier.value,
            "rules": [
                {
                    "rule_id": str(r.rule_id),
                    "name": r.name,
                    "rule_source": r.rule_source,
                    "created_at": r.created_at.isoformat(),
                }
                for r in v.rules
            ],
            "signature_verified": v.signature_verified,
            "content_sha256": v.content_sha256,
            "created_at": v.created_at,
        }

    @staticmethod
    def _version_from_row(row: dict[str, Any]) -> YaraRulePackVersion:
        rules = tuple(
            YaraRule(
                rule_id=uuid.UUID(r["rule_id"]),
                name=r["name"],
                rule_source=r["rule_source"],
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in row["rules"]
        )
        return YaraRulePackVersion(
            pack_id=row["pack_id"],
            version=row["version"],
            org_id=row["org_id"],
            source_tier=RulePackSourceTier(row["source_tier"]),
            rules=rules,
            signature_verified=row["signature_verified"],
            content_sha256=row.get("content_sha256"),
            created_at=_ensure_utc(row["created_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
