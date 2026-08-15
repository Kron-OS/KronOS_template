"""PostgreSQL implementation of RulePackRepository using SQLAlchemy Core.

Mirrors src/adapter/repository/postgres_detection.py's shape. Rule content
(``rules``) is stored as a JSON array snapshot per version row -- append-
only, never mutated: a UNIQUE(pack_id, version) constraint is the
enforcement mechanism behind RulePackRepository's "versions are never
overwritten" contract (roadmap invariant #6).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.rule_pack import RulePackRepository
from src.domain.rule_pack import (
    CostGateDecision,
    CostGateFinding,
    CostGateVerdict,
    CustomRule,
    RulePack,
    RulePackSourceTier,
    RulePackVersion,
)
from src.exceptions import StorageError

_metadata = sa.MetaData()

rule_packs_table = sa.Table(
    "rule_packs",
    _metadata,
    sa.Column("pack_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("org_id", "name", name="uq_rule_packs_org_name"),
)

rule_pack_versions_table = sa.Table(
    "rule_pack_versions",
    _metadata,
    sa.Column("pack_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("version", sa.Integer, nullable=False),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("source_tier", sa.String(32), nullable=False),
    sa.Column("rules", sa.JSON, nullable=False, default=list),
    sa.Column("signature_verified", sa.Boolean, nullable=False, default=False),
    sa.Column("content_sha256", sa.String(64), nullable=True),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint("pack_id", "version", name="pk_rule_pack_versions"),
)

published_custom_rules_table = sa.Table(
    "published_custom_rules",
    _metadata,
    sa.Column("rule_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("opensearch_rule_id", sa.String(128), nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
)


class PostgresRulePackRepository(RulePackRepository):
    """Persists RulePack/RulePackVersion domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def get_or_create_pack(self, org_id: uuid.UUID, name: str) -> RulePack:
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    rule_packs_table.select().where(
                        rule_packs_table.c.org_id == org_id, rule_packs_table.c.name == name
                    )
                )
            ).one_or_none()
            if row is not None:
                return self._pack_from_row(row._asdict())

            pack = RulePack(org_id=org_id, name=name)
            try:
                await conn.execute(
                    rule_packs_table.insert().values(
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
                        rule_packs_table.select().where(
                            rule_packs_table.c.org_id == org_id, rule_packs_table.c.name == name
                        )
                    )
                ).one()
                return self._pack_from_row(row._asdict())
            return pack

    async def save_version(self, version: RulePackVersion) -> RulePackVersion:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    rule_pack_versions_table.insert().values(**self._version_to_row(version))
                )
            except Exception as exc:
                raise StorageError(
                    "RulePackVersion already exists for this (pack_id, version)",
                    context={"pack_id": str(version.pack_id), "version": version.version, "error": str(exc)},
                ) from exc
        return version

    async def get_latest_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> RulePackVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    rule_pack_versions_table.select()
                    .where(
                        rule_pack_versions_table.c.pack_id == pack_id,
                        rule_pack_versions_table.c.org_id == org_id,
                    )
                    .order_by(rule_pack_versions_table.c.version.desc())
                    .limit(1)
                )
            ).one_or_none()
        return None if row is None else self._version_from_row(row._asdict())

    async def list_versions(self, pack_id: uuid.UUID) -> list[RulePackVersion]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                rule_pack_versions_table.select()
                .where(rule_pack_versions_table.c.pack_id == pack_id)
                .order_by(rule_pack_versions_table.c.version.asc())
            )
            return [self._version_from_row(row._asdict()) for row in result]

    async def record_publication(
        self, rule_id: uuid.UUID, org_id: uuid.UUID, opensearch_rule_id: str
    ) -> None:
        async with self._engine.begin() as conn:
            existing = (
                await conn.execute(
                    published_custom_rules_table.select().where(
                        published_custom_rules_table.c.rule_id == rule_id
                    )
                )
            ).one_or_none()
            if existing is not None:
                return
            await conn.execute(
                published_custom_rules_table.insert().values(
                    rule_id=rule_id,
                    org_id=org_id,
                    opensearch_rule_id=opensearch_rule_id,
                    created_at=datetime.now(UTC),
                )
            )

    async def get_published_opensearch_id(
        self, rule_id: uuid.UUID, org_id: uuid.UUID
    ) -> str | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    published_custom_rules_table.select().where(
                        published_custom_rules_table.c.rule_id == rule_id,
                        published_custom_rules_table.c.org_id == org_id,
                    )
                )
            ).one_or_none()
        return None if row is None else str(row._asdict()["opensearch_rule_id"])

    async def delete_publication(self, rule_id: uuid.UUID) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                published_custom_rules_table.delete().where(
                    published_custom_rules_table.c.rule_id == rule_id
                )
            )

    @staticmethod
    def _pack_from_row(row: dict[str, Any]) -> RulePack:
        return RulePack(
            pack_id=row["pack_id"], org_id=row["org_id"], name=row["name"], created_at=row["created_at"]
        )

    @staticmethod
    def _version_to_row(v: RulePackVersion) -> dict[str, Any]:
        return {
            "pack_id": v.pack_id,
            "version": v.version,
            "org_id": v.org_id,
            "source_tier": v.source_tier.value,
            "rules": [
                {
                    "rule_id": str(r.rule_id),
                    "title": r.title,
                    "log_type": r.log_type,
                    "sigma_yaml": r.sigma_yaml,
                    "opensearch_rule_id": r.opensearch_rule_id,
                    "created_at": r.created_at.isoformat(),
                    "cost_gate_verdict": {
                        "decision": r.cost_gate_verdict.decision.value,
                        "findings": [
                            {"heuristic": f.heuristic, "reason": f.reason}
                            for f in r.cost_gate_verdict.findings
                        ],
                    },
                }
                for r in v.rules
            ],
            "signature_verified": v.signature_verified,
            "content_sha256": v.content_sha256,
            "created_at": v.created_at,
        }

    @staticmethod
    def _version_from_row(row: dict[str, Any]) -> RulePackVersion:
        rules = tuple(
            CustomRule(
                rule_id=uuid.UUID(r["rule_id"]),
                title=r["title"],
                log_type=r["log_type"],
                sigma_yaml=r["sigma_yaml"],
                opensearch_rule_id=r.get("opensearch_rule_id"),
                created_at=datetime.fromisoformat(r["created_at"]),
                cost_gate_verdict=CostGateVerdict(
                    decision=CostGateDecision(r["cost_gate_verdict"]["decision"]),
                    findings=tuple(
                        CostGateFinding(heuristic=f["heuristic"], reason=f["reason"])
                        for f in r["cost_gate_verdict"]["findings"]
                    ),
                ),
            )
            for r in row["rules"]
        )
        return RulePackVersion(
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
