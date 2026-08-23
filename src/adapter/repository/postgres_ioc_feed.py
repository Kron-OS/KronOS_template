"""PostgreSQL implementation of IOCFeedRepository using SQLAlchemy Core.

Mirrors ``src/adapter/repository/postgres_rule_pack.py``'s shape for
``ioc_feeds``/``ioc_feed_versions`` (indicator content stored as a JSON
array snapshot per version row; a UNIQUE(feed_id, version) constraint
enforces the append-only contract).

One addition with no RulePack equivalent: ``ioc_feed_current_indicators``,
a materialized, indexed projection of each feed's LATEST version's
indicators only -- ``match_indicator`` runs one indexed-equality query
against it rather than pulling every version's full JSON blob into Python
and scanning, which is the only way a real per-record match lookup stays
cheap. It is derived, never authoritative: fully rebuilt (delete rows for
*feed_id*, insert the new version's) inside the same transaction as
``save_version``, so it can never drift from ``ioc_feed_versions`` (the
real, append-only source of truth) for longer than one transaction.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

from src.adapter.repository._schema_lock import acquire_schema_creation_lock
from src.adapter.repository.ioc_feed import IOCFeedRepository
from src.domain.ioc_feed import IOCFeed, IOCFeedVersion, IOCIndicator, IOCMatch, IOCType
from src.exceptions import StorageError

_metadata = sa.MetaData()

ioc_feeds_table = sa.Table(
    "ioc_feeds",
    _metadata,
    sa.Column("feed_id", sa.UUID(as_uuid=True), primary_key=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("name", sa.String(256), nullable=False),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.UniqueConstraint("org_id", "name", name="uq_ioc_feeds_org_name"),
)

ioc_feed_versions_table = sa.Table(
    "ioc_feed_versions",
    _metadata,
    sa.Column("feed_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("version", sa.Integer, nullable=False),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("source_format", sa.String(32), nullable=False),
    sa.Column("indicators", sa.JSON, nullable=False, default=list),
    sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint("feed_id", "version", name="pk_ioc_feed_versions"),
)

# Materialized "current state" projection -- see module docstring. Indexed
# on the exact tuple match_indicator() queries by so a per-record lookup
# during ingest stays an indexed equality scan, not a JSON table scan.
ioc_feed_current_indicators_table = sa.Table(
    "ioc_feed_current_indicators",
    _metadata,
    sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
    sa.Column("feed_id", sa.UUID(as_uuid=True), nullable=False, index=True),
    sa.Column("org_id", sa.UUID(as_uuid=True), nullable=False),
    sa.Column("feed_name", sa.String(256), nullable=False),
    sa.Column("ioc_type", sa.String(16), nullable=False),
    sa.Column("value_normalized", sa.String(512), nullable=False),
    sa.Column("indicator_json", sa.JSON, nullable=False),
    sa.Index(
        "ix_ioc_current_match",
        "org_id",
        "ioc_type",
        "value_normalized",
    ),
)


class PostgresIOCFeedRepository(IOCFeedRepository):
    """Persists IOCFeed/IOCFeedVersion domain objects via PostgreSQL."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @classmethod
    async def create_tables(cls, engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            await acquire_schema_creation_lock(conn)
            await conn.run_sync(
                lambda sync_conn: _metadata.create_all(bind=sync_conn, checkfirst=True)
            )

    async def get_or_create_feed(self, org_id: uuid.UUID, name: str) -> IOCFeed:
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    ioc_feeds_table.select().where(
                        ioc_feeds_table.c.org_id == org_id, ioc_feeds_table.c.name == name
                    )
                )
            ).one_or_none()
            if row is not None:
                return self._feed_from_row(row._asdict())

            feed = IOCFeed(org_id=org_id, name=name)
            try:
                await conn.execute(
                    ioc_feeds_table.insert().values(
                        feed_id=feed.feed_id,
                        org_id=feed.org_id,
                        name=feed.name,
                        created_at=feed.created_at,
                    )
                )
            except Exception:
                # Race: another writer created the same (org_id, name) feed
                # concurrently -- re-read rather than fail the caller.
                row = (
                    await conn.execute(
                        ioc_feeds_table.select().where(
                            ioc_feeds_table.c.org_id == org_id, ioc_feeds_table.c.name == name
                        )
                    )
                ).one()
                return self._feed_from_row(row._asdict())
            return feed

    async def save_version(self, version: IOCFeedVersion) -> IOCFeedVersion:
        async with self._engine.begin() as conn:
            try:
                await conn.execute(
                    ioc_feed_versions_table.insert().values(**self._version_to_row(version))
                )
            except Exception as exc:
                raise StorageError(
                    "IOCFeedVersion already exists for this (feed_id, version)",
                    context={
                        "feed_id": str(version.feed_id),
                        "version": version.version,
                        "error": str(exc),
                    },
                ) from exc

            # Rebuild the materialized "current" projection for this feed in
            # the SAME transaction -- see module docstring; never a window
            # where the index disagrees with the version just committed.
            feed_row = (
                await conn.execute(
                    ioc_feeds_table.select().where(ioc_feeds_table.c.feed_id == version.feed_id)
                )
            ).one()
            feed_name = feed_row._asdict()["name"]

            await conn.execute(
                ioc_feed_current_indicators_table.delete().where(
                    ioc_feed_current_indicators_table.c.feed_id == version.feed_id
                )
            )
            if version.indicators:
                await conn.execute(
                    ioc_feed_current_indicators_table.insert(),
                    [
                        {
                            "feed_id": version.feed_id,
                            "org_id": version.org_id,
                            "feed_name": feed_name,
                            "ioc_type": indicator.ioc_type.value,
                            "value_normalized": IOCIndicator.normalize(
                                indicator.ioc_type, indicator.value
                            ),
                            "indicator_json": self._indicator_to_dict(indicator),
                        }
                        for indicator in version.indicators
                    ],
                )
        return version

    async def get_latest_version(
        self, feed_id: uuid.UUID, org_id: uuid.UUID
    ) -> IOCFeedVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    ioc_feed_versions_table.select()
                    .where(
                        ioc_feed_versions_table.c.feed_id == feed_id,
                        ioc_feed_versions_table.c.org_id == org_id,
                    )
                    .order_by(ioc_feed_versions_table.c.version.desc())
                    .limit(1)
                )
            ).one_or_none()
        return None if row is None else self._version_from_row(row._asdict())

    async def list_versions(self, feed_id: uuid.UUID, org_id: uuid.UUID) -> list[IOCFeedVersion]:
        async with self._engine.connect() as conn:
            result = await conn.execute(
                ioc_feed_versions_table.select()
                .where(
                    ioc_feed_versions_table.c.feed_id == feed_id,
                    ioc_feed_versions_table.c.org_id == org_id,
                )
                .order_by(ioc_feed_versions_table.c.version.asc())
            )
            return [self._version_from_row(row._asdict()) for row in result]

    async def match_indicator(
        self, org_id: uuid.UUID, ioc_type: IOCType, value: str
    ) -> IOCMatch | None:
        needle = IOCIndicator.normalize(ioc_type, value)
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    ioc_feed_current_indicators_table.select()
                    .where(
                        ioc_feed_current_indicators_table.c.org_id == org_id,
                        ioc_feed_current_indicators_table.c.ioc_type == ioc_type.value,
                        ioc_feed_current_indicators_table.c.value_normalized == needle,
                    )
                    .limit(1)
                )
            ).one_or_none()
        if row is None:
            return None
        d = row._asdict()
        return IOCMatch(
            feed_name=d["feed_name"], indicator=self._indicator_from_dict(d["indicator_json"])
        )

    @staticmethod
    def _feed_from_row(row: dict[str, Any]) -> IOCFeed:
        return IOCFeed(
            feed_id=row["feed_id"],
            org_id=row["org_id"],
            name=row["name"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _indicator_to_dict(indicator: IOCIndicator) -> dict[str, Any]:
        return {
            "indicator_id": str(indicator.indicator_id),
            "ioc_type": indicator.ioc_type.value,
            "value": indicator.value,
            "confidence": indicator.confidence,
            "description": indicator.description,
            "source_ref": indicator.source_ref,
        }

    @staticmethod
    def _indicator_from_dict(d: dict[str, Any]) -> IOCIndicator:
        return IOCIndicator(
            indicator_id=uuid.UUID(d["indicator_id"]),
            ioc_type=IOCType(d["ioc_type"]),
            value=d["value"],
            confidence=d.get("confidence"),
            description=d.get("description"),
            source_ref=d.get("source_ref"),
        )

    @classmethod
    def _version_to_row(cls, v: IOCFeedVersion) -> dict[str, Any]:
        return {
            "feed_id": v.feed_id,
            "version": v.version,
            "org_id": v.org_id,
            "source_format": v.source_format,
            "indicators": [cls._indicator_to_dict(i) for i in v.indicators],
            "created_at": v.created_at,
        }

    @classmethod
    def _version_from_row(cls, row: dict[str, Any]) -> IOCFeedVersion:
        indicators = tuple(cls._indicator_from_dict(i) for i in row["indicators"])
        return IOCFeedVersion(
            feed_id=row["feed_id"],
            version=row["version"],
            org_id=row["org_id"],
            source_format=row["source_format"],
            indicators=indicators,
            created_at=_ensure_utc(row["created_at"]),
        )


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
