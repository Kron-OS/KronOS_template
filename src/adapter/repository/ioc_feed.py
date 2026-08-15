"""Abstract and in-memory IOCFeed repository (roadmap M5/F2).

Mirrors ``src/adapter/repository/rule_pack.py``'s shape: an ABC + a
thread-unsafe in-memory default so DI wiring never hard-fails before
Postgres is configured, plus a real Postgres implementation
(``postgres_ioc_feed.py``) for production.

``match_indicator`` is the one method with no RulePackRepository
equivalent -- IOC matching happens per-``TimelineRecord`` at ingest
(``IOCMatchEnricher``), so it needs a real lookup path, not just "list
everything for publishing". It always searches only the CURRENT (latest)
version of each of the org's feeds -- an older, superseded version's
indicators must never produce a live match (mirrors ``RulePackVersion
.accepted_rules`` only ever being consulted from the latest version via
``RulePackService``), while ``list_versions``/``get_latest_version`` still
expose full history for audit replay.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.ioc_feed import IOCFeed, IOCFeedVersion, IOCIndicator, IOCMatch, IOCType


class IOCFeedRepository(ABC):
    """Org-scoped, append-only persistence for IOC feeds and their versions."""

    @abstractmethod
    async def get_or_create_feed(self, org_id: uuid.UUID, name: str) -> IOCFeed:
        """Return the existing (org_id, name) feed, or atomically create one."""

    @abstractmethod
    async def save_version(self, version: IOCFeedVersion) -> IOCFeedVersion:
        """Persist a new version. Must raise StorageError if (feed_id, version)
        already exists -- versions are append-only, never overwritten."""

    @abstractmethod
    async def get_latest_version(
        self, feed_id: uuid.UUID, org_id: uuid.UUID
    ) -> IOCFeedVersion | None:
        """Return the highest-numbered version for *feed_id* scoped to
        *org_id*, or None if the feed has no versions yet or does not
        belong to *org_id* (defense-in-depth org scoping, mirrors
        ``DetectionRepository.get_by_id``)."""

    @abstractmethod
    async def list_versions(self, feed_id: uuid.UUID) -> list[IOCFeedVersion]:
        """Return every version for *feed_id*, ascending by version number --
        proof that an older version is never lost when a newer one is added."""

    @abstractmethod
    async def match_indicator(
        self, org_id: uuid.UUID, ioc_type: IOCType, value: str
    ) -> IOCMatch | None:
        """Return the first real match for *value* among *org_id*'s feeds'
        CURRENT versions, or None -- an honest "no match", never a
        fabricated one."""


class InMemoryIOCFeedRepository(IOCFeedRepository):
    """Thread-unsafe in-memory impl for unit tests and until Postgres is wired."""

    def __init__(self) -> None:
        self._feeds: dict[uuid.UUID, IOCFeed] = {}
        self._versions: dict[uuid.UUID, list[IOCFeedVersion]] = {}

    async def get_or_create_feed(self, org_id: uuid.UUID, name: str) -> IOCFeed:
        for feed in self._feeds.values():
            if feed.org_id == org_id and feed.name == name:
                return feed
        feed = IOCFeed(org_id=org_id, name=name)
        self._feeds[feed.feed_id] = feed
        self._versions[feed.feed_id] = []
        return feed

    async def save_version(self, version: IOCFeedVersion) -> IOCFeedVersion:
        existing = self._versions.setdefault(version.feed_id, [])
        if any(v.version == version.version for v in existing):
            from src.exceptions import StorageError  # noqa: PLC0415

            raise StorageError(
                "IOCFeedVersion already exists for this (feed_id, version)",
                context={"feed_id": str(version.feed_id), "version": version.version},
            )
        existing.append(version)
        return version

    async def get_latest_version(
        self, feed_id: uuid.UUID, org_id: uuid.UUID
    ) -> IOCFeedVersion | None:
        versions = [v for v in self._versions.get(feed_id, []) if v.org_id == org_id]
        if not versions:
            return None
        return max(versions, key=lambda v: v.version)

    async def list_versions(self, feed_id: uuid.UUID) -> list[IOCFeedVersion]:
        return sorted(self._versions.get(feed_id, []), key=lambda v: v.version)

    async def match_indicator(
        self, org_id: uuid.UUID, ioc_type: IOCType, value: str
    ) -> IOCMatch | None:
        needle = IOCIndicator.normalize(ioc_type, value)
        for feed in self._feeds.values():
            if feed.org_id != org_id:
                continue
            latest = await self.get_latest_version(feed.feed_id, org_id)
            if latest is None:
                continue
            for indicator in latest.indicators:
                if indicator.ioc_type != ioc_type:
                    continue
                if IOCIndicator.normalize(indicator.ioc_type, indicator.value) == needle:
                    return IOCMatch(feed_name=feed.name, indicator=indicator)
        return None
