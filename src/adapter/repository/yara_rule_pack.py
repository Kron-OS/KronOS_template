"""Abstract and in-memory YaraRulePack repository.

Roadmap E4. Mirrors ``src/adapter/repository/rule_pack.py``'s pattern: an
ABC + a thread-unsafe in-memory default so DI wiring never hard-fails
before Postgres is configured, plus a real Postgres implementation
(``postgres_yara_rule_pack.py``) for production.

The append-only contract on ``save_version`` is the whole point of this
repository, exactly as it is for ``RulePackRepository``:
``YaraRulePackVersion`` rows are NEVER updated or deleted once persisted,
so creating version N+1 never loses version N (roadmap invariant #6 --
replayability).

``publish_version``/``get_published_version``/``list_published_versions_for_org``
are a SEPARATE, mutable pointer mechanism layered on top of that immutable
version history -- publishing never rewrites or removes a version row,
only records/updates which already-persisted version number is currently
"live" for a pack. This is the concrete integration point
``SignedYaraRulePackProvider`` (``src/application/yara_rules.py``) reads
from.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.yara_rule_pack import YaraRulePack, YaraRulePackVersion


class YaraRulePackRepository(ABC):
    """Org-scoped, append-only persistence for YARA rule packs and their versions."""

    @abstractmethod
    async def get_or_create_pack(self, org_id: uuid.UUID, name: str) -> YaraRulePack:
        """Return the existing (org_id, name) pack, or atomically create one.

        Never creates a second pack for the same (org_id, name) -- the unique
        identity a caller versions against.
        """

    @abstractmethod
    async def save_version(self, version: YaraRulePackVersion) -> YaraRulePackVersion:
        """Persist a new version. Must raise StorageError if (pack_id, version)
        already exists -- versions are append-only, never overwritten."""

    @abstractmethod
    async def get_latest_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> YaraRulePackVersion | None:
        """Return the highest-numbered version for *pack_id* scoped to
        *org_id*, or None if the pack has no versions yet or does not
        belong to *org_id* (defense-in-depth org scoping, mirrors
        ``DetectionRepository.get_by_id``)."""

    @abstractmethod
    async def list_versions(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> list[YaraRulePackVersion]:
        """Return every version for *pack_id* scoped to *org_id*, ascending
        by version number -- proof that an older version is never lost when
        a newer one is added, and defense-in-depth org scoping (mirrors
        ``get_latest_version``/``get_published_version``; see
        ``rule_pack.py``'s identical fix, Gap Audit Milestone RR)."""

    @abstractmethod
    async def publish_version(self, pack_id: uuid.UUID, version: int) -> None:
        """Mark *version* as the currently-active version for *pack_id*.

        Idempotent upsert of a pointer, NOT a mutation of the version row
        itself -- calling this again with a different version number simply
        repoints which already-persisted version is "live"; every version
        this ever pointed to remains independently retrievable via
        ``list_versions``/``get_latest_version``. Caller (the service layer)
        is responsible for confirming *version* actually exists for
        *pack_id* before calling this -- the repository does not itself
        cross-check against ``rule_pack_versions``.
        """

    @abstractmethod
    async def get_published_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> YaraRulePackVersion | None:
        """Return the currently-published version for *pack_id* scoped to
        *org_id*, or None if no version has ever been published or the pack
        does not belong to *org_id* (defense-in-depth org scoping, mirrors
        ``DetectionRepository.get_by_id``)."""

    @abstractmethod
    async def list_published_versions_for_org(self, org_id: uuid.UUID) -> list[YaraRulePackVersion]:
        """Return the currently-published version of every pack belonging to
        *org_id* that has one (packs with nothing published yet are
        skipped, not represented as an error or a placeholder).

        This is what ``SignedYaraRulePackProvider.get_rule_source()`` reads
        from directly: an org can own multiple named packs, and every one
        of them that has a published version contributes its rule text to
        the single combined YARA-X source string returned to
        ``ZipArchiveParser``/``TarArchiveParser``.
        """


class InMemoryYaraRulePackRepository(YaraRulePackRepository):
    """Thread-unsafe in-memory impl for unit tests and until Postgres is wired."""

    def __init__(self) -> None:
        self._packs: dict[uuid.UUID, YaraRulePack] = {}
        self._versions: dict[uuid.UUID, list[YaraRulePackVersion]] = {}
        self._published: dict[uuid.UUID, int] = {}

    async def get_or_create_pack(self, org_id: uuid.UUID, name: str) -> YaraRulePack:
        for pack in self._packs.values():
            if pack.org_id == org_id and pack.name == name:
                return pack
        pack = YaraRulePack(org_id=org_id, name=name)
        self._packs[pack.pack_id] = pack
        self._versions[pack.pack_id] = []
        return pack

    async def save_version(self, version: YaraRulePackVersion) -> YaraRulePackVersion:
        existing = self._versions.setdefault(version.pack_id, [])
        if any(v.version == version.version for v in existing):
            from src.exceptions import StorageError  # noqa: PLC0415

            raise StorageError(
                "YaraRulePackVersion already exists for this (pack_id, version)",
                context={"pack_id": str(version.pack_id), "version": version.version},
            )
        existing.append(version)
        return version

    async def get_latest_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> YaraRulePackVersion | None:
        versions = [v for v in self._versions.get(pack_id, []) if v.org_id == org_id]
        if not versions:
            return None
        return max(versions, key=lambda v: v.version)

    async def list_versions(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> list[YaraRulePackVersion]:
        versions = [v for v in self._versions.get(pack_id, []) if v.org_id == org_id]
        return sorted(versions, key=lambda v: v.version)

    async def publish_version(self, pack_id: uuid.UUID, version: int) -> None:
        self._published[pack_id] = version

    async def get_published_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> YaraRulePackVersion | None:
        published_num = self._published.get(pack_id)
        if published_num is None:
            return None
        for v in self._versions.get(pack_id, []):
            if v.version == published_num and v.org_id == org_id:
                return v
        return None

    async def list_published_versions_for_org(self, org_id: uuid.UUID) -> list[YaraRulePackVersion]:
        results: list[YaraRulePackVersion] = []
        for pack in self._packs.values():
            if pack.org_id != org_id:
                continue
            published = await self.get_published_version(pack.pack_id, org_id)
            if published is not None:
                results.append(published)
        return results
