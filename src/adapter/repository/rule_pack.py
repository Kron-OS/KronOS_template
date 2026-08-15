"""Abstract and in-memory RulePack repository.

Roadmap M2/C3. Mirrors the DetectionRepository/CaseRepository pattern: an
ABC + a thread-unsafe in-memory default so DI wiring never hard-fails
before Postgres is configured, plus a real Postgres implementation
(postgres_rule_pack.py) for production.

The append-only contract on ``save_version`` is the whole point of this
repository: ``RulePackVersion`` rows are NEVER updated or deleted once
persisted, so creating version N+1 never loses version N (roadmap
invariant #6 -- replayability).
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.rule_pack import RulePack, RulePackVersion


class RulePackRepository(ABC):
    """Org-scoped, append-only persistence for rule packs and their versions."""

    @abstractmethod
    async def get_or_create_pack(self, org_id: uuid.UUID, name: str) -> RulePack:
        """Return the existing (org_id, name) pack, or atomically create one.

        Never creates a second pack for the same (org_id, name) -- the unique
        identity a caller versions against.
        """

    @abstractmethod
    async def save_version(self, version: RulePackVersion) -> RulePackVersion:
        """Persist a new version. Must raise StorageError if (pack_id, version)
        already exists -- versions are append-only, never overwritten."""

    @abstractmethod
    async def get_latest_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> RulePackVersion | None:
        """Return the highest-numbered version for *pack_id* scoped to
        *org_id*, or None if the pack has no versions yet or does not
        belong to *org_id* (defense-in-depth org scoping, mirrors
        ``DetectionRepository.get_by_id``)."""

    @abstractmethod
    async def list_versions(self, pack_id: uuid.UUID) -> list[RulePackVersion]:
        """Return every version for *pack_id*, ascending by version number --
        proof that an older version is never lost when a newer one is added."""

    @abstractmethod
    async def record_publication(
        self, rule_id: uuid.UUID, org_id: uuid.UUID, opensearch_rule_id: str
    ) -> None:
        """Record that *rule_id* has been pushed to OpenSearch as
        *opensearch_rule_id*. Insert-only; idempotent no-op if already
        recorded with the same mapping."""

    @abstractmethod
    async def get_published_opensearch_id(
        self, rule_id: uuid.UUID, org_id: uuid.UUID
    ) -> str | None:
        """Return the OpenSearch rule id *rule_id* was published as, scoped
        to *org_id*, or None if it has never been published or was
        published under a different org (defense-in-depth org scoping,
        mirrors ``DetectionRepository.get_by_id``)."""

    @abstractmethod
    async def delete_publication(self, rule_id: uuid.UUID) -> None:
        """Forget a rule's publication record (used when a rule is removed
        from a pack by a later version). Idempotent."""


class InMemoryRulePackRepository(RulePackRepository):
    """Thread-unsafe in-memory impl for unit tests and until Postgres is wired."""

    def __init__(self) -> None:
        self._packs: dict[uuid.UUID, RulePack] = {}
        self._versions: dict[uuid.UUID, list[RulePackVersion]] = {}
        # rule_id -> (org_id, opensearch_rule_id) -- org_id kept alongside the
        # value so get_published_opensearch_id can scope its lookup, mirroring
        # published_custom_rules_table.org_id in the Postgres implementation.
        self._publications: dict[uuid.UUID, tuple[uuid.UUID, str]] = {}

    async def get_or_create_pack(self, org_id: uuid.UUID, name: str) -> RulePack:
        for pack in self._packs.values():
            if pack.org_id == org_id and pack.name == name:
                return pack
        pack = RulePack(org_id=org_id, name=name)
        self._packs[pack.pack_id] = pack
        self._versions[pack.pack_id] = []
        return pack

    async def save_version(self, version: RulePackVersion) -> RulePackVersion:
        existing = self._versions.setdefault(version.pack_id, [])
        if any(v.version == version.version for v in existing):
            from src.exceptions import StorageError  # noqa: PLC0415

            raise StorageError(
                "RulePackVersion already exists for this (pack_id, version)",
                context={"pack_id": str(version.pack_id), "version": version.version},
            )
        existing.append(version)
        return version

    async def get_latest_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> RulePackVersion | None:
        versions = [v for v in self._versions.get(pack_id, []) if v.org_id == org_id]
        if not versions:
            return None
        return max(versions, key=lambda v: v.version)

    async def list_versions(self, pack_id: uuid.UUID) -> list[RulePackVersion]:
        return sorted(self._versions.get(pack_id, []), key=lambda v: v.version)

    async def record_publication(
        self, rule_id: uuid.UUID, org_id: uuid.UUID, opensearch_rule_id: str
    ) -> None:
        self._publications[rule_id] = (org_id, opensearch_rule_id)

    async def get_published_opensearch_id(
        self, rule_id: uuid.UUID, org_id: uuid.UUID
    ) -> str | None:
        entry = self._publications.get(rule_id)
        if entry is None or entry[0] != org_id:
            return None
        return entry[1]

    async def delete_publication(self, rule_id: uuid.UUID) -> None:
        self._publications.pop(rule_id, None)
