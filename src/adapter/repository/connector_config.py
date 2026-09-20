"""Abstract and in-memory ConnectorConfigRepository.

Mirrors ``integration_source_key.py``'s exact shape (ABC + thread-unsafe
in-memory default so DI wiring never hard-fails before Postgres is
configured, real Postgres impl in ``postgres_connector_config.py``).
Stores only non-secret fields + which field names are secret-backed --
actual secret VALUES live in a ``SecretStore`` (``src/application/
secret_store.py``, Vault-backed in production), never here.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime

from src.domain.connector import ConnectorConfigSummary


class ConnectorConfigRepository(ABC):
    """Org-scoped persistence for connector configuration (non-secret half)."""

    @abstractmethod
    async def upsert(
        self,
        org_id: uuid.UUID,
        source_type: str,
        non_secret_fields: dict[str, str],
        secret_field_names: tuple[str, ...],
        *,
        enabled: bool = True,
    ) -> ConnectorConfigSummary:
        """Create or replace the config row for (org_id, source_type).

        Resets ``consecutive_failure_count`` to 0 and clears
        ``auto_disabled_at`` -- a fresh ``set_config`` is an explicit admin
        action that supersedes any prior circuit-breaker state."""

    @abstractmethod
    async def get(self, org_id: uuid.UUID, source_type: str) -> ConnectorConfigSummary | None:
        """Return the config row for (org_id, source_type), or None if never configured."""

    @abstractmethod
    async def list_by_org(self, org_id: uuid.UUID) -> list[ConnectorConfigSummary]:
        """Return every configured connector for *org_id*."""

    @abstractmethod
    async def list_all_enabled_by_source_type(self, source_type: str) -> list[ConnectorConfigSummary]:
        """Return every org's enabled row for *source_type*, across all orgs.

        Used only by system-scheduled tasks (e.g. the Defender poll beat
        task) that must discover which orgs to act on without already
        knowing their org_ids -- mirrors ``EvidenceRepository.stream_all_by_state``'s
        own "system tasks only, never a route" scoping (CLAUDE.md SS E.5)."""

    @abstractmethod
    async def delete(self, org_id: uuid.UUID, source_type: str) -> None:
        """Remove the config row for (org_id, source_type). Idempotent."""

    @abstractmethod
    async def set_enabled(
        self, org_id: uuid.UUID, source_type: str, enabled: bool
    ) -> ConnectorConfigSummary | None:
        """Flip the user-controlled ``enabled`` flag; clears ``auto_disabled_at``
        when re-enabling. Returns None if no such config exists."""

    @abstractmethod
    async def record_success(self, org_id: uuid.UUID, source_type: str) -> None:
        """Reset ``consecutive_failure_count`` to 0 after a successful run."""

    @abstractmethod
    async def record_failure(
        self, org_id: uuid.UUID, source_type: str, *, auto_disable_threshold: int
    ) -> ConnectorConfigSummary | None:
        """Increment ``consecutive_failure_count``; at *auto_disable_threshold*
        consecutive failures, set ``auto_disabled_at`` and flip ``enabled=False``.
        Returns the updated summary, or None if no such config exists."""


class InMemoryConnectorConfigRepository(ConnectorConfigRepository):
    """Thread-unsafe in-memory impl for unit tests and until Postgres is wired."""

    def __init__(self) -> None:
        self._rows: dict[tuple[uuid.UUID, str], ConnectorConfigSummary] = {}

    async def upsert(
        self,
        org_id: uuid.UUID,
        source_type: str,
        non_secret_fields: dict[str, str],
        secret_field_names: tuple[str, ...],
        *,
        enabled: bool = True,
    ) -> ConnectorConfigSummary:
        now = datetime.now(UTC)
        existing = self._rows.get((org_id, source_type))
        row = ConnectorConfigSummary(
            org_id=org_id,
            source_type=source_type,
            enabled=enabled,
            non_secret_fields=dict(non_secret_fields),
            secret_field_names=tuple(secret_field_names),
            consecutive_failure_count=0,
            auto_disabled_at=None,
            created_at=existing.created_at if existing is not None else now,
            updated_at=now,
        )
        self._rows[(org_id, source_type)] = row
        return row

    async def get(self, org_id: uuid.UUID, source_type: str) -> ConnectorConfigSummary | None:
        return self._rows.get((org_id, source_type))

    async def list_by_org(self, org_id: uuid.UUID) -> list[ConnectorConfigSummary]:
        return [row for (oid, _st), row in self._rows.items() if oid == org_id]

    async def list_all_enabled_by_source_type(self, source_type: str) -> list[ConnectorConfigSummary]:
        return [
            row
            for (_oid, st), row in self._rows.items()
            if st == source_type and row.enabled
        ]

    async def delete(self, org_id: uuid.UUID, source_type: str) -> None:
        self._rows.pop((org_id, source_type), None)

    async def set_enabled(
        self, org_id: uuid.UUID, source_type: str, enabled: bool
    ) -> ConnectorConfigSummary | None:
        existing = self._rows.get((org_id, source_type))
        if existing is None:
            return None
        updated = existing.model_copy(
            update={
                "enabled": enabled,
                "auto_disabled_at": None if enabled else existing.auto_disabled_at,
                "consecutive_failure_count": 0 if enabled else existing.consecutive_failure_count,
                "updated_at": datetime.now(UTC),
            }
        )
        self._rows[(org_id, source_type)] = updated
        return updated

    async def record_success(self, org_id: uuid.UUID, source_type: str) -> None:
        existing = self._rows.get((org_id, source_type))
        if existing is None or existing.consecutive_failure_count == 0:
            return
        self._rows[(org_id, source_type)] = existing.model_copy(
            update={"consecutive_failure_count": 0, "updated_at": datetime.now(UTC)}
        )

    async def record_failure(
        self, org_id: uuid.UUID, source_type: str, *, auto_disable_threshold: int
    ) -> ConnectorConfigSummary | None:
        existing = self._rows.get((org_id, source_type))
        if existing is None:
            return None
        new_count = existing.consecutive_failure_count + 1
        should_disable = new_count >= auto_disable_threshold and existing.enabled
        updated = existing.model_copy(
            update={
                "consecutive_failure_count": new_count,
                "enabled": False if should_disable else existing.enabled,
                "auto_disabled_at": datetime.now(UTC) if should_disable else existing.auto_disabled_at,
                "updated_at": datetime.now(UTC),
            }
        )
        self._rows[(org_id, source_type)] = updated
        return updated
