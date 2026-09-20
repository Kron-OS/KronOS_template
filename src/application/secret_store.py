"""SecretStore: abstract port for per-org connector secret persistence.

Distinct from ``IntegrationSourceKeyRepository``'s hashing (which never
needs the plaintext back -- it only ever verifies an inbound-supplied key
against a stored hash): connector secrets like Defender's ``client_secret``
must be recoverable in plaintext later, since KronOS is the one presenting
them outbound. Reversible storage, not a one-way hash -- see
``poc/vault_secret_store/README.md`` for the real Vault KV-v2 verification
this ABC's Vault-backed implementation (``src/adapter/secret/
vault_secret_store.py``) is built from.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod


class SecretStore(ABC):
    """Org-scoped, reversible secret storage for one connector's secret fields."""

    @abstractmethod
    async def put(self, org_id: uuid.UUID, source_type: str, secrets: dict[str, str]) -> None:
        """Store *secrets* for (org_id, source_type), replacing any prior value."""

    @abstractmethod
    async def get(self, org_id: uuid.UUID, source_type: str) -> dict[str, str] | None:
        """Return the stored secrets for (org_id, source_type), or None if never set."""

    @abstractmethod
    async def delete(self, org_id: uuid.UUID, source_type: str) -> None:
        """Remove any stored secrets for (org_id, source_type). Idempotent."""


class InMemorySecretStore(SecretStore):
    """Thread-unsafe in-memory impl for unit tests and until Vault is wired."""

    def __init__(self) -> None:
        self._store: dict[tuple[uuid.UUID, str], dict[str, str]] = {}

    async def put(self, org_id: uuid.UUID, source_type: str, secrets: dict[str, str]) -> None:
        self._store[(org_id, source_type)] = dict(secrets)

    async def get(self, org_id: uuid.UUID, source_type: str) -> dict[str, str] | None:
        value = self._store.get((org_id, source_type))
        return dict(value) if value is not None else None

    async def delete(self, org_id: uuid.UUID, source_type: str) -> None:
        self._store.pop((org_id, source_type), None)
