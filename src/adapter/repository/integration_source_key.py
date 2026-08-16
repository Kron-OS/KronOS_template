"""Abstract and in-memory IntegrationSourceKeyRepository (roadmap Q1 /
Milestone W8, Gap Audit P1-7).

Replaces the boot-time-only static dict
(``StaticApiKeyInboundAuthenticator``'s old ``provisioned_keys`` constructor
argument, seeded once from ``Settings``/Vault at process start) with a real,
per-request-queried repository -- the only way an admin-provisioned key can
ever take effect without restarting the whole backend process. Mirrors
``RulePackRepository``/``SourceCursorRepository``'s own established shape
exactly: an ABC + a thread-unsafe in-memory default so DI wiring never
hard-fails before Postgres is configured, plus a real Postgres
implementation (``postgres_integration_source_key.py``) for production.
Org-scoped queries follow the same defense-in-depth precedent
``RulePackRepository`` adopted in P2-W10 (``get_latest_version``/
``get_published_opensearch_id`` both require ``org_id``) -- applied here
from the start rather than added later.

Hashing, not encryption, not plaintext (non-negotiable, CLAUDE.md's own
security-embedded principle): the plaintext API key is never persisted.
``_hash_api_key`` computes a SHA-256 digest of the UTF-8 key bytes, and
every persisted row stores only that hash -- ``get_by_key(api_key)`` hashes
the caller-supplied key the same way and looks it up by an exact, indexed
match. SHA-256 (not a slow/salted password hash like bcrypt/argon2) is the
right primitive here specifically because these are high-entropy random
tokens (``secrets.token_urlsafe(32)`` -- 256 bits of real entropy), not
low-entropy human-chosen passwords: a slow hash defends against an offline
brute-force guessing attack on a small keyspace, which is not the threat
model for a 256-bit random token (brute-forcing a preimage of a random
256-bit value is infeasible regardless of hash speed). The tradeoff this
buys back: hashing first means the plaintext key is never stored or
comparable in the clear anywhere at rest, in exchange for turning "is this
exact key provisioned" into a real, indexed, exact-match DB lookup --
which is in principle a timing-observable "does this hash exist" signal
(unlike the in-memory ``hmac.compare_digest`` linear scan Milestone W6
added, which compared every candidate unconditionally). That in-memory scan
becomes moot with a real DB-backed lookup-by-hash: the meaningful attack
surface for guessing a 256-bit random token byte-by-byte via timing was
never realistic to begin with (a scan over "does index B-tree have this
value" gives no exploitable per-byte signal the way a linear plaintext
comparison loop could), and a proportionate, indexed persisted-store design
is a deliberate, accepted tradeoff for provisioned API-key storage
generally -- not a regression of W6's own fix, but its correct evolution
once storage moved from an in-process dict to a real database.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime

from src.domain.integration_source import ProvisionedApiKeySummary, StaticApiKeyProvisioning

_API_KEY_BYTES = 32  # secrets.token_urlsafe(32) -- 256 bits of real entropy.


def generate_api_key() -> str:
    """Generate a fresh, cryptographically random plaintext API key.

    Never a predictable value (CLAUDE.md SS F / this milestone's own
    binding design decision) -- ``secrets.token_urlsafe`` is Python's own
    CSPRNG-backed token generator, not ``random``.
    """
    return secrets.token_urlsafe(_API_KEY_BYTES)


def hash_api_key(api_key: str) -> str:
    """SHA-256 hex digest of *api_key* -- see this module's own docstring
    for why SHA-256 (not a slow password hash) is the right primitive for a
    high-entropy random token."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class IntegrationSourceKeyRepository(ABC):
    """Org-scoped persistence for provisioned inbound-push API keys.

    ``get_by_key`` is the real per-request lookup path
    ``StaticApiKeyInboundAuthenticator.authenticate`` calls on every inbound
    push -- unlike the old static dict, this queries live storage, so a key
    provisioned a moment ago is usable immediately, no process restart
    required.
    """

    @abstractmethod
    async def provision(
        self, org_id: uuid.UUID, source_id: str, source_type: str
    ) -> StaticApiKeyProvisioning:
        """Generate a real, random API key for (org_id, source_id), persist
        only its hash, and return the full record INCLUDING the plaintext
        key -- the one and only time it is ever available again (standard
        "shown once" API-key issuance UX). Calling this again for the same
        (org_id, source_id) rotates the key: the previous key stops
        resolving via ``get_by_key`` and a fresh one is returned."""

    @abstractmethod
    async def get_by_key(self, api_key: str) -> StaticApiKeyProvisioning | None:
        """Return the provisioning record for *api_key*, or None if no
        non-revoked provisioned key hashes to match. Never returns a
        revoked key's provisioning -- a revoked key is indistinguishable
        from a never-provisioned one to this lookup."""

    @abstractmethod
    async def list_by_org(self, org_id: uuid.UUID) -> list[ProvisionedApiKeySummary]:
        """Return every key (including revoked ones, for audit visibility)
        provisioned for *org_id* -- NEVER includes plaintext key material
        (``ProvisionedApiKeySummary`` has no field for it; see that type's
        own docstring)."""

    @abstractmethod
    async def revoke(self, org_id: uuid.UUID, source_id: str) -> None:
        """Mark the (org_id, source_id) key as revoked. Idempotent: a
        no-op if already revoked or never provisioned -- scoped to
        *org_id* so one org can never revoke another org's key even if it
        somehow learned the source_id."""


class InMemoryIntegrationSourceKeyRepository(IntegrationSourceKeyRepository):
    """Thread-unsafe in-memory impl for unit tests and until Postgres is wired.

    Deliberately stores only the hash (never the plaintext), mirroring the
    Postgres implementation's own storage contract exactly -- this repo's
    behavior (a lookup miss on a revoked key, hash-based matching) must be
    identical to the real one for tests exercised against this double to
    mean anything.
    """

    def __init__(self) -> None:
        # (org_id, source_id) -> provisioning, api_key overwritten with the
        # plaintext at construction time only; the "stored" representation
        # is _hash_by_key below -- this dict is intentionally NOT what
        # get_by_key searches, to mirror the Postgres impl's "hash is the
        # only true index" shape instead of taking an in-memory shortcut.
        self._records: dict[tuple[uuid.UUID, str], StaticApiKeyProvisioning] = {}
        self._hash_index: dict[str, tuple[uuid.UUID, str]] = {}

    async def provision(
        self, org_id: uuid.UUID, source_id: str, source_type: str
    ) -> StaticApiKeyProvisioning:
        # Rotating an existing key: drop the old hash-index entry first so
        # a stale hash can never resolve after rotation.
        existing = self._records.get((org_id, source_id))
        if existing is not None:
            self._hash_index.pop(hash_api_key(existing.api_key), None)

        api_key = generate_api_key()
        record = StaticApiKeyProvisioning(
            api_key=api_key,
            org_id=org_id,
            source_id=source_id,
            source_type=source_type,
            created_at=datetime.now(UTC),
            revoked_at=None,
        )
        self._records[(org_id, source_id)] = record
        self._hash_index[hash_api_key(api_key)] = (org_id, source_id)
        return record

    async def get_by_key(self, api_key: str) -> StaticApiKeyProvisioning | None:
        key = self._hash_index.get(hash_api_key(api_key))
        if key is None:
            return None
        record = self._records.get(key)
        if record is None or record.is_revoked:
            return None
        return record

    async def list_by_org(self, org_id: uuid.UUID) -> list[ProvisionedApiKeySummary]:
        return [
            ProvisionedApiKeySummary(
                org_id=r.org_id,
                source_id=r.source_id,
                source_type=r.source_type,
                created_at=r.created_at,
                revoked_at=r.revoked_at,
            )
            for r in self._records.values()
            if r.org_id == org_id
        ]

    async def revoke(self, org_id: uuid.UUID, source_id: str) -> None:
        record = self._records.get((org_id, source_id))
        if record is None or record.org_id != org_id or record.is_revoked:
            return
        self._records[(org_id, source_id)] = record.model_copy(
            update={"revoked_at": datetime.now(UTC)}
        )
