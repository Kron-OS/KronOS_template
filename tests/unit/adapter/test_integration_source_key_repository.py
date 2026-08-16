"""Unit tests for InMemoryIntegrationSourceKeyRepository (Milestone W8,
Gap Audit P1-7).

The real ``PostgresIntegrationSourceKeyRepository`` is verified against a
real running Postgres in ``poc/integration_source_key_provisioning/`` (per
CLAUDE.md SS F) -- these tests cover the in-memory double's own contract
(the DI default, and what routes/unit tests are exercised against), plus
the hashing helpers both implementations share.
"""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.integration_source_key import (
    InMemoryIntegrationSourceKeyRepository,
    generate_api_key,
    hash_api_key,
)


class TestHashingHelpers:
    def test_generate_api_key_produces_high_entropy_distinct_values(self) -> None:
        keys = {generate_api_key() for _ in range(50)}
        assert len(keys) == 50  # no collisions across 50 real CSPRNG draws
        assert all(len(k) >= 32 for k in keys)

    def test_hash_api_key_is_deterministic(self) -> None:
        assert hash_api_key("same-key") == hash_api_key("same-key")

    def test_hash_api_key_differs_for_different_input(self) -> None:
        assert hash_api_key("key-a") != hash_api_key("key-b")

    def test_hash_api_key_never_equals_the_plaintext(self) -> None:
        plaintext = "some-plaintext-key"
        assert hash_api_key(plaintext) != plaintext


class TestInMemoryIntegrationSourceKeyRepository:
    @pytest.mark.asyncio
    async def test_provision_returns_plaintext_key_once(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()

        record = await repo.provision(org_id, "s1", "wazuh")

        assert record.org_id == org_id
        assert record.source_id == "s1"
        assert record.source_type == "wazuh"
        assert record.api_key  # real, non-empty plaintext
        assert record.revoked_at is None

    @pytest.mark.asyncio
    async def test_provisioned_key_never_stored_in_the_clear(self) -> None:
        """The repository's own internal hash index must never contain the
        plaintext key as a key or value -- a structural proof the "never
        persist plaintext" invariant actually holds for this double too."""
        repo = InMemoryIntegrationSourceKeyRepository()
        record = await repo.provision(uuid.uuid4(), "s1", "wazuh")

        assert record.api_key not in repo._hash_index
        assert hash_api_key(record.api_key) in repo._hash_index

    @pytest.mark.asyncio
    async def test_get_by_key_resolves_the_provisioned_record(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()
        record = await repo.provision(org_id, "s1", "wazuh")

        resolved = await repo.get_by_key(record.api_key)

        assert resolved is not None
        assert resolved.org_id == org_id
        assert resolved.source_id == "s1"
        assert resolved.source_type == "wazuh"

    @pytest.mark.asyncio
    async def test_get_by_key_unknown_key_returns_none(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        assert await repo.get_by_key("never-provisioned") is None

    @pytest.mark.asyncio
    async def test_revoke_then_get_by_key_returns_none(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()
        record = await repo.provision(org_id, "s1", "wazuh")

        await repo.revoke(org_id, "s1")

        assert await repo.get_by_key(record.api_key) is None

    @pytest.mark.asyncio
    async def test_revoke_is_idempotent(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()
        await repo.provision(org_id, "s1", "wazuh")

        await repo.revoke(org_id, "s1")
        await repo.revoke(org_id, "s1")  # must not raise

    @pytest.mark.asyncio
    async def test_revoke_unknown_source_is_a_noop(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        await repo.revoke(uuid.uuid4(), "never-provisioned")  # must not raise

    @pytest.mark.asyncio
    async def test_revoke_scoped_to_org_cannot_revoke_another_orgs_key(self) -> None:
        """Defense-in-depth org scoping (P2-W10 precedent, applied here from
        the start): revoking with the WRONG org_id but the right source_id
        must not touch the real owner's key."""
        repo = InMemoryIntegrationSourceKeyRepository()
        real_org, attacker_org = uuid.uuid4(), uuid.uuid4()
        record = await repo.provision(real_org, "s1", "wazuh")

        await repo.revoke(attacker_org, "s1")

        # Still resolvable -- the attacker's org_id never matched the real
        # owner's record, so nothing was revoked.
        assert await repo.get_by_key(record.api_key) is not None

    @pytest.mark.asyncio
    async def test_list_by_org_excludes_plaintext_key(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()
        await repo.provision(org_id, "s1", "wazuh")

        summaries = await repo.list_by_org(org_id)

        assert len(summaries) == 1
        assert not hasattr(summaries[0], "api_key")

    @pytest.mark.asyncio
    async def test_list_by_org_is_org_scoped(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await repo.provision(org_a, "s1", "wazuh")
        await repo.provision(org_b, "s2", "crowdstrike")

        summaries_a = await repo.list_by_org(org_a)

        assert len(summaries_a) == 1
        assert summaries_a[0].source_id == "s1"

    @pytest.mark.asyncio
    async def test_list_by_org_includes_revoked_keys_for_audit_visibility(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()
        await repo.provision(org_id, "s1", "wazuh")
        await repo.revoke(org_id, "s1")

        summaries = await repo.list_by_org(org_id)

        assert len(summaries) == 1
        assert summaries[0].revoked_at is not None
        assert summaries[0].is_revoked is True

    @pytest.mark.asyncio
    async def test_reprovisioning_rotates_the_key(self) -> None:
        """Calling provision() again for the same (org, source_id) must
        invalidate the old key and mint a genuinely new one."""
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()
        first = await repo.provision(org_id, "s1", "wazuh")
        second = await repo.provision(org_id, "s1", "wazuh")

        assert first.api_key != second.api_key
        assert await repo.get_by_key(first.api_key) is None
        assert await repo.get_by_key(second.api_key) is not None

    @pytest.mark.asyncio
    async def test_reprovisioning_clears_prior_revocation(self) -> None:
        repo = InMemoryIntegrationSourceKeyRepository()
        org_id = uuid.uuid4()
        await repo.provision(org_id, "s1", "wazuh")
        await repo.revoke(org_id, "s1")

        rotated = await repo.provision(org_id, "s1", "wazuh")

        assert rotated.revoked_at is None
        assert await repo.get_by_key(rotated.api_key) is not None
