"""Unit tests for InMemoryRulePackRepository (roadmap M2/C3).

P2-W10 focus: ``get_latest_version``/``get_published_opensearch_id`` were
hardened to require ``org_id`` (defense-in-depth org scoping, mirroring
``DetectionRepository.get_by_id``) -- these tests prove the new parameter
is actually enforced, not just accepted and ignored.
"""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.rule_pack import InMemoryRulePackRepository
from src.domain.rule_pack import RulePackSourceTier, RulePackVersion


class TestInMemoryRulePackRepository:
    @pytest.mark.asyncio
    async def test_get_or_create_pack_is_idempotent(self) -> None:
        repo = InMemoryRulePackRepository()
        org_id = uuid.uuid4()

        pack1 = await repo.get_or_create_pack(org_id, "my-pack")
        pack2 = await repo.get_or_create_pack(org_id, "my-pack")

        assert pack1.pack_id == pack2.pack_id

    @pytest.mark.asyncio
    async def test_save_version_then_get_latest(self) -> None:
        repo = InMemoryRulePackRepository()
        org_id = uuid.uuid4()
        pack = await repo.get_or_create_pack(org_id, "p")
        version = RulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_id,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )

        await repo.save_version(version)
        latest = await repo.get_latest_version(pack.pack_id, org_id)

        assert latest == version

    @pytest.mark.asyncio
    async def test_no_versions_yet_returns_none(self) -> None:
        repo = InMemoryRulePackRepository()
        org_id = uuid.uuid4()
        pack = await repo.get_or_create_pack(org_id, "p")

        assert await repo.get_latest_version(pack.pack_id, org_id) is None

    @pytest.mark.asyncio
    async def test_get_latest_version_cross_org_isolation(self) -> None:
        """A lookup with the wrong org_id must return None even though the
        pack_id is real -- confirmed unreachable from any current route
        (P2-SEC-3), but a real gap if this repository is ever exposed."""
        repo = InMemoryRulePackRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        pack = await repo.get_or_create_pack(org_a, "p")
        version = RulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_a,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )
        await repo.save_version(version)

        assert await repo.get_latest_version(pack.pack_id, org_a) == version
        assert await repo.get_latest_version(pack.pack_id, org_b) is None

    @pytest.mark.asyncio
    async def test_list_versions_cross_org_isolation(self) -> None:
        """A lookup with the wrong org_id must return nothing even though
        the pack_id is real -- Gap Audit Milestone RR: list_versions was
        missing the same defense-in-depth org scoping P2-SEC-3 already gave
        get_latest_version/get_published_opensearch_id on this repository."""
        repo = InMemoryRulePackRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        pack = await repo.get_or_create_pack(org_a, "p")
        version = RulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_a,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )
        await repo.save_version(version)

        assert await repo.list_versions(pack.pack_id, org_a) == [version]
        assert await repo.list_versions(pack.pack_id, org_b) == []

    @pytest.mark.asyncio
    async def test_delete_publication_cross_org_isolation(self) -> None:
        """Deleting a publication with the wrong org_id must be a no-op --
        the real record must survive, redeemable by its actual owning org.
        Gap Audit Milestone RR: delete_publication was the one write method
        on this repository with no org_id parameter at all."""
        repo = InMemoryRulePackRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        rule_id = uuid.uuid4()
        await repo.record_publication(rule_id, org_a, "os-rule-1")

        await repo.delete_publication(rule_id, org_b)
        assert await repo.get_published_opensearch_id(rule_id, org_a) == "os-rule-1"

        await repo.delete_publication(rule_id, org_a)
        assert await repo.get_published_opensearch_id(rule_id, org_a) is None

    @pytest.mark.asyncio
    async def test_get_published_opensearch_id_round_trips(self) -> None:
        repo = InMemoryRulePackRepository()
        org_id = uuid.uuid4()
        rule_id = uuid.uuid4()

        assert await repo.get_published_opensearch_id(rule_id, org_id) is None

        await repo.record_publication(rule_id, org_id, "os-rule-1")

        assert await repo.get_published_opensearch_id(rule_id, org_id) == "os-rule-1"

    @pytest.mark.asyncio
    async def test_get_published_opensearch_id_cross_org_isolation(self) -> None:
        """A rule published under org_a must not resolve when looked up
        with org_b's org_id, even though rule_id is real."""
        repo = InMemoryRulePackRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        rule_id = uuid.uuid4()
        await repo.record_publication(rule_id, org_a, "os-rule-1")

        assert await repo.get_published_opensearch_id(rule_id, org_a) == "os-rule-1"
        assert await repo.get_published_opensearch_id(rule_id, org_b) is None
