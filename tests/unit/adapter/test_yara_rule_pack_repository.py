"""Unit tests for InMemoryYaraRulePackRepository (roadmap E4).

P2-W10 focus: ``get_latest_version``/``get_published_version`` were
hardened to require ``org_id`` (defense-in-depth org scoping, mirroring
``DetectionRepository.get_by_id``) -- these tests prove the new parameter
is actually enforced, not just accepted and ignored.
"""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.yara_rule_pack import InMemoryYaraRulePackRepository
from src.domain.rule_pack import RulePackSourceTier
from src.domain.yara_rule_pack import YaraRulePackVersion


class TestInMemoryYaraRulePackRepository:
    @pytest.mark.asyncio
    async def test_get_or_create_pack_is_idempotent(self) -> None:
        repo = InMemoryYaraRulePackRepository()
        org_id = uuid.uuid4()

        pack1 = await repo.get_or_create_pack(org_id, "my-pack")
        pack2 = await repo.get_or_create_pack(org_id, "my-pack")

        assert pack1.pack_id == pack2.pack_id

    @pytest.mark.asyncio
    async def test_save_version_then_get_latest(self) -> None:
        repo = InMemoryYaraRulePackRepository()
        org_id = uuid.uuid4()
        pack = await repo.get_or_create_pack(org_id, "p")
        version = YaraRulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_id,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )

        await repo.save_version(version)
        latest = await repo.get_latest_version(pack.pack_id, org_id)

        assert latest == version

    @pytest.mark.asyncio
    async def test_get_latest_version_cross_org_isolation(self) -> None:
        """A lookup with the wrong org_id must return None even though the
        pack_id is real -- confirmed unreachable from any current route
        (P2-SEC-3), but a real gap if this repository is ever exposed."""
        repo = InMemoryYaraRulePackRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        pack = await repo.get_or_create_pack(org_a, "p")
        version = YaraRulePackVersion(
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
        get_latest_version/get_published_version on this repository."""
        repo = InMemoryYaraRulePackRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        pack = await repo.get_or_create_pack(org_a, "p")
        version = YaraRulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_a,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )
        await repo.save_version(version)

        assert await repo.list_versions(pack.pack_id, org_a) == [version]
        assert await repo.list_versions(pack.pack_id, org_b) == []

    @pytest.mark.asyncio
    async def test_get_published_version_round_trips(self) -> None:
        repo = InMemoryYaraRulePackRepository()
        org_id = uuid.uuid4()
        pack = await repo.get_or_create_pack(org_id, "p")
        version = YaraRulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_id,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )
        await repo.save_version(version)

        assert await repo.get_published_version(pack.pack_id, org_id) is None

        await repo.publish_version(pack.pack_id, 1)

        assert await repo.get_published_version(pack.pack_id, org_id) == version

    @pytest.mark.asyncio
    async def test_get_published_version_cross_org_isolation(self) -> None:
        """A version published under org_a must not resolve when looked up
        with org_b's org_id, even though pack_id is real."""
        repo = InMemoryYaraRulePackRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        pack = await repo.get_or_create_pack(org_a, "p")
        version = YaraRulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_a,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )
        await repo.save_version(version)
        await repo.publish_version(pack.pack_id, 1)

        assert await repo.get_published_version(pack.pack_id, org_a) == version
        assert await repo.get_published_version(pack.pack_id, org_b) is None

    @pytest.mark.asyncio
    async def test_list_published_versions_for_org_still_scoped(self) -> None:
        """Regression guard: the internal get_published_version call inside
        list_published_versions_for_org must still pass org_id through after
        the signature hardening, or every published pack would silently
        stop appearing for its own org."""
        repo = InMemoryYaraRulePackRepository()
        org_id = uuid.uuid4()
        pack = await repo.get_or_create_pack(org_id, "p")
        version = YaraRulePackVersion(
            pack_id=pack.pack_id,
            version=1,
            org_id=org_id,
            source_tier=RulePackSourceTier.TENANT_CUSTOM,
        )
        await repo.save_version(version)
        await repo.publish_version(pack.pack_id, 1)

        results = await repo.list_published_versions_for_org(org_id)

        assert results == [version]
