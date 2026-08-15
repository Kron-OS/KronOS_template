"""Unit tests for YaraRulePackService (in-memory repo, mocked signature verifier)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.adapter.repository.yara_rule_pack import InMemoryYaraRulePackRepository
from src.application.audit_log import AuditLogService
from src.application.yara_rule_pack_service import YaraRulePackService
from src.domain.audit import AuditEventType
from src.domain.rule_pack import RulePackSourceTier
from src.exceptions import RulePackError, ValidationError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context

_RULE_A = "rule RuleA { condition: true }"
_RULE_B = 'rule RuleB { strings: $a = "evil" condition: $a }'


@pytest.fixture
def signature_verifier() -> MagicMock:
    verifier = MagicMock()
    verifier.verify.return_value = True
    return verifier


@pytest.fixture
def service(signature_verifier: MagicMock) -> YaraRulePackService:
    audit_repo = InMemoryAuditLogRepository()
    return YaraRulePackService(
        repository=InMemoryYaraRulePackRepository(),
        signature_verifier=signature_verifier,
        audit_log=AuditLogService(audit_repo),
    )


class TestAddRule:
    @pytest.mark.asyncio
    async def test_first_rule_creates_version_1(self, service: YaraRulePackService) -> None:
        tenant = make_tenant_context()
        rule = await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        assert rule.rule_source == _RULE_A

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is not None
        assert version.version == 1
        assert len(version.rules) == 1
        assert version.source_tier == RulePackSourceTier.TENANT_CUSTOM

    @pytest.mark.asyncio
    async def test_second_rule_creates_version_2_without_losing_version_1(
        self, service: YaraRulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        await service.add_rule(tenant, "pack1", "RuleB", _RULE_B)

        pack = await service.get_or_create_pack(tenant, "pack1")
        all_versions = await service.list_versions(pack.pack_id)
        assert [v.version for v in all_versions] == [1, 2]
        assert len(all_versions[0].rules) == 1
        assert len(all_versions[1].rules) == 2

    @pytest.mark.asyncio
    async def test_org_id_always_from_tenant_context(self, service: YaraRulePackService) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is not None
        assert version.org_id == tenant.org_id

    @pytest.mark.asyncio
    async def test_combined_rule_source_concatenates_all_rules(
        self, service: YaraRulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        await service.add_rule(tenant, "pack1", "RuleB", _RULE_B)
        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is not None
        combined = version.combined_rule_source
        assert combined is not None
        assert _RULE_A in combined
        assert _RULE_B in combined


class TestUpdateAndDeleteRule:
    @pytest.mark.asyncio
    async def test_update_replaces_rule_content_as_new_version(
        self, service: YaraRulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        updated = await service.update_rule(tenant, "pack1", "RuleA", _RULE_B)
        assert updated.rule_source == _RULE_B

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is not None
        assert version.version == 2
        assert len(version.rules) == 1  # replaced, not appended

    @pytest.mark.asyncio
    async def test_update_nonexistent_rule_raises(self, service: YaraRulePackService) -> None:
        tenant = make_tenant_context()
        with pytest.raises(ValidationError):
            await service.update_rule(tenant, "pack1", "Nonexistent", _RULE_A)

    @pytest.mark.asyncio
    async def test_delete_removes_rule_as_new_version(self, service: YaraRulePackService) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        await service.delete_rule(tenant, "pack1", "RuleA")

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is not None
        assert version.version == 2
        assert len(version.rules) == 0

    @pytest.mark.asyncio
    async def test_delete_nonexistent_rule_is_a_noop(self, service: YaraRulePackService) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        await service.delete_rule(tenant, "pack1", "Nonexistent")

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is not None
        assert version.version == 1  # no new version created


class TestImportSignedPack:
    @pytest.mark.asyncio
    async def test_valid_signature_is_accepted_and_versioned(
        self, service: YaraRulePackService, signature_verifier: MagicMock
    ) -> None:
        tenant = make_tenant_context()
        signature_verifier.verify.return_value = True

        version = await service.import_signed_pack(
            tenant, "signed-pack", b"content", b"sig", "/tmp/pub.key", [("RuleA", _RULE_A)]
        )
        assert version.signature_verified is True
        assert version.source_tier == RulePackSourceTier.SIGNED_THIRD_PARTY
        assert version.content_sha256 is not None

    @pytest.mark.asyncio
    async def test_invalid_signature_is_rejected_with_no_version_created(
        self, service: YaraRulePackService, signature_verifier: MagicMock
    ) -> None:
        tenant = make_tenant_context()
        signature_verifier.verify.return_value = False

        with pytest.raises(RulePackError):
            await service.import_signed_pack(
                tenant, "bad-pack", b"content", b"sig", "/tmp/pub.key", [("RuleA", _RULE_A)]
            )

        pack = await service.get_or_create_pack(tenant, "bad-pack")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is None

    @pytest.mark.asyncio
    async def test_invalid_signature_is_audited(
        self, service: YaraRulePackService, signature_verifier: MagicMock
    ) -> None:
        tenant = make_tenant_context()
        signature_verifier.verify.return_value = False
        audit_repo = service._audit._repository  # noqa: SLF001

        with pytest.raises(RulePackError):
            await service.import_signed_pack(
                tenant, "bad-pack", b"content", b"sig", "/tmp/pub.key", [("RuleA", _RULE_A)]
            )

        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.YARA_RULE_PACK_SIGNATURE_REJECTED in types


class TestPublishVersion:
    @pytest.mark.asyncio
    async def test_publish_makes_version_the_published_one(
        self, service: YaraRulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        pack = await service.get_or_create_pack(tenant, "pack1")

        published = await service.publish_version(tenant, "pack1", 1)
        assert published.version == 1

        current = await service.get_published_version(pack.pack_id, tenant.org_id)
        assert current is not None
        assert current.version == 1

    @pytest.mark.asyncio
    async def test_republishing_a_newer_version_moves_the_pointer(
        self, service: YaraRulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        await service.add_rule(tenant, "pack1", "RuleB", _RULE_B)
        pack = await service.get_or_create_pack(tenant, "pack1")

        await service.publish_version(tenant, "pack1", 1)
        await service.publish_version(tenant, "pack1", 2)

        current = await service.get_published_version(pack.pack_id, tenant.org_id)
        assert current is not None
        assert current.version == 2
        # version 1 remains independently retrievable -- publishing never
        # deletes/mutates any version row.
        all_versions = await service.list_versions(pack.pack_id)
        assert [v.version for v in all_versions] == [1, 2]

    @pytest.mark.asyncio
    async def test_publish_nonexistent_version_raises(self, service: YaraRulePackService) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)

        with pytest.raises(ValidationError):
            await service.publish_version(tenant, "pack1", 99)

    @pytest.mark.asyncio
    async def test_unpublished_pack_has_no_published_version(
        self, service: YaraRulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", _RULE_A)
        pack = await service.get_or_create_pack(tenant, "pack1")

        assert await service.get_published_version(pack.pack_id, tenant.org_id) is None
