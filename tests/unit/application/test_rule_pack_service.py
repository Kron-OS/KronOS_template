"""Unit tests for RulePackService (in-memory repo, mocked signature verifier)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.adapter.repository.rule_pack import InMemoryRulePackRepository
from src.application.audit_log import AuditLogService
from src.application.cost_gate import RuleCostGate
from src.application.rule_pack_service import RulePackService
from src.domain.audit import AuditEventType
from src.domain.rule_pack import RulePackSourceTier
from src.exceptions import RulePackError, ValidationError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context

_REASONABLE_RULE = """
detection:
  selection:
    dest_port: 4444
  condition: selection
"""

_EXPENSIVE_RULE = """
detection:
  selection:
    process.command_line|contains: 'evil'
  condition: selection
"""


@pytest.fixture
def signature_verifier() -> MagicMock:
    verifier = MagicMock()
    verifier.verify.return_value = True
    return verifier


@pytest.fixture
def service(signature_verifier: MagicMock) -> RulePackService:
    audit_repo = InMemoryAuditLogRepository()
    return RulePackService(
        repository=InMemoryRulePackRepository(),
        cost_gate=RuleCostGate(),
        signature_verifier=signature_verifier,
        audit_log=AuditLogService(audit_repo),
    )


class TestAddCustomRule:
    @pytest.mark.asyncio
    async def test_first_rule_creates_version_1(self, service: RulePackService) -> None:
        tenant = make_tenant_context()
        rule = await service.add_custom_rule(tenant, "pack1", "Rule A", _REASONABLE_RULE, "network")
        assert rule.is_accepted

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is not None
        assert version.version == 1
        assert len(version.rules) == 1

    @pytest.mark.asyncio
    async def test_rejected_rule_is_stored_not_dropped(self, service: RulePackService) -> None:
        tenant = make_tenant_context()
        rule = await service.add_custom_rule(tenant, "pack1", "Rule B", _EXPENSIVE_RULE, "network")
        assert not rule.is_accepted

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert len(version.rules) == 1
        assert len(version.accepted_rules) == 0

    @pytest.mark.asyncio
    async def test_second_rule_creates_version_2_without_losing_version_1(
        self, service: RulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", _REASONABLE_RULE, "network")
        await service.add_custom_rule(tenant, "pack1", "Rule B", _EXPENSIVE_RULE, "network")

        pack = await service.get_or_create_pack(tenant, "pack1")
        all_versions = await service.list_versions(pack.pack_id, tenant.org_id)
        assert [v.version for v in all_versions] == [1, 2]
        assert len(all_versions[0].rules) == 1
        assert len(all_versions[1].rules) == 2

    @pytest.mark.asyncio
    async def test_org_id_always_from_tenant_context(self, service: RulePackService) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", _REASONABLE_RULE, "network")
        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version.org_id == tenant.org_id


class TestUpdateAndDeleteCustomRule:
    @pytest.mark.asyncio
    async def test_update_replaces_rule_content_as_new_version(
        self, service: RulePackService
    ) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", _REASONABLE_RULE, "network")
        updated = await service.update_custom_rule(
            tenant, "pack1", "Rule A", _EXPENSIVE_RULE, "network"
        )
        assert not updated.is_accepted

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version.version == 2
        assert len(version.rules) == 1  # replaced, not appended

    @pytest.mark.asyncio
    async def test_update_nonexistent_rule_raises(self, service: RulePackService) -> None:
        tenant = make_tenant_context()
        with pytest.raises(ValidationError):
            await service.update_custom_rule(
                tenant, "pack1", "Nonexistent", _REASONABLE_RULE, "network"
            )

    @pytest.mark.asyncio
    async def test_delete_removes_rule_as_new_version(self, service: RulePackService) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", _REASONABLE_RULE, "network")
        await service.delete_custom_rule(tenant, "pack1", "Rule A")

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version.version == 2
        assert len(version.rules) == 0

    @pytest.mark.asyncio
    async def test_delete_nonexistent_rule_is_a_noop(self, service: RulePackService) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", _REASONABLE_RULE, "network")
        await service.delete_custom_rule(tenant, "pack1", "Nonexistent")

        pack = await service.get_or_create_pack(tenant, "pack1")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version.version == 1  # no new version created


class TestImportSignedPack:
    @pytest.mark.asyncio
    async def test_valid_signature_is_accepted_and_versioned(
        self, service: RulePackService, signature_verifier: MagicMock
    ) -> None:
        tenant = make_tenant_context()
        signature_verifier.verify.return_value = True

        version = await service.import_signed_pack(
            tenant,
            "signed-pack",
            b"content",
            b"sig",
            "/tmp/pub.key",
            [("R", "network", _REASONABLE_RULE)],
        )
        assert version.signature_verified is True
        assert version.source_tier == RulePackSourceTier.SIGNED_THIRD_PARTY
        assert version.content_sha256 is not None

    @pytest.mark.asyncio
    async def test_invalid_signature_is_rejected_with_no_version_created(
        self, service: RulePackService, signature_verifier: MagicMock
    ) -> None:
        tenant = make_tenant_context()
        signature_verifier.verify.return_value = False

        with pytest.raises(RulePackError):
            await service.import_signed_pack(
                tenant,
                "bad-pack",
                b"content",
                b"sig",
                "/tmp/pub.key",
                [("R", "network", _REASONABLE_RULE)],
            )

        pack = await service.get_or_create_pack(tenant, "bad-pack")
        version = await service.get_latest_version(pack.pack_id, tenant.org_id)
        assert version is None

    @pytest.mark.asyncio
    async def test_invalid_signature_is_audited(
        self, service: RulePackService, signature_verifier: MagicMock
    ) -> None:
        tenant = make_tenant_context()
        signature_verifier.verify.return_value = False
        audit_repo = service._audit._repository  # noqa: SLF001

        with pytest.raises(RulePackError):
            await service.import_signed_pack(
                tenant,
                "bad-pack",
                b"content",
                b"sig",
                "/tmp/pub.key",
                [("R", "network", _REASONABLE_RULE)],
            )

        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.RULE_PACK_SIGNATURE_REJECTED in types
