"""Unit tests for YaraRuleProvider/DirectoryYaraRuleProvider (roadmap M4/E3)
and SignedYaraRulePackProvider (roadmap E4)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.adapter.repository.yara_rule_pack import InMemoryYaraRulePackRepository
from src.application.audit_log import AuditLogService
from src.application.yara_rule_pack_service import YaraRulePackService
from src.application.yara_rules import (
    DirectoryYaraRuleProvider,
    SignedYaraRulePackProvider,
    yara_scan_org_var,
)
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class TestDirectoryYaraRuleProvider:
    @pytest.mark.asyncio
    async def test_missing_directory_returns_none(self, tmp_path: Path) -> None:
        provider = DirectoryYaraRuleProvider(tmp_path / "does-not-exist")

        assert await provider.get_rule_source() is None

    @pytest.mark.asyncio
    async def test_empty_directory_returns_none(self, tmp_path: Path) -> None:
        provider = DirectoryYaraRuleProvider(tmp_path)

        assert await provider.get_rule_source() is None

    @pytest.mark.asyncio
    async def test_ignores_non_yar_files(self, tmp_path: Path) -> None:
        (tmp_path / "readme.txt").write_text("not a rule")
        provider = DirectoryYaraRuleProvider(tmp_path)

        assert await provider.get_rule_source() is None

    @pytest.mark.asyncio
    async def test_concatenates_every_yar_file_in_sorted_order(self, tmp_path: Path) -> None:
        (tmp_path / "b_second.yar").write_text("rule second { condition: true }")
        (tmp_path / "a_first.yar").write_text("rule first { condition: true }")
        provider = DirectoryYaraRuleProvider(tmp_path)

        source = await provider.get_rule_source()

        assert source is not None
        assert source.index("rule first") < source.index("rule second")

    @pytest.mark.asyncio
    async def test_unreadable_file_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        good = tmp_path / "good.yar"
        good.write_text("rule good { condition: true }")
        bad_dir_as_file = tmp_path / "bad.yar"
        bad_dir_as_file.mkdir()  # a directory named *.yar -- read_text() will raise

        source = await DirectoryYaraRuleProvider(tmp_path).get_rule_source()

        assert source is not None
        assert "rule good" in source


def _make_service() -> YaraRulePackService:
    verifier = MagicMock()
    verifier.verify.return_value = True
    return YaraRulePackService(
        repository=InMemoryYaraRulePackRepository(),
        signature_verifier=verifier,
        audit_log=AuditLogService(InMemoryAuditLogRepository()),
    )


class TestSignedYaraRulePackProvider:
    @pytest.mark.asyncio
    async def test_no_org_context_bound_returns_none(self) -> None:
        service = _make_service()
        provider = SignedYaraRulePackProvider(service._repo)  # noqa: SLF001

        token = yara_scan_org_var.set(None)
        try:
            assert await provider.get_rule_source() is None
        finally:
            yara_scan_org_var.reset(token)

    @pytest.mark.asyncio
    async def test_org_with_no_published_pack_returns_none(self) -> None:
        service = _make_service()
        provider = SignedYaraRulePackProvider(service._repo)  # noqa: SLF001
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", "rule RuleA { condition: true }")
        # Added, but never published -- must not leak into scanning.

        token = yara_scan_org_var.set(tenant.org_id)
        try:
            assert await provider.get_rule_source() is None
        finally:
            yara_scan_org_var.reset(token)

    @pytest.mark.asyncio
    async def test_published_version_rule_source_is_returned(self) -> None:
        service = _make_service()
        provider = SignedYaraRulePackProvider(service._repo)  # noqa: SLF001
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", "rule RuleA { condition: true }")
        await service.publish_version(tenant, "pack1", 1)

        token = yara_scan_org_var.set(tenant.org_id)
        try:
            source = await provider.get_rule_source()
        finally:
            yara_scan_org_var.reset(token)

        assert source is not None
        assert "rule RuleA" in source

    @pytest.mark.asyncio
    async def test_combines_published_versions_of_every_pack_for_the_org(self) -> None:
        service = _make_service()
        provider = SignedYaraRulePackProvider(service._repo)  # noqa: SLF001
        tenant = make_tenant_context()
        await service.add_rule(tenant, "pack1", "RuleA", "rule RuleA { condition: true }")
        await service.publish_version(tenant, "pack1", 1)
        await service.add_rule(tenant, "pack2", "RuleB", "rule RuleB { condition: true }")
        await service.publish_version(tenant, "pack2", 1)

        token = yara_scan_org_var.set(tenant.org_id)
        try:
            source = await provider.get_rule_source()
        finally:
            yara_scan_org_var.reset(token)

        assert source is not None
        assert "rule RuleA" in source
        assert "rule RuleB" in source

    @pytest.mark.asyncio
    async def test_a_different_orgs_rules_are_not_visible(self) -> None:
        service = _make_service()
        provider = SignedYaraRulePackProvider(service._repo)  # noqa: SLF001
        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()
        await service.add_rule(tenant_a, "pack1", "RuleA", "rule RuleA { condition: true }")
        await service.publish_version(tenant_a, "pack1", 1)

        token = yara_scan_org_var.set(tenant_b.org_id)
        try:
            source = await provider.get_rule_source()
        finally:
            yara_scan_org_var.reset(token)

        assert source is None
