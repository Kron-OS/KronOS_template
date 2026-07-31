"""Unit tests for RulePackPublisher (in-memory repo, mocked OpenSearch adapters)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from src.adapter.repository.rule_pack import InMemoryRulePackRepository
from src.application.audit_log import AuditLogService
from src.application.rule_pack_publisher import RulePackPublisher
from src.application.rule_pack_service import RulePackService
from src.domain.rule_pack import CostGateDecision, CostGateVerdict
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


class _StubCostGate:
    def evaluate(self, sigma_yaml: str) -> CostGateVerdict:
        return CostGateVerdict(decision=CostGateDecision.ACCEPTED)


class _StubSignatureVerifier:
    def verify(self, content: bytes, signature: bytes, public_key_path: str) -> bool:
        return True


@pytest.fixture
def repo() -> InMemoryRulePackRepository:
    return InMemoryRulePackRepository()


@pytest.fixture
def service(repo: InMemoryRulePackRepository) -> RulePackService:
    return RulePackService(
        repository=repo,
        cost_gate=_StubCostGate(),
        signature_verifier=_StubSignatureVerifier(),
        audit_log=AuditLogService(InMemoryAuditLogRepository()),
    )


@pytest.fixture
def custom_rule_client() -> AsyncMock:
    client = AsyncMock()
    client.create_rule.return_value = "opensearch-generated-id-1"
    return client


@pytest.fixture
def detector_binder() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def publisher(
    repo: InMemoryRulePackRepository, custom_rule_client: AsyncMock, detector_binder: AsyncMock
) -> RulePackPublisher:
    return RulePackPublisher(
        repository=repo,
        custom_rule_client=custom_rule_client,
        detector_binder=detector_binder,
        audit_log=AuditLogService(InMemoryAuditLogRepository()),
    )


class TestPublishPackVersion:
    @pytest.mark.asyncio
    async def test_publishes_accepted_rule_and_syncs_detector(
        self,
        service: RulePackService,
        publisher: RulePackPublisher,
        custom_rule_client: AsyncMock,
        detector_binder: AsyncMock,
    ) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", "detection: {}", "network")

        published = await publisher.publish_pack_version(tenant, "pack1", "network")

        assert published == 1
        custom_rule_client.create_rule.assert_awaited_once()
        detector_binder.sync_custom_detector.assert_awaited_once_with(
            tenant.org_alias, "network", ("opensearch-generated-id-1",)
        )

    @pytest.mark.asyncio
    async def test_republish_is_idempotent(
        self, service: RulePackService, publisher: RulePackPublisher, custom_rule_client: AsyncMock
    ) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", "detection: {}", "network")

        await publisher.publish_pack_version(tenant, "pack1", "network")
        second = await publisher.publish_pack_version(tenant, "pack1", "network")

        assert second == 0
        assert custom_rule_client.create_rule.await_count == 1

    @pytest.mark.asyncio
    async def test_no_version_yet_publishes_nothing(
        self, publisher: RulePackPublisher, custom_rule_client: AsyncMock
    ) -> None:
        tenant = make_tenant_context()
        published = await publisher.publish_pack_version(tenant, "nonexistent-pack", "network")
        assert published == 0
        custom_rule_client.create_rule.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_publish_failure_is_audited_not_raised(
        self, service: RulePackService, publisher: RulePackPublisher, custom_rule_client: AsyncMock
    ) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", "detection: {}", "network")
        custom_rule_client.create_rule.side_effect = RuntimeError("OpenSearch unreachable")

        published = await publisher.publish_pack_version(tenant, "pack1", "network")
        assert published == 0  # failed publish is not counted as published

    @pytest.mark.asyncio
    async def test_wrong_log_type_rules_are_not_published(
        self, service: RulePackService, publisher: RulePackPublisher, custom_rule_client: AsyncMock
    ) -> None:
        tenant = make_tenant_context()
        await service.add_custom_rule(tenant, "pack1", "Rule A", "detection: {}", "windows")

        published = await publisher.publish_pack_version(tenant, "pack1", "network")
        assert published == 0
        custom_rule_client.create_rule.assert_not_awaited()
