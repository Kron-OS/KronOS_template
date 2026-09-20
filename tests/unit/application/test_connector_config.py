"""Unit tests for ConnectorConfigService (connector marketplace, `/admin/connectors`).

Real Postgres/Vault integration is covered separately under
tests/integration/ (testcontainers) -- these tests exercise pure
validation/redaction/audit logic against in-memory doubles only.
"""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.connector_config import InMemoryConnectorConfigRepository
from src.application.audit_log import AuditLogService
from src.application.connector_catalog import ConnectorCatalog
from src.application.connector_config import ConnectorConfigService
from src.application.secret_store import InMemorySecretStore
from src.domain.audit import AuditEventType
from src.exceptions import ValidationError
from tests.conftest import InMemoryAuditLogRepository


def _make_service(*, auto_disable_threshold: int = 5) -> tuple[ConnectorConfigService, InMemoryAuditLogRepository]:
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    service = ConnectorConfigService(
        ConnectorCatalog(),
        InMemoryConnectorConfigRepository(),
        InMemorySecretStore(),
        audit_log,
        auto_disable_threshold=auto_disable_threshold,
    )
    return service, audit_repo


class TestSetConfigValidation:
    @pytest.mark.asyncio
    async def test_unknown_source_type_rejected(self) -> None:
        service, _ = _make_service()
        with pytest.raises(ValidationError, match="Unknown connector"):
            await service.set_config(uuid.uuid4(), "not-a-real-connector", {}, actor_user_id=uuid.uuid4())

    @pytest.mark.asyncio
    async def test_missing_required_parameter_rejected(self) -> None:
        service, _ = _make_service()
        with pytest.raises(ValidationError, match="missing required"):
            await service.set_config(
                uuid.uuid4(),
                "ms-defender-alerts",
                {"defender_tenant_id": "t1"},  # missing client_id/client_secret
                actor_user_id=uuid.uuid4(),
            )

    @pytest.mark.asyncio
    async def test_unknown_parameter_rejected(self) -> None:
        service, _ = _make_service()
        with pytest.raises(ValidationError, match="unknown parameter"):
            await service.set_config(
                uuid.uuid4(),
                "ms-defender-alerts",
                {
                    "defender_tenant_id": "t1",
                    "defender_client_id": "c1",
                    "defender_client_secret": "s1",
                    "not_a_real_field": "x",
                },
                actor_user_id=uuid.uuid4(),
            )

    @pytest.mark.asyncio
    async def test_valid_config_accepted(self) -> None:
        service, _ = _make_service()
        org_id = uuid.uuid4()
        summary = await service.set_config(
            org_id,
            "ms-defender-alerts",
            {
                "defender_tenant_id": "t1",
                "defender_client_id": "c1",
                "defender_client_secret": "super-secret",
            },
            actor_user_id=uuid.uuid4(),
        )
        assert summary.org_id == org_id
        assert summary.enabled is True
        assert summary.non_secret_fields == {"defender_tenant_id": "t1", "defender_client_id": "c1"}
        assert summary.secret_field_names == ("defender_client_secret",)


class TestRedaction:
    @pytest.mark.asyncio
    async def test_get_config_never_contains_secret_values(self) -> None:
        service, _ = _make_service()
        org_id = uuid.uuid4()
        await service.set_config(
            org_id,
            "splunk-hec",
            {"splunk_hec_url": "https://splunk.example.com:8088", "splunk_hec_token": "top-secret-token"},
            actor_user_id=uuid.uuid4(),
        )

        summary = await service.get_config(org_id, "splunk-hec")
        assert summary is not None
        assert "top-secret-token" not in summary.model_dump_json()
        assert summary.secrets_set is True
        assert summary.secret_field_names == ("splunk_hec_token",)

    @pytest.mark.asyncio
    async def test_resolve_runtime_config_reassembles_plaintext_for_internal_use(self) -> None:
        service, _ = _make_service()
        org_id = uuid.uuid4()
        await service.set_config(
            org_id,
            "splunk-hec",
            {"splunk_hec_url": "https://splunk.example.com:8088", "splunk_hec_token": "top-secret-token"},
            actor_user_id=uuid.uuid4(),
        )

        resolved = await service.resolve_runtime_config(org_id, "splunk-hec")
        assert resolved is not None
        assert resolved["splunk_hec_token"] == "top-secret-token"
        assert resolved["splunk_hec_url"] == "https://splunk.example.com:8088"
        # unset optional param falls back to its declared default
        assert resolved["splunk_hec_sourcetype"] == "_json"

    @pytest.mark.asyncio
    async def test_resolve_runtime_config_none_when_unconfigured(self) -> None:
        service, _ = _make_service()
        assert await service.resolve_runtime_config(uuid.uuid4(), "splunk-hec") is None

    @pytest.mark.asyncio
    async def test_resolve_runtime_config_none_when_disabled(self) -> None:
        service, _ = _make_service()
        org_id = uuid.uuid4()
        actor = uuid.uuid4()
        await service.set_config(
            org_id,
            "cef-syslog",
            {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"},
            actor_user_id=actor,
        )
        await service.set_enabled(org_id, "cef-syslog", False, actor_user_id=actor)
        assert await service.resolve_runtime_config(org_id, "cef-syslog") is None


class TestAuditCalls:
    @pytest.mark.asyncio
    async def test_set_config_audits_attempted_and_executed(self) -> None:
        service, audit_repo = _make_service()
        org_id = uuid.uuid4()
        await service.set_config(
            org_id,
            "cef-syslog",
            {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"},
            actor_user_id=uuid.uuid4(),
        )
        event_types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.CONNECTOR_CONFIG_SET_ATTEMPTED in event_types
        assert AuditEventType.CONNECTOR_CONFIG_SET_EXECUTED in event_types
        assert AuditEventType.CONNECTOR_CONFIG_SET_FAILED not in event_types

    @pytest.mark.asyncio
    async def test_delete_config_audits_revoked(self) -> None:
        service, audit_repo = _make_service()
        org_id = uuid.uuid4()
        actor = uuid.uuid4()
        await service.set_config(
            org_id,
            "cef-syslog",
            {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"},
            actor_user_id=actor,
        )
        await service.delete_config(org_id, "cef-syslog", actor_user_id=actor)
        assert await service.get_config(org_id, "cef-syslog") is None
        event_types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.CONNECTOR_CONFIG_REVOKED in event_types

    @pytest.mark.asyncio
    async def test_record_failure_auto_disables_at_threshold_and_audits(self) -> None:
        service, audit_repo = _make_service(auto_disable_threshold=3)
        org_id = uuid.uuid4()
        actor = uuid.uuid4()
        await service.set_config(
            org_id,
            "cef-syslog",
            {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"},
            actor_user_id=actor,
        )

        for _ in range(2):
            await service.record_failure(org_id, "cef-syslog")
        summary = await service.get_config(org_id, "cef-syslog")
        assert summary is not None
        assert summary.enabled is True
        assert summary.auto_disabled_at is None

        await service.record_failure(org_id, "cef-syslog")  # 3rd failure -- crosses threshold
        summary = await service.get_config(org_id, "cef-syslog")
        assert summary is not None
        assert summary.enabled is False
        assert summary.auto_disabled_at is not None

        event_types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.CONNECTOR_CONFIG_AUTO_DISABLED in event_types

    @pytest.mark.asyncio
    async def test_record_success_resets_failure_count(self) -> None:
        service, _ = _make_service(auto_disable_threshold=3)
        org_id = uuid.uuid4()
        actor = uuid.uuid4()
        await service.set_config(
            org_id,
            "cef-syslog",
            {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"},
            actor_user_id=actor,
        )
        await service.record_failure(org_id, "cef-syslog")
        await service.record_failure(org_id, "cef-syslog")
        await service.record_success(org_id, "cef-syslog")

        summary = await service.get_config(org_id, "cef-syslog")
        assert summary is not None
        assert summary.consecutive_failure_count == 0

    @pytest.mark.asyncio
    async def test_set_enabled_true_clears_auto_disabled_state(self) -> None:
        service, _ = _make_service(auto_disable_threshold=1)
        org_id = uuid.uuid4()
        actor = uuid.uuid4()
        await service.set_config(
            org_id,
            "cef-syslog",
            {"cef_syslog_host": "siem.example.com", "cef_syslog_port": "514"},
            actor_user_id=actor,
        )
        await service.record_failure(org_id, "cef-syslog")
        summary = await service.get_config(org_id, "cef-syslog")
        assert summary is not None and summary.auto_disabled_at is not None

        await service.set_enabled(org_id, "cef-syslog", True, actor_user_id=actor)
        summary = await service.get_config(org_id, "cef-syslog")
        assert summary is not None
        assert summary.enabled is True
        assert summary.auto_disabled_at is None


class TestCrossOrgIsolation:
    @pytest.mark.asyncio
    async def test_two_orgs_same_source_type_never_collide(self) -> None:
        service, _ = _make_service()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await service.set_config(
            org_a,
            "splunk-hec",
            {"splunk_hec_url": "https://a.example.com:8088", "splunk_hec_token": "secret-a"},
            actor_user_id=uuid.uuid4(),
        )
        await service.set_config(
            org_b,
            "splunk-hec",
            {"splunk_hec_url": "https://b.example.com:8088", "splunk_hec_token": "secret-b"},
            actor_user_id=uuid.uuid4(),
        )

        resolved_a = await service.resolve_runtime_config(org_a, "splunk-hec")
        resolved_b = await service.resolve_runtime_config(org_b, "splunk-hec")
        assert resolved_a is not None and resolved_b is not None
        assert resolved_a["splunk_hec_token"] == "secret-a"
        assert resolved_b["splunk_hec_token"] == "secret-b"

        await service.delete_config(org_a, "splunk-hec", actor_user_id=uuid.uuid4())
        assert await service.resolve_runtime_config(org_a, "splunk-hec") is None
        # org_b untouched by org_a's deletion
        resolved_b_after = await service.resolve_runtime_config(org_b, "splunk-hec")
        assert resolved_b_after is not None
        assert resolved_b_after["splunk_hec_token"] == "secret-b"

        assert [s.org_id for s in await service.list_configs(org_a)] == []
        assert [s.org_id for s in await service.list_configs(org_b)] == [org_b]
