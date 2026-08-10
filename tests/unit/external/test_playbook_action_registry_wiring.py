"""Unit tests for PlaybookActionRegistry/PlaybookExecutionService DI wiring
(Gap Audit 2026-08 P1-1 / roadmap Milestone V2, item a).

Real, previously-undiscovered gap this closes: `get_playbook_action_registry`
never existed before -- every concrete PlaybookAction only ever got
registered inside test files, meaning a real PlaybookExecutionService built
from the DI container would have found zero real actions to run. These
tests exercise the real getter functions directly (they are plain,
type-annotated functions -- FastAPI's Depends() wrapper does not prevent
calling them with manually-supplied real arguments, same approach
test_correlation_sync_service-style tests in this repo already use for
Depends-shaped getters).
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.detection_triage import DetectionTriageService
from src.application.playbook_execution import PlaybookExecutionService
from src.application.sync_detection_to_siem_action import SyncDetectionToSiemAction
from src.domain.playbook import Playbook, PlaybookStep
from src.external.dependencies import (
    configure_splunk_hec_sink_from_settings,
    get_playbook_action_registry,
    get_playbook_execution_service,
    reset_dependencies,
)
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


def _fake_splunk_settings(
    *,
    splunk_hec_url: str | None = "https://splunk.example.com:8088/services/collector/event",
    splunk_hec_token: str | None = "test-token-123",
) -> SimpleNamespace:
    token_obj = None
    if splunk_hec_token is not None:
        token_obj = MagicMock()
        token_obj.get_secret_value.return_value = splunk_hec_token
    return SimpleNamespace(
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=token_obj,
        splunk_hec_source="kronos:test",
        splunk_hec_sourcetype="kronos:test-detection",
        splunk_hec_index="kronos_idx",
        splunk_hec_verify_tls=True,
    )


def _build_registry_inputs() -> (
    tuple[InMemoryDetectionRepository, DetectionTriageService, AuditLogService]
):
    detection_repository = InMemoryDetectionRepository()
    audit_log = AuditLogService(InMemoryAuditLogRepository())
    triage_service = DetectionTriageService(
        detection_repository=detection_repository, audit_log=audit_log
    )
    return detection_repository, triage_service, audit_log


class TestPlaybookActionRegistryWiring:
    def setup_method(self) -> None:
        reset_dependencies()

    def teardown_method(self) -> None:
        reset_dependencies()

    def test_default_registry_has_the_two_pre_existing_real_actions(self) -> None:
        detection_repository, triage_service, audit_log = _build_registry_inputs()
        registry = get_playbook_action_registry(detection_repository, triage_service, audit_log)

        assert registry.get_action("transition_detection_triage") is not None
        assert registry.get_action("log_notification") is not None

    def test_no_siem_action_registered_when_no_sink_configured(self) -> None:
        detection_repository, triage_service, audit_log = _build_registry_inputs()
        registry = get_playbook_action_registry(detection_repository, triage_service, audit_log)

        assert registry.get_action("sync_detection_to_siem_splunk") is None
        assert registry.get_action("sync_detection_to_siem_cef") is None
        assert registry.get_action("sync_detection_to_siem_sentinel") is None

    def test_splunk_sink_configured_registers_a_real_siem_action(self) -> None:
        with patch("src.config.Settings", return_value=_fake_splunk_settings()):
            configure_splunk_hec_sink_from_settings()

        detection_repository, triage_service, audit_log = _build_registry_inputs()
        registry = get_playbook_action_registry(detection_repository, triage_service, audit_log)

        action = registry.get_action("sync_detection_to_siem_splunk")
        assert isinstance(action, SyncDetectionToSiemAction)
        # The other two sinks are still honestly absent.
        assert registry.get_action("sync_detection_to_siem_cef") is None
        assert registry.get_action("sync_detection_to_siem_sentinel") is None

    def test_ticket_sync_action_is_deliberately_not_registered(self) -> None:
        """No real TicketingSystem implementation exists anywhere in this
        codebase yet -- registering SyncDetectionTicketAction against a
        fabricated one would be exactly CLAUDE.md SS F's "plausible code
        without a captured real run" failure mode."""
        detection_repository, triage_service, audit_log = _build_registry_inputs()
        registry = get_playbook_action_registry(detection_repository, triage_service, audit_log)

        assert registry.get_action("sync_detection_ticket") is None

    def test_playbook_execution_service_runs_a_real_registered_action(self) -> None:
        """End-to-end: PlaybookExecutionService.execute() against the DI-built
        registry actually finds and runs a real action, proving the wiring
        (not just the registry's own get_action lookup) works."""
        detection_repository, triage_service, audit_log = _build_registry_inputs()
        registry = get_playbook_action_registry(detection_repository, triage_service, audit_log)
        execution_service = get_playbook_execution_service(registry, audit_log)
        assert isinstance(execution_service, PlaybookExecutionService)

        tenant = make_tenant_context()
        playbook = Playbook(
            playbook_id=uuid.uuid4(),
            name="poc-log-only",
            steps=(
                PlaybookStep(
                    step_id="s1",
                    action_name="log_notification",
                    params={"message": "playbook wiring works"},
                ),
            ),
        )

        import asyncio

        result = asyncio.run(execution_service.execute(playbook, tenant))
        assert result.succeeded
        assert result.step_results[0].output == {"message": "playbook wiring works"}
