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

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from src.adapter.keycloak.admin_client import HttpxKeycloakAdminClient
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.approval_gate import StepUpApprovalGate
from src.application.audit_log import AuditLogService
from src.application.containment_actions import RevokeKeycloakSessionAction
from src.application.detection_triage import DetectionTriageService
from src.application.playbook_execution import PlaybookExecutionService
from src.application.sync_detection_to_siem_action import SyncDetectionToSiemAction
from src.domain.playbook import Playbook, PlaybookStep
from src.external.dependencies import (
    configure_keycloak_admin_client_from_settings,
    configure_splunk_hec_sink_from_settings,
    get_containment_approval_gate,
    get_keycloak_admin_client,
    get_playbook_action_registry,
    get_playbook_execution_service,
    get_revoke_keycloak_session_action,
    get_step_up_auth,
    reset_dependencies,
)
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


def _fake_keycloak_settings() -> SimpleNamespace:
    secret = MagicMock()
    secret.get_secret_value.return_value = "test-keycloak-client-secret"
    return SimpleNamespace(
        keycloak_url="https://keycloak.example.com",
        keycloak_realm="kronos",
        keycloak_client_id="kronos-backend",
        keycloak_client_secret=secret,
    )


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
        splunk_hec_enable_indexer_ack=False,
        splunk_hec_ack_poll_timeout=30.0,
        splunk_hec_ack_poll_interval=1.0,
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

        result = asyncio.run(execution_service.execute(playbook, tenant))
        assert result.succeeded
        assert result.step_results[0].output == {"message": "playbook wiring works"}


class TestRevokeKeycloakSessionActionWiring:
    """DI wiring for RevokeKeycloakSessionAction (roadmap M7/H2/EE1) --
    closes H2's own explicitly-flagged gap: "ContainmentAction/ApprovalGate/
    HttpxKeycloakAdminClient are not yet wired into dependencies.py/
    startup.py". Mirrors TestPlaybookActionRegistryWiring's own style for
    the pre-existing Splunk sink getter, applied to the new
    get_keycloak_admin_client/get_containment_approval_gate/
    get_revoke_keycloak_session_action getters."""

    def setup_method(self) -> None:
        reset_dependencies()

    def teardown_method(self) -> None:
        reset_dependencies()

    def test_keycloak_admin_client_is_none_when_unconfigured(self) -> None:
        assert get_keycloak_admin_client() is None

    def test_configure_from_settings_builds_a_real_httpx_client(self) -> None:
        with patch("src.config.Settings", return_value=_fake_keycloak_settings()):
            configure_keycloak_admin_client_from_settings()

        client = get_keycloak_admin_client()
        assert isinstance(client, HttpxKeycloakAdminClient)

    def test_configure_from_settings_falls_back_silently_when_settings_unavailable(self) -> None:
        with patch("src.config.Settings", side_effect=RuntimeError("no env vars in this test")):
            configure_keycloak_admin_client_from_settings()

        assert get_keycloak_admin_client() is None

    def test_containment_approval_gate_reuses_the_real_step_up_auth_ticket_store(self) -> None:
        """The whole human-approval loop (POST /api/step-up/ticket ->
        StepUpApprovalGate.authorize()) only closes if both sides consume
        the SAME TicketStore instance -- this is the concrete behavior that
        matters, not merely that a StepUpApprovalGate object is returned."""
        step_up_auth = get_step_up_auth()
        gate = get_containment_approval_gate(step_up_auth)

        assert isinstance(gate, StepUpApprovalGate)
        # Reach into the gate's own store via the real ticket-issue/consume
        # round trip rather than a private-attribute comparison: a ticket
        # issued through step_up_auth.issue_ticket() must be consumable by
        # this exact gate.
        tenant = make_tenant_context()
        ticket_id = step_up_auth.issue_ticket(
            user_id=tenant.user_id, operation="revoke_keycloak_session", resource_id="sess-1"
        )
        decision = asyncio.run(
            gate.authorize(
                "revoke_keycloak_session",
                "sess-1",
                {"approval_ticket_id": str(ticket_id)},
                tenant,
            )
        )
        assert decision.authorized is True

    def test_revoke_action_getter_is_none_without_a_configured_admin_client(self) -> None:
        _detection_repository, _triage_service, audit_log = _build_registry_inputs()
        gate = get_containment_approval_gate(get_step_up_auth())

        action = get_revoke_keycloak_session_action(get_keycloak_admin_client(), gate, audit_log)

        assert action is None

    def test_revoke_action_getter_returns_a_real_action_once_configured(self) -> None:
        with patch("src.config.Settings", return_value=_fake_keycloak_settings()):
            configure_keycloak_admin_client_from_settings()

        _detection_repository, _triage_service, audit_log = _build_registry_inputs()
        gate = get_containment_approval_gate(get_step_up_auth())

        action = get_revoke_keycloak_session_action(get_keycloak_admin_client(), gate, audit_log)

        assert isinstance(action, RevokeKeycloakSessionAction)
        assert action.action_name == "revoke_keycloak_session"

    def test_no_revoke_session_action_registered_when_keycloak_admin_client_unconfigured(
        self,
    ) -> None:
        detection_repository, triage_service, audit_log = _build_registry_inputs()
        registry = get_playbook_action_registry(detection_repository, triage_service, audit_log)

        assert registry.get_action("revoke_keycloak_session") is None

    def test_registry_registers_a_real_revoke_session_action_once_keycloak_is_configured(
        self,
    ) -> None:
        with patch("src.config.Settings", return_value=_fake_keycloak_settings()):
            configure_keycloak_admin_client_from_settings()

        detection_repository, triage_service, audit_log = _build_registry_inputs()
        registry = get_playbook_action_registry(detection_repository, triage_service, audit_log)

        action = registry.get_action("revoke_keycloak_session")
        assert isinstance(action, RevokeKeycloakSessionAction)
