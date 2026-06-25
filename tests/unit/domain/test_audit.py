"""Unit tests for AuditEvent domain model."""

from __future__ import annotations

import uuid

from src.domain.audit import AuditEvent, AuditEventType
from tests.fixtures.factories import make_audit_event


class TestAuditEvent:
    def test_event_id_auto_generated(self) -> None:
        event = make_audit_event()
        assert isinstance(event.event_id, uuid.UUID)

    def test_frozen_model(self) -> None:
        event = make_audit_event()
        try:
            event.sequence_number = 99  # type: ignore[misc]
            raise AssertionError("Should have raised")
        except Exception:
            pass

    def test_event_type_values(self) -> None:
        assert AuditEventType.EVIDENCE_UPLOAD_REQUESTED.value == "evidence.upload_requested"
        assert AuditEventType.PARSE_COMPLETED.value == "parse.completed"
        assert AuditEventType.INGEST_COMPLETED.value == "ingest.completed"

    def test_details_default_empty(self) -> None:
        event = make_audit_event()
        assert event.details == {}

    def test_optional_fields_default_none(self) -> None:
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,
            org_id=uuid.uuid4(),
        )
        assert event.actor_user_id is None
        assert event.case_id is None
        assert event.evidence_id is None
        assert event.row_hash is None
        assert event.prev_row_hash is None
