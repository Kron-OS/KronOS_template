"""Unit tests for Evidence domain model and FSM."""

from __future__ import annotations

import uuid

import pytest

from src.domain.evidence import (
    EvidenceState,
    is_parse_stage_error_reason,
    is_retryable_error_reason,
)
from src.exceptions import EvidenceStateError
from tests.fixtures.factories import make_evidence, make_evidence_metadata


class TestEvidenceStateFSM:
    def test_initial_state_is_uploading(self) -> None:
        ev = make_evidence()
        assert ev.state == EvidenceState.UPLOADING

    def test_uploading_to_scanning(self) -> None:
        ev = make_evidence(EvidenceState.UPLOADING)
        ev2 = ev.with_state(EvidenceState.SCANNING)
        assert ev2.state == EvidenceState.SCANNING

    def test_scanning_to_hashing(self) -> None:
        ev = make_evidence(EvidenceState.SCANNING)
        ev2 = ev.with_state(EvidenceState.HASHING)
        assert ev2.state == EvidenceState.HASHING

    def test_hashing_to_received(self) -> None:
        ev = make_evidence(EvidenceState.HASHING)
        ev2 = ev.with_state(EvidenceState.RECEIVED)
        assert ev2.state == EvidenceState.RECEIVED

    def test_received_to_parsing(self) -> None:
        ev = make_evidence(EvidenceState.RECEIVED)
        ev2 = ev.with_state(EvidenceState.PARSING)
        assert ev2.state == EvidenceState.PARSING

    def test_parsing_to_complete(self) -> None:
        ev = make_evidence(EvidenceState.PARSING)
        ev2 = ev.with_state(EvidenceState.COMPLETE)
        assert ev2.state == EvidenceState.COMPLETE

    def test_invalid_transition_raises(self) -> None:
        ev = make_evidence(EvidenceState.UPLOADING)
        with pytest.raises(EvidenceStateError):
            ev.with_state(EvidenceState.COMPLETE)

    def test_complete_is_terminal(self) -> None:
        ev = make_evidence(EvidenceState.COMPLETE)
        with pytest.raises(EvidenceStateError):
            ev.with_state(EvidenceState.PARSING)

    def test_error_from_scanning(self) -> None:
        ev = make_evidence(EvidenceState.SCANNING)
        ev2 = ev.with_error("virus detected")
        assert ev2.state == EvidenceState.ERROR
        assert ev2.error_reason == "virus detected"

    def test_error_from_hashing(self) -> None:
        ev = make_evidence(EvidenceState.HASHING)
        ev2 = ev.with_error("hash mismatch")
        assert ev2.state == EvidenceState.ERROR

    def test_error_on_complete_raises(self) -> None:
        ev = make_evidence(EvidenceState.COMPLETE)
        with pytest.raises(EvidenceStateError):
            ev.with_error("cannot fail a completed evidence")

    def test_immutability_preserves_original(self) -> None:
        ev = make_evidence(EvidenceState.UPLOADING)
        ev2 = ev.with_state(EvidenceState.SCANNING)
        assert ev.state == EvidenceState.UPLOADING
        assert ev2.state == EvidenceState.SCANNING

    def test_can_transition_to_positive(self) -> None:
        assert EvidenceState.UPLOADING.can_transition_to(EvidenceState.SCANNING)

    def test_can_transition_to_negative(self) -> None:
        assert not EvidenceState.UPLOADING.can_transition_to(EvidenceState.COMPLETE)

    def test_error_to_scanning_retry_intake(self) -> None:
        ev = make_evidence(EvidenceState.SCANNING).with_error("intake_failed:StorageError")
        ev2 = ev.with_state(EvidenceState.SCANNING)
        assert ev2.state == EvidenceState.SCANNING
        assert ev2.error_reason is None

    def test_error_to_parsing_retry_parse(self) -> None:
        ev = make_evidence(EvidenceState.PARSING).with_error("ingest_failed")
        ev2 = ev.with_state(EvidenceState.PARSING)
        assert ev2.state == EvidenceState.PARSING
        assert ev2.error_reason is None

    def test_error_to_received_is_invalid(self) -> None:
        ev = make_evidence(EvidenceState.PARSING).with_error("parse_failed")
        with pytest.raises(EvidenceStateError):
            ev.with_state(EvidenceState.RECEIVED)


class TestErrorReasonTaxonomy:
    @pytest.mark.parametrize(
        "reason",
        ["validation_failed", "size_limit_exceeded", "hash_mismatch", "no_parser_found"],
    )
    def test_terminal_reasons_not_retryable(self, reason: str) -> None:
        assert not is_retryable_error_reason(reason)

    def test_infected_prefix_not_retryable(self) -> None:
        assert not is_retryable_error_reason("infected:Eicar-Test-Signature")

    def test_none_reason_not_retryable(self) -> None:
        assert not is_retryable_error_reason(None)

    @pytest.mark.parametrize(
        "reason",
        [
            "intake_failed:StorageError",
            "upload_timeout",
            "intake_timeout",
            "parse_failed",
            "ingest_failed",
            "parse_timeout",
        ],
    )
    def test_unclassified_and_connectivity_reasons_are_retryable(self, reason: str) -> None:
        assert is_retryable_error_reason(reason)

    @pytest.mark.parametrize(
        "reason", ["no_parser_found", "parse_failed", "ingest_failed", "parse_timeout"]
    )
    def test_parse_stage_reasons(self, reason: str) -> None:
        assert is_parse_stage_error_reason(reason)

    @pytest.mark.parametrize(
        "reason",
        [
            "validation_failed",
            "size_limit_exceeded",
            "hash_mismatch",
            "intake_failed:StorageError",
            "upload_timeout",
            "intake_timeout",
            "infected:Eicar-Test-Signature",
            None,
        ],
    )
    def test_intake_stage_reasons_are_not_parse_stage(self, reason: str | None) -> None:
        assert not is_parse_stage_error_reason(reason)


class TestEvidenceModel:
    def test_evidence_is_frozen(self) -> None:
        from pydantic import ValidationError as PydanticValidationError

        ev = make_evidence()
        with pytest.raises((PydanticValidationError, TypeError)):
            ev.state = EvidenceState.ERROR  # type: ignore[misc]

    def test_with_hashes(self) -> None:
        ev = make_evidence()
        ev2 = ev.with_hashes("abc123", "def456")
        assert ev2.sha256 == "abc123"
        assert ev2.md5 == "def456"
        assert ev.sha256 is None  # original unchanged

    def test_with_keys(self) -> None:
        ev = make_evidence()
        ev2 = ev.with_keys("quarantine/key", "evidence/key")
        assert ev2.minio_quarantine_key == "quarantine/key"
        assert ev2.minio_evidence_key == "evidence/key"

    def test_evidence_id_generated(self) -> None:
        ev = make_evidence()
        assert isinstance(ev.evidence_id, uuid.UUID)

    def test_metadata_required_fields(self) -> None:
        meta = make_evidence_metadata()
        assert meta.original_filename == "test.evtx"
        assert meta.size_bytes == 1024
