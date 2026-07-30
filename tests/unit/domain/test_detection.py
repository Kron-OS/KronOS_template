"""Unit tests for Detection domain model and triage FSM (no mocks -- pure domain)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState
from src.exceptions import DetectionStateError


def make_detection(state: DetectionTriageState = DetectionTriageState.NEW) -> Detection:
    return Detection(
        org_id=uuid.uuid4(),
        org_alias="acme",
        case_id=uuid.uuid4(),
        finding_id=str(uuid.uuid4()),
        detector_name="kronos-acme-network-detector",
        source_index="kronos-acme-case-abc-202601",
        rule_matches=(
            DetectionRuleMatch(
                rule_id="1fc0809e-06bf-4de3-ad52-25e5263b7623",
                rule_name="1fc0809e-06bf-4de3-ad52-25e5263b7623",
                tags=("high", "network", "attack.t1021.001"),
            ),
        ),
        matched_document_ids=("abc123",),
        finding_timestamp=datetime.now(UTC),
        triage_state=state,
    )


class TestDetectionTriageFSM:
    def test_initial_state_is_new(self) -> None:
        d = make_detection()
        assert d.triage_state == DetectionTriageState.NEW

    def test_new_to_investigating(self) -> None:
        d = make_detection(DetectionTriageState.NEW)
        d2 = d.with_triage_state(DetectionTriageState.INVESTIGATING)
        assert d2.triage_state == DetectionTriageState.INVESTIGATING

    def test_investigating_to_true_positive(self) -> None:
        d = make_detection(DetectionTriageState.INVESTIGATING)
        d2 = d.with_triage_state(DetectionTriageState.TRUE_POSITIVE)
        assert d2.triage_state == DetectionTriageState.TRUE_POSITIVE

    def test_investigating_to_false_positive(self) -> None:
        d = make_detection(DetectionTriageState.INVESTIGATING)
        d2 = d.with_triage_state(DetectionTriageState.FALSE_POSITIVE)
        assert d2.triage_state == DetectionTriageState.FALSE_POSITIVE

    def test_new_cannot_skip_to_true_positive(self) -> None:
        d = make_detection(DetectionTriageState.NEW)
        with pytest.raises(DetectionStateError):
            d.with_triage_state(DetectionTriageState.TRUE_POSITIVE)

    def test_new_cannot_skip_to_false_positive(self) -> None:
        d = make_detection(DetectionTriageState.NEW)
        with pytest.raises(DetectionStateError):
            d.with_triage_state(DetectionTriageState.FALSE_POSITIVE)

    def test_true_positive_is_terminal(self) -> None:
        d = make_detection(DetectionTriageState.TRUE_POSITIVE)
        with pytest.raises(DetectionStateError):
            d.with_triage_state(DetectionTriageState.INVESTIGATING)

    def test_false_positive_is_terminal(self) -> None:
        d = make_detection(DetectionTriageState.FALSE_POSITIVE)
        with pytest.raises(DetectionStateError):
            d.with_triage_state(DetectionTriageState.INVESTIGATING)

    def test_investigating_cannot_go_back_to_new(self) -> None:
        d = make_detection(DetectionTriageState.INVESTIGATING)
        with pytest.raises(DetectionStateError):
            d.with_triage_state(DetectionTriageState.NEW)

    def test_with_triage_state_updates_updated_at(self) -> None:
        d = make_detection(DetectionTriageState.NEW)
        d2 = d.with_triage_state(DetectionTriageState.INVESTIGATING)
        assert d2.updated_at >= d.updated_at

    def test_frozen_model(self) -> None:
        d = make_detection()
        with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError on frozen model
            d.triage_state = DetectionTriageState.INVESTIGATING  # type: ignore[misc]


class TestDetectionAttackTags:
    def test_attack_tags_extracts_attack_prefixed_tags_only(self) -> None:
        d = make_detection()
        assert d.attack_tags == ("attack.t1021.001",)

    def test_attack_tags_dedupes_across_multiple_rule_matches(self) -> None:
        d = make_detection().model_copy(
            update={
                "rule_matches": (
                    DetectionRuleMatch(rule_id="r1", tags=("high", "attack.t1021.001")),
                    DetectionRuleMatch(rule_id="r2", tags=("medium", "attack.t1021.001", "attack.t1210")),
                )
            }
        )
        assert d.attack_tags == ("attack.t1021.001", "attack.t1210")

    def test_attack_tags_empty_when_no_rule_matches(self) -> None:
        d = make_detection().model_copy(update={"rule_matches": ()})
        assert d.attack_tags == ()


class TestDetectionRuleMatch:
    def test_frozen(self) -> None:
        m = DetectionRuleMatch(rule_id="r1", tags=("high",))
        with pytest.raises(Exception):  # noqa: B017
            m.rule_id = "r2"  # type: ignore[misc]

    def test_tags_default_empty(self) -> None:
        m = DetectionRuleMatch(rule_id="r1")
        assert m.tags == ()
