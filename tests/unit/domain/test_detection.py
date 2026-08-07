"""Unit tests for Detection domain model and triage FSM (no mocks -- pure domain)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.domain.detection import (
    Detection,
    DetectionCorrelation,
    DetectionRuleMatch,
    DetectionTriageState,
)
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
                    DetectionRuleMatch(
                        rule_id="r2", tags=("medium", "attack.t1021.001", "attack.t1210")
                    ),
                )
            }
        )
        assert d.attack_tags == ("attack.t1021.001", "attack.t1210")

    def test_attack_tags_empty_when_no_rule_matches(self) -> None:
        d = make_detection().model_copy(update={"rule_matches": ()})
        assert d.attack_tags == ()


class TestDetectionRuleSeverity:
    """Roadmap M5/F4: real Sigma severity vocabulary (confirmed against the
    live OpenSearch 2.11.1 cluster's own 2077 pre-packaged rules -- see
    poc/detection_risk_scoring/), extracted the same way attack_tags
    filters ATT&CK tags out of the same real, mixed tags list."""

    def test_rule_severity_extracts_the_bare_severity_token(self) -> None:
        d = make_detection()  # tags=("high", "network", "attack.t1021.001")
        assert d.rule_severity == "high"

    def test_rule_severity_picks_the_highest_across_multiple_rule_matches(self) -> None:
        d = make_detection().model_copy(
            update={
                "rule_matches": (
                    DetectionRuleMatch(rule_id="r1", tags=("low", "attack.t1006")),
                    DetectionRuleMatch(rule_id="r2", tags=("critical", "attack.t1210")),
                    DetectionRuleMatch(rule_id="r3", tags=("medium",)),
                )
            }
        )
        assert d.rule_severity == "critical"

    def test_rule_severity_none_when_no_recognized_severity_tag(self) -> None:
        d = make_detection().model_copy(
            update={
                "rule_matches": (
                    DetectionRuleMatch(rule_id="r1", tags=("network", "attack.t1210")),
                )
            }
        )
        assert d.rule_severity is None

    def test_rule_severity_none_when_no_rule_matches(self) -> None:
        d = make_detection().model_copy(update={"rule_matches": ()})
        assert d.rule_severity is None

    def test_rule_severity_recognizes_every_real_sigma_level(self) -> None:
        for level in ("informational", "low", "medium", "high", "critical"):
            d = make_detection().model_copy(
                update={"rule_matches": (DetectionRuleMatch(rule_id="r1", tags=(level,)),)}
            )
            assert d.rule_severity == level


class TestDetectionRiskScore:
    """Detection.risk_score/risk_factors are plain frozen fields, set once at
    construction (by DetectionSyncService in real use) -- see
    tests/unit/application/test_detection_sync.py for the full,
    real, end-to-end scoring path exercised through the sync service."""

    def test_risk_score_defaults_to_none(self) -> None:
        d = make_detection()
        assert d.risk_score is None
        assert d.risk_factors == ()

    def test_risk_score_and_factors_are_frozen(self) -> None:
        d = make_detection().model_copy(update={"risk_score": 75.0})
        with pytest.raises(Exception):  # noqa: B017
            d.risk_score = 10.0  # type: ignore[misc]


class TestDetectionExternalTicketId:
    """Roadmap M7/H4: a pure traceability pointer, never part of the triage
    FSM -- see with_external_ticket_id's own docstring."""

    def test_defaults_to_none(self) -> None:
        d = make_detection()
        assert d.external_ticket_id is None

    def test_with_external_ticket_id_sets_it(self) -> None:
        d = make_detection()
        d2 = d.with_external_ticket_id("TICKET-123")
        assert d2.external_ticket_id == "TICKET-123"

    def test_with_external_ticket_id_does_not_mutate_triage_state(self) -> None:
        d = make_detection(DetectionTriageState.INVESTIGATING)
        d2 = d.with_external_ticket_id("TICKET-123")
        assert d2.triage_state == DetectionTriageState.INVESTIGATING

    def test_with_external_ticket_id_updates_updated_at(self) -> None:
        d = make_detection()
        d2 = d.with_external_ticket_id("TICKET-123")
        assert d2.updated_at >= d.updated_at

    def test_with_external_ticket_id_rejects_empty_string(self) -> None:
        d = make_detection()
        with pytest.raises(ValueError, match="non-empty"):
            d.with_external_ticket_id("")

    def test_with_external_ticket_id_does_not_mutate_original(self) -> None:
        d = make_detection()
        d.with_external_ticket_id("TICKET-123")
        assert d.external_ticket_id is None

    def test_frozen_field(self) -> None:
        d = make_detection()
        with pytest.raises(Exception):  # noqa: B017
            d.external_ticket_id = "TICKET-123"  # type: ignore[misc]


class TestDetectionRuleMatch:
    def test_frozen(self) -> None:
        m = DetectionRuleMatch(rule_id="r1", tags=("high",))
        with pytest.raises(Exception):  # noqa: B017
            m.rule_id = "r2"  # type: ignore[misc]

    def test_tags_default_empty(self) -> None:
        m = DetectionRuleMatch(rule_id="r1")
        assert m.tags == ()


def make_correlation(**overrides: object) -> DetectionCorrelation:
    defaults: dict[str, object] = {
        "org_id": uuid.uuid4(),
        "detection_id_a": uuid.uuid4(),
        "detection_id_b": uuid.uuid4(),
        "finding_id_a": str(uuid.uuid4()),
        "finding_id_b": str(uuid.uuid4()),
        "rule_ids": ("rule-1",),
    }
    defaults.update(overrides)
    return DetectionCorrelation(**defaults)  # type: ignore[arg-type]


class TestDetectionCorrelation:
    def test_frozen(self) -> None:
        c = make_correlation()
        with pytest.raises(Exception):  # noqa: B017
            c.org_id = uuid.uuid4()  # type: ignore[misc]

    def test_rule_ids_default_empty(self) -> None:
        c = make_correlation(rule_ids=())
        assert c.rule_ids == ()

    def test_rule_ids_preserves_multiple_real_rule_ids(self) -> None:
        c = make_correlation(rule_ids=("rule-1", "rule-2"))
        assert c.rule_ids == ("rule-1", "rule-2")

    def test_correlation_id_auto_generated_and_unique(self) -> None:
        c1 = make_correlation()
        c2 = make_correlation()
        assert c1.correlation_id != c2.correlation_id

    def test_synced_at_defaults_to_now(self) -> None:
        c = make_correlation()
        assert c.synced_at is not None
