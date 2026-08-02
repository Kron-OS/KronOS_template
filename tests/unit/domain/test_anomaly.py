"""Unit tests for the BehavioralAnomalySignal domain model (roadmap M6/G2).

Focus: the structural, mechanically-checkable non-reproducibility markers
G3 will depend on, frozen immutability, and bounds validation -- mirrors
tests/unit/domain/test_rarity.py's own shape for G1's sibling model.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.domain.anomaly import (
    AnomalyEntityDimension,
    AnomalyFeatureObservation,
    BehavioralAnomalySignal,
)


def _make_signal(**overrides: object) -> BehavioralAnomalySignal:
    defaults: dict[str, object] = {
        "org_id": uuid.uuid4(),
        "org_alias": "acme",
        "detector_id": "det-1",
        "detector_name": "kronos-acme-behavioral-ad-detector",
        "anomaly_grade": 0.75,
        "confidence": 0.9,
        "data_start_time": datetime(2026, 8, 1, tzinfo=UTC),
        "data_end_time": datetime(2026, 8, 1, 0, 10, tzinfo=UTC),
    }
    defaults.update(overrides)
    return BehavioralAnomalySignal(**defaults)  # type: ignore[arg-type]


class TestNonReproducibilityMarkers:
    """The two independent, mechanically-checkable markers G3's future
    harness depends on -- see module docstring's "belt-and-braces" reasoning."""

    def test_class_level_marker_is_true_without_instantiation(self) -> None:
        assert BehavioralAnomalySignal.NOT_REPRODUCIBLE is True

    def test_instance_field_marker_is_true(self) -> None:
        signal = _make_signal()
        assert signal.not_reproducible is True

    def test_instance_field_marker_survives_serialization(self) -> None:
        # G3's harness may inspect an already-serialized payload (e.g. an
        # API response body), not just a live Python object -- the marker
        # must survive that round-trip.
        signal = _make_signal()
        dumped = signal.model_dump(mode="json")
        assert dumped["not_reproducible"] is True

    def test_instance_field_cannot_be_constructed_false(self) -> None:
        with pytest.raises(ValidationError):
            _make_signal(not_reproducible=False)


class TestImmutability:
    def test_signal_is_frozen(self) -> None:
        signal = _make_signal()
        with pytest.raises(ValidationError):
            signal.anomaly_grade = 0.1  # type: ignore[misc]

    def test_entity_dimension_is_frozen(self) -> None:
        dim = AnomalyEntityDimension(name="host.name", value="host-1")
        with pytest.raises(ValidationError):
            dim.value = "host-2"  # type: ignore[misc]

    def test_feature_observation_is_frozen(self) -> None:
        obs = AnomalyFeatureObservation(feature_name="event_volume", observed_value=5.0)
        with pytest.raises(ValidationError):
            obs.observed_value = 6.0  # type: ignore[misc]


class TestBoundsValidation:
    def test_anomaly_grade_must_be_within_0_and_1(self) -> None:
        _make_signal(anomaly_grade=0.0)
        _make_signal(anomaly_grade=1.0)
        with pytest.raises(ValidationError):
            _make_signal(anomaly_grade=1.1)
        with pytest.raises(ValidationError):
            _make_signal(anomaly_grade=-0.1)

    def test_confidence_must_be_within_0_and_1_when_present(self) -> None:
        with pytest.raises(ValidationError):
            _make_signal(confidence=1.5)

    def test_confidence_may_be_none(self) -> None:
        signal = _make_signal(confidence=None)
        assert signal.confidence is None


class TestFeatureObservationHonestAbsence:
    def test_expected_value_defaults_to_none_not_a_fabricated_default(self) -> None:
        # Real, confirmed case: an early result whose RCF shingle isn't yet
        # full carries no expected_values at all (poc output) -- the
        # domain model must represent that honestly, never substitute 0.0
        # or any other fabricated neutral value.
        obs = AnomalyFeatureObservation(feature_name="event_volume", observed_value=42.0)
        assert obs.expected_value is None


class TestEntitiesAndFeaturesDefaultEmpty:
    def test_signal_with_no_category_field_has_empty_entities(self) -> None:
        signal = _make_signal()
        assert signal.entities == ()

    def test_signal_default_features_empty(self) -> None:
        signal = _make_signal()
        assert signal.features == ()

    def test_task_id_defaults_to_none_for_a_real_time_result(self) -> None:
        signal = _make_signal()
        assert signal.task_id is None

    def test_task_id_set_for_a_historical_analysis_result(self) -> None:
        signal = _make_signal(task_id="task-123")
        assert signal.task_id == "task-123"
