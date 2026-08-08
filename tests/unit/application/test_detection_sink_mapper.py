"""Unit tests for MappedSinkEvent/DetectionEventMapper (roadmap R1).

No named-vendor mapper exists yet (R2/R4 own scope) -- these tests use a
minimal, real, in-process test-double mapper to prove the ABC's own
contract, mirroring test_ticket_sync_action.py's own
"_FakeTicketingSystem" idiom for an ABC with no first-party concrete
implementation to test directly yet.
"""

from __future__ import annotations

import uuid
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent
from src.domain.detection import Detection, DetectionRuleMatch


def _make_detection(finding_id: str = "f-1") -> Detection:
    return Detection(
        org_id=uuid.uuid4(),
        org_alias="testorg",
        case_id=uuid.uuid4(),
        finding_id=finding_id,
        detector_name="kronos-testorg-network-detector",
        source_index="kronos-testorg-case-abc-202601",
        rule_matches=(DetectionRuleMatch(rule_id="r1", tags=("high", "attack.t1021.001")),),
        finding_timestamp=datetime.now(UTC),
    )


class _JsonStandInMapper(DetectionEventMapper):
    """A deliberately generic, non-vendor-specific JSON mapper test double."""

    def map(self, detection: Detection) -> MappedSinkEvent:
        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            payload={"finding_id": detection.finding_id, "severity": detection.rule_severity},
            mapper_metadata={"target": "stand-in-json"},
        )


class _RawTextStandInMapper(DetectionEventMapper):
    """A deliberately generic, non-vendor-specific line-oriented mapper test double."""

    def map(self, detection: Detection) -> MappedSinkEvent:
        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            raw_text=f"CEF:0|KronOS|Detection|1.0|{detection.finding_id}|{detection.detector_name}|5|",
        )


class TestMappedSinkEventInvariant:
    def test_payload_only_is_valid(self) -> None:
        event = MappedSinkEvent(source_detection_id="1", payload={"a": 1})
        assert event.payload == {"a": 1}
        assert event.raw_text is None

    def test_raw_text_only_is_valid(self) -> None:
        event = MappedSinkEvent(source_detection_id="1", raw_text="line")
        assert event.raw_text == "line"
        assert event.payload is None

    def test_neither_set_raises(self) -> None:
        with pytest.raises(ValueError):
            MappedSinkEvent(source_detection_id="1")

    def test_both_set_raises(self) -> None:
        with pytest.raises(ValueError):
            MappedSinkEvent(source_detection_id="1", payload={"a": 1}, raw_text="line")

    def test_mapper_metadata_defaults_to_empty_dict(self) -> None:
        event = MappedSinkEvent(source_detection_id="1", payload={})
        assert event.mapper_metadata == {}

    def test_is_frozen(self) -> None:
        event = MappedSinkEvent(source_detection_id="1", payload={"a": 1})
        with pytest.raises(FrozenInstanceError):
            event.source_detection_id = "2"  # type: ignore[misc]


class TestDetectionEventMapperPluggability:
    """Proves the ABC is genuinely pluggable across structurally different
    target shapes (JSON payload vs. line-oriented raw_text) with zero
    changes to Detection or to any orchestration code -- see also
    poc/integration_sink_foundation/ for the same proof end-to-end against
    real transports."""

    def test_json_mapper_produces_payload_shaped_event(self) -> None:
        mapper = _JsonStandInMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["finding_id"] == detection.finding_id
        assert event.source_detection_id == str(detection.detection_id)

    def test_raw_text_mapper_produces_line_shaped_event(self) -> None:
        mapper = _RawTextStandInMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.raw_text is not None
        assert detection.finding_id in event.raw_text

    def test_mapper_never_mutates_the_detection(self) -> None:
        mapper = _JsonStandInMapper()
        detection = _make_detection()
        before = detection.model_copy(deep=True)
        mapper.map(detection)
        assert detection == before
