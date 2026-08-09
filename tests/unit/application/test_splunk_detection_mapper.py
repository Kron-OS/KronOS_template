"""Unit tests for SplunkDetectionMapper (roadmap R2).

Envelope shape asserted here (top-level time/host/source/sourcetype/index
vs. nested event) was independently verified against the real official
Splunk HEC docs first -- see poc/integration_sink_splunk_hec/README.md and
splunk_hec_sink.py's own module docstring for the exact sources cited.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from src.application.splunk_detection_mapper import SplunkDetectionMapper
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState

_UNSET: Any = object()


def _make_detection(
    finding_id: str = "f-1",
    *,
    case_id: uuid.UUID | None = _UNSET,
    org_alias: str = "acme-corp",
) -> Detection:
    return Detection(
        org_id=uuid.uuid4(),
        org_alias=org_alias,
        case_id=uuid.uuid4() if case_id is _UNSET else case_id,
        finding_id=finding_id,
        detector_name="kronos-acme-network-detector",
        source_index="kronos-acme-case-abc-202601",
        rule_matches=(
            DetectionRuleMatch(
                rule_id="r1", rule_name="Suspicious Login", tags=("high", "attack.t1078")
            ),
        ),
        matched_document_ids=("doc-1", "doc-2"),
        finding_timestamp=datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC),
        risk_score=72.5,
    )


class TestSplunkDetectionMapperEnvelopeShape:
    def test_top_level_hec_fields_present(self) -> None:
        mapper = SplunkDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)

        assert event.payload is not None
        assert event.payload["time"] == detection.finding_timestamp.timestamp()
        assert event.payload["source"] == "kronos:detection_sink"
        assert event.payload["sourcetype"] == "kronos:detection"
        # index omitted by default (real HEC: falls back to the token's own
        # configured default index when not set at the request level).
        assert "index" not in event.payload

    def test_host_defaults_to_org_alias(self) -> None:
        mapper = SplunkDetectionMapper()
        detection = _make_detection(org_alias="widgets-inc")
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["host"] == "widgets-inc"

    def test_host_override_takes_precedence(self) -> None:
        mapper = SplunkDetectionMapper(host="kronos-platform")
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["host"] == "kronos-platform"

    def test_index_included_when_configured(self) -> None:
        mapper = SplunkDetectionMapper(index="kronos_detections")
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["index"] == "kronos_detections"

    def test_source_sourcetype_overridable(self) -> None:
        mapper = SplunkDetectionMapper(source="my-app", sourcetype="my:type")
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["source"] == "my-app"
        assert event.payload["sourcetype"] == "my:type"

    def test_event_field_is_nested_object_not_string(self) -> None:
        mapper = SplunkDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert isinstance(event.payload["event"], dict)

    def test_event_body_carries_real_detection_fields(self) -> None:
        mapper = SplunkDetectionMapper()
        case_id = uuid.uuid4()
        detection = _make_detection(finding_id="f-42", case_id=case_id)
        event = mapper.map(detection)
        assert event.payload is not None
        body = event.payload["event"]
        assert body["finding_id"] == "f-42"
        assert body["detection_id"] == str(detection.detection_id)
        assert body["org_id"] == str(detection.org_id)
        assert body["org_alias"] == detection.org_alias
        assert body["case_id"] == str(case_id)
        assert body["detector_name"] == detection.detector_name
        assert body["source_index"] == detection.source_index
        assert body["triage_state"] == DetectionTriageState.NEW.value
        assert body["rule_severity"] == "high"
        assert body["attack_tags"] == ["attack.t1078"]
        assert body["risk_score"] == 72.5
        assert body["matched_document_ids"] == ["doc-1", "doc-2"]
        assert body["rule_matches"] == [
            {"rule_id": "r1", "rule_name": "Suspicious Login", "tags": ["high", "attack.t1078"]}
        ]

    def test_none_case_id_maps_to_none_not_string(self) -> None:
        mapper = SplunkDetectionMapper()
        detection = _make_detection(case_id=None)
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["event"]["case_id"] is None

    def test_source_detection_id_matches_detection(self) -> None:
        mapper = SplunkDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.source_detection_id == str(detection.detection_id)

    def test_mapper_metadata_records_target_config(self) -> None:
        mapper = SplunkDetectionMapper(source="s", sourcetype="st", index="idx")
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.mapper_metadata == {"source": "s", "sourcetype": "st", "index": "idx"}

    def test_mapper_never_mutates_the_detection(self) -> None:
        mapper = SplunkDetectionMapper()
        detection = _make_detection()
        before = detection.model_copy(deep=True)
        mapper.map(detection)
        assert detection == before

    def test_payload_is_json_serializable(self) -> None:
        import json

        mapper = SplunkDetectionMapper(index="idx")
        detection = _make_detection()
        event = mapper.map(detection)
        # Must not raise -- every value in the envelope must be a real,
        # directly JSON-serializable type (no datetime/UUID objects leaking
        # through), since SplunkHecSink calls json.dumps on this unchanged.
        json.dumps(event.payload)
