"""Unit tests for SentinelDetectionMapper (roadmap R4).

The rigid, 14-column record shape asserted here was independently designed
and documented against the real, current Azure Monitor Logs Ingestion
API/DCR contract -- see sentinel_detection_mapper.py's own module docstring
and poc/integration_sink_sentinel/README.md for the exact doc sources cited
(``streamDeclaration`` column types, the real ``dynamic`` catch-all
mechanism, the "every top-level property must be declared" rigidity rule).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from src.application.sentinel_detection_mapper import (
    DEFAULT_STREAM_NAME,
    DEFAULT_TABLE_NAME,
    SentinelDetectionMapper,
)
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState

_UNSET: Any = object()

_EXPECTED_COLUMNS = {
    "TimeGenerated",
    "DetectionId",
    "FindingId",
    "DetectorName",
    "OrgId",
    "OrgAlias",
    "CaseId",
    "SourceIndex",
    "TriageState",
    "RuleSeverity",
    "RiskScore",
    "AttackTags",
    "RuleMatches",
    "MatchedDocumentIds",
    "ExtendedProperties",
}


def _make_detection(
    finding_id: str = "f-1",
    *,
    case_id: uuid.UUID | None = _UNSET,
    org_alias: str = "acme-corp",
    external_ticket_id: str | None = None,
) -> Detection:
    detection = Detection(
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
    if external_ticket_id is not None:
        detection = detection.with_external_ticket_id(external_ticket_id)
    return detection


class TestSentinelDetectionMapperRigidSchema:
    def test_record_carries_exactly_the_declared_column_set(self) -> None:
        """The real DCR contract requires every top-level property present in
        a record to be declared -- this mapper must never emit a stray key
        (nor omit a nullable one, which must still appear as JSON null)."""
        mapper = SentinelDetectionMapper()
        event = mapper.map(_make_detection())
        assert event.payload is not None
        assert set(event.payload.keys()) == _EXPECTED_COLUMNS

    def test_scalar_columns_carry_real_detection_fields(self) -> None:
        mapper = SentinelDetectionMapper()
        case_id = uuid.uuid4()
        detection = _make_detection(finding_id="f-42", case_id=case_id)
        event = mapper.map(detection)
        assert event.payload is not None
        payload = event.payload
        assert payload["DetectionId"] == str(detection.detection_id)
        assert payload["FindingId"] == "f-42"
        assert payload["DetectorName"] == detection.detector_name
        assert payload["OrgId"] == str(detection.org_id)
        assert payload["OrgAlias"] == detection.org_alias
        assert payload["CaseId"] == str(case_id)
        assert payload["SourceIndex"] == detection.source_index
        assert payload["TriageState"] == DetectionTriageState.NEW.value
        assert payload["RuleSeverity"] == "high"
        assert payload["RiskScore"] == 72.5

    def test_time_generated_is_iso8601_string_from_finding_timestamp(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["TimeGenerated"] == detection.finding_timestamp.isoformat()

    def test_dynamic_columns_are_real_json_arrays_not_strings(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["AttackTags"] == ["attack.t1078"]
        assert event.payload["MatchedDocumentIds"] == ["doc-1", "doc-2"]
        assert event.payload["RuleMatches"] == [
            {"rule_id": "r1", "rule_name": "Suspicious Login", "tags": ["high", "attack.t1078"]}
        ]

    def test_nullable_columns_are_explicit_json_null_not_omitted(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = _make_detection(case_id=None)
        event = mapper.map(detection)
        assert event.payload is not None
        assert "CaseId" in event.payload
        assert event.payload["CaseId"] is None

    def test_risk_score_none_is_explicit_json_null(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = _make_detection().model_copy(update={"risk_score": None})
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["RiskScore"] is None

    def test_rule_severity_none_is_explicit_json_null_when_unrecognized(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = Detection(
            org_id=uuid.uuid4(),
            org_alias="acme-corp",
            finding_id="f-no-severity",
            detector_name="d",
            source_index="idx",
            rule_matches=(DetectionRuleMatch(rule_id="r1", rule_name="n", tags=("network",)),),
            finding_timestamp=datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC),
        )
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["RuleSeverity"] is None

    def test_extended_properties_is_the_real_catch_all_for_secondary_fields(self) -> None:
        """external_ticket_id/synced_at/updated_at don't earn their own
        first-class column (roadmap R4's own "what happens to fields that
        don't fit" question) -- they are never dropped, only bucketed into
        the one dynamic catch-all column."""
        mapper = SentinelDetectionMapper()
        detection = _make_detection(external_ticket_id="TICK-123")
        event = mapper.map(detection)
        assert event.payload is not None
        extended = event.payload["ExtendedProperties"]
        assert extended["external_ticket_id"] == "TICK-123"
        assert extended["synced_at"] == detection.synced_at.isoformat()
        assert extended["updated_at"] == detection.updated_at.isoformat()

    def test_extended_properties_ticket_id_none_when_unset(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.payload is not None
        assert event.payload["ExtendedProperties"]["external_ticket_id"] is None

    def test_source_detection_id_matches_detection(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.source_detection_id == str(detection.detection_id)

    def test_mapper_metadata_records_table_and_stream_names(self) -> None:
        mapper = SentinelDetectionMapper()
        event = mapper.map(_make_detection())
        assert event.mapper_metadata == {
            "table_name": DEFAULT_TABLE_NAME,
            "stream_name": DEFAULT_STREAM_NAME,
        }

    def test_mapper_never_mutates_the_detection(self) -> None:
        mapper = SentinelDetectionMapper()
        detection = _make_detection()
        before = detection.model_copy(deep=True)
        mapper.map(detection)
        assert detection == before

    def test_payload_is_json_serializable(self) -> None:
        mapper = SentinelDetectionMapper()
        event = mapper.map(_make_detection())
        # Must not raise -- every value must be directly JSON-serializable
        # (no datetime/UUID objects leaking through), since SentinelHttpSink
        # calls json.dumps([...]) on a list of these unchanged.
        json.dumps(event.payload)

    def test_two_detections_never_share_a_mutable_record(self) -> None:
        mapper = SentinelDetectionMapper()
        d1 = _make_detection(finding_id="f-1")
        d2 = _make_detection(finding_id="f-2")
        e1 = mapper.map(d1)
        e2 = mapper.map(d2)
        assert e1.payload is not None
        assert e2.payload is not None
        assert e1.payload["FindingId"] != e2.payload["FindingId"]
