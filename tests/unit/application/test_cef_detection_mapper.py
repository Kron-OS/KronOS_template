"""Unit tests for CefDetectionMapper (roadmap R3).

Escaping rules asserted here were independently verified against the real
official CEF specification first -- see cef_detection_mapper.py's own
module docstring for the exact sources cited (Micro Focus/OpenText
"Implementing ArcSight Common Event Format (CEF)" guide, corroborated by
Microsoft Sentinel's own CEF-via-AMA connector docs). This file focuses on
exhaustively exercising the escaping rules (the roadmap brief's own "this is
the part most likely to have subtle bugs" callout) at the string level;
full real-transport + round-trip-parse verification lives in
poc/integration_sink_cef_syslog/.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from src.application.cef_detection_mapper import (
    CefDetectionMapper,
    _escape_extension_value,
    _escape_header_field,
)
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState

_UNSET: Any = object()


def _split_escape_aware(value: str, delimiter: str, maxsplit: int | None = None) -> list[str]:
    """Real CEF parsing rule: split on *delimiter* only where it is NOT
    preceded by an (unescaped) backslash -- i.e. a backslash always escapes
    the very next character, so an escaped delimiter is never mistaken for
    a real one. This is the same "parse it back apart field-by-field, don't
    just eyeball it" standard the roadmap brief requires of the real PoC,
    applied here at unit-test scope too so header assertions stay correct
    even when a field's own value contains an escaped delimiter (see
    TestCefDetectionMapperEscapingEdgeCase).

    *maxsplit*, when given, stops splitting after that many delimiters and
    returns the remainder untouched -- exactly what's needed to isolate the
    7 real pipe-delimited CEF header fields from the extension tail, whose
    OWN unescaped pipes (real spec: "pipes in the extension do not need
    escaping") must NOT be treated as further header-field boundaries.
    """
    parts: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(value):
        if maxsplit is not None and len(parts) >= maxsplit:
            break
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            current.append(char)
            current.append(value[i + 1])
            i += 2
            continue
        if char == delimiter:
            parts.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    parts.append("".join(current) + value[i:])
    return parts


def _unescape_header_field(value: str) -> str:
    """Reverses _escape_header_field via a single greedy left-to-right pass
    (never sequential ``.replace()`` calls, which can misparse an escaped
    backslash immediately followed by a real delimiter -- the exact
    ambiguity this whole escaping scheme exists to avoid)."""
    result: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in ("\\", "|"):
            result.append(value[i + 1])
            i += 2
            continue
        result.append(char)
        i += 1
    return "".join(result)


def _make_detection(
    finding_id: str = "f-1",
    *,
    case_id: uuid.UUID | None = _UNSET,
    org_alias: str = "acme-corp",
    detector_name: str = "kronos-acme-network-detector",
    rule_matches: tuple[DetectionRuleMatch, ...] = (
        DetectionRuleMatch(
            rule_id="r1", rule_name="Suspicious Login", tags=("high", "attack.t1078")
        ),
    ),
    risk_score: float | None = 72.5,
) -> Detection:
    return Detection(
        org_id=uuid.uuid4(),
        org_alias=org_alias,
        case_id=uuid.uuid4() if case_id is _UNSET else case_id,
        finding_id=finding_id,
        detector_name=detector_name,
        source_index="kronos-acme-case-abc-202601",
        rule_matches=rule_matches,
        matched_document_ids=("doc-1", "doc-2"),
        finding_timestamp=datetime(2026, 8, 9, 12, 0, 5, tzinfo=UTC),
        risk_score=risk_score,
    )


class TestEscapeHeaderField:
    """Real CEF header/"prefix" rule: backslash first, then pipe; '=' untouched."""

    def test_pipe_is_escaped(self) -> None:
        assert _escape_header_field("a|b") == "a\\|b"

    def test_backslash_is_escaped(self) -> None:
        assert _escape_header_field("a\\b") == "a\\\\b"

    def test_equals_is_left_untouched(self) -> None:
        assert _escape_header_field("a=b") == "a=b"

    def test_backslash_escaped_before_pipe_no_double_escape(self) -> None:
        # A literal "\|" in the source (backslash followed by pipe) must
        # become "\\\|" (escaped backslash, then escaped pipe) -- NOT
        # "\\|" (which would misparse as one escaped pipe on read-back).
        assert _escape_header_field("a\\|b") == "a\\\\\\|b"

    def test_combined_all_three_characters(self) -> None:
        # '=' must survive completely untouched in the header zone.
        assert _escape_header_field("a|b\\c=d") == "a\\|b\\\\c=d"

    def test_newline_and_carriage_return_escaped(self) -> None:
        assert _escape_header_field("a\nb\rc") == "a\\nb\\rc"

    def test_empty_string(self) -> None:
        assert _escape_header_field("") == ""

    def test_no_special_characters_unchanged(self) -> None:
        assert _escape_header_field("plain text") == "plain text"


class TestEscapeExtensionValue:
    """Real CEF extension rule: backslash first, then equals; '|' untouched."""

    def test_equals_is_escaped(self) -> None:
        assert _escape_extension_value("a=b") == "a\\=b"

    def test_backslash_is_escaped(self) -> None:
        assert _escape_extension_value("a\\b") == "a\\\\b"

    def test_pipe_is_left_untouched(self) -> None:
        assert _escape_extension_value("a|b") == "a|b"

    def test_backslash_escaped_before_equals_no_double_escape(self) -> None:
        # A literal "\=" in the source must become "\\\=", not "\\=".
        assert _escape_extension_value("a\\=b") == "a\\\\\\=b"

    def test_combined_all_three_characters(self) -> None:
        # '|' must survive completely untouched in the extension zone.
        assert _escape_extension_value("a|b\\c=d") == "a|b\\\\c\\=d"

    def test_newline_and_carriage_return_escaped(self) -> None:
        assert _escape_extension_value("a\nb\rc") == "a\\nb\\rc"

    def test_empty_string(self) -> None:
        assert _escape_extension_value("") == ""

    def test_no_special_characters_unchanged(self) -> None:
        assert _escape_extension_value("plain text") == "plain text"


class TestCefDetectionMapperHeaderShape:
    def test_raw_text_set_not_payload(self) -> None:
        mapper = CefDetectionMapper()
        event = mapper.map(_make_detection())
        assert event.raw_text is not None
        assert event.payload is None

    def test_source_detection_id_matches_detection(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.source_detection_id == str(detection.detection_id)

    def test_cef_marker_and_version_present(self) -> None:
        mapper = CefDetectionMapper()
        event = mapper.map(_make_detection())
        assert event.raw_text is not None
        assert "CEF:0|" in event.raw_text

    def test_syslog_prefix_precedes_cef_marker(self) -> None:
        mapper = CefDetectionMapper()
        event = mapper.map(_make_detection())
        assert event.raw_text is not None
        # Real RFC 3164 framing: "<PRI>Mmm dd hh:mm:ss host CEF:0|..."
        assert event.raw_text.startswith("<")
        pri_end = event.raw_text.index(">")
        assert event.raw_text[1:pri_end].isdigit()
        cef_index = event.raw_text.index("CEF:0|")
        header_and_hostname = event.raw_text[pri_end + 1 : cef_index].strip()
        assert header_and_hostname.endswith("acme-corp")

    def test_pri_uses_default_local4_facility(self) -> None:
        mapper = CefDetectionMapper()
        event = mapper.map(_make_detection())
        assert event.raw_text is not None
        # local4 (20) * 8 + Notice (5) = 165.
        assert event.raw_text.startswith("<165>")

    def test_pri_overridable(self) -> None:
        mapper = CefDetectionMapper(syslog_facility=1, syslog_severity=6)
        event = mapper.map(_make_detection())
        assert event.raw_text is not None
        assert event.raw_text.startswith("<14>")  # 1*8+6

    def test_hostname_defaults_to_org_alias(self) -> None:
        mapper = CefDetectionMapper()
        event = mapper.map(_make_detection(org_alias="widgets-inc"))
        assert event.raw_text is not None
        assert " widgets-inc CEF:0|" in event.raw_text

    def test_hostname_override_takes_precedence(self) -> None:
        mapper = CefDetectionMapper(hostname="kronos-platform")
        event = mapper.map(_make_detection())
        assert event.raw_text is not None
        assert " kronos-platform CEF:0|" in event.raw_text

    def test_header_field_order_and_values(self) -> None:
        mapper = CefDetectionMapper(
            device_vendor="KronOS", device_product="DetectionSink", device_version="1.0"
        )
        detection = _make_detection(detector_name="net-detector")
        event = mapper.map(detection)
        assert event.raw_text is not None
        cef_part = event.raw_text[event.raw_text.index("CEF:0|") :]
        # Escape-aware split: 7 header fields, extension is whatever's left.
        fields = _split_escape_aware(cef_part, "|", maxsplit=7)
        assert fields[0] == "CEF:0"
        assert fields[1] == "KronOS"
        assert fields[2] == "DetectionSink"
        assert fields[3] == "1.0"
        assert fields[4] == "net-detector"
        assert fields[5] == "Suspicious Login"  # rule_matches[0].rule_name
        assert fields[6] == "8"  # 'high' -> CEF severity 8

    def test_name_falls_back_to_detector_name_when_no_rule_name(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(
            detector_name="fallback-detector",
            rule_matches=(DetectionRuleMatch(rule_id="r1", rule_name=None, tags=()),),
        )
        event = mapper.map(detection)
        assert event.raw_text is not None
        cef_part = event.raw_text[event.raw_text.index("CEF:0|") :]
        fields = _split_escape_aware(cef_part, "|", maxsplit=7)
        assert fields[5] == "fallback-detector"

    def test_severity_unknown_zero_when_no_severity_tag(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(
            rule_matches=(DetectionRuleMatch(rule_id="r1", rule_name="x", tags=("attack.t1078",)),)
        )
        event = mapper.map(detection)
        assert event.raw_text is not None
        cef_part = event.raw_text[event.raw_text.index("CEF:0|") :]
        fields = _split_escape_aware(cef_part, "|", maxsplit=7)
        assert fields[6] == "0"

    def test_severity_mapping_ascending(self) -> None:
        mapper = CefDetectionMapper()
        expected = {
            "informational": "0",
            "low": "3",
            "medium": "5",
            "high": "8",
            "critical": "10",
        }
        for sigma_level, cef_value in expected.items():
            detection = _make_detection(
                rule_matches=(DetectionRuleMatch(rule_id="r1", rule_name="x", tags=(sigma_level,)),)
            )
            event = mapper.map(detection)
            assert event.raw_text is not None
            cef_part = event.raw_text[event.raw_text.index("CEF:0|") :]
            fields = _split_escape_aware(cef_part, "|", maxsplit=7)
            assert fields[6] == cef_value


class TestCefDetectionMapperExtension:
    def test_extension_contains_expected_keys(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.raw_text is not None
        extension = _split_escape_aware(
            event.raw_text[event.raw_text.index("CEF:0|") :], "|", maxsplit=7
        )[7]
        assert f"externalId={detection.detection_id}" in extension
        assert "cat=kronos-acme-network-detector" in extension
        assert "cs1Label=KronOS Org ID" in extension
        assert f"cs1={detection.org_id}" in extension
        assert "cs3=NEW" in extension
        assert "cn1=72.5" in extension

    def test_case_id_omitted_entirely_when_none(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(case_id=None)
        event = mapper.map(detection)
        assert event.raw_text is not None
        extension = _split_escape_aware(
            event.raw_text[event.raw_text.index("CEF:0|") :], "|", maxsplit=7
        )[7]
        assert "cs2" not in extension
        assert "cs2Label" not in extension

    def test_case_id_present_when_set(self) -> None:
        case_id = uuid.uuid4()
        mapper = CefDetectionMapper()
        detection = _make_detection(case_id=case_id)
        event = mapper.map(detection)
        assert event.raw_text is not None
        extension = _split_escape_aware(
            event.raw_text[event.raw_text.index("CEF:0|") :], "|", maxsplit=7
        )[7]
        assert f"cs2={case_id}" in extension

    def test_risk_score_omitted_when_none(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(risk_score=None)
        event = mapper.map(detection)
        assert event.raw_text is not None
        extension = _split_escape_aware(
            event.raw_text[event.raw_text.index("CEF:0|") :], "|", maxsplit=7
        )[7]
        assert "cn1" not in extension

    def test_attack_tags_joined_by_comma(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(
            rule_matches=(
                DetectionRuleMatch(
                    rule_id="r1", rule_name="x", tags=("high", "attack.t1078", "attack.t1021")
                ),
            )
        )
        event = mapper.map(detection)
        assert event.raw_text is not None
        extension = _split_escape_aware(
            event.raw_text[event.raw_text.index("CEF:0|") :], "|", maxsplit=7
        )[7]
        assert "cs4=attack.t1078,attack.t1021" in extension


class TestCefDetectionMapperEscapingEdgeCase:
    """The roadmap brief's own required deliberate edge case: a Detection
    whose fields contain a literal '|', '\\', or '=' character."""

    def test_pipe_in_detector_name_escaped_in_header_unescaped_in_extension(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(detector_name="malware|scanner")
        event = mapper.map(detection)
        assert event.raw_text is not None
        cef_part = event.raw_text[event.raw_text.index("CEF:0|") :]
        fields = _split_escape_aware(cef_part, "|", maxsplit=7)
        # Header field 4 (Device Event Class ID) must carry the ESCAPED pipe
        # as ONE token -- an escape-aware parser does not split on it.
        assert fields[4] == "malware\\|scanner"
        # Real round-trip: unescaping the header field recovers the exact
        # original raw Detection value.
        assert _unescape_header_field(fields[4]) == "malware|scanner"
        # ...but the SAME raw value, reused in the 'cat' extension field,
        # must NOT be escaped there (extension pipes need no escaping) --
        # so it appears completely unescaped, verbatim, in the extension.
        extension = fields[7]
        assert "cat=malware|scanner" in extension

    def test_backslash_in_rule_name_escaped_in_header(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(
            rule_matches=(
                DetectionRuleMatch(rule_id="r1", rule_name="suspicious\\process", tags=("high",)),
            )
        )
        event = mapper.map(detection)
        assert event.raw_text is not None
        cef_part = event.raw_text[event.raw_text.index("CEF:0|") :]
        fields = _split_escape_aware(cef_part, "|", maxsplit=7)
        assert fields[5] == "suspicious\\\\process"
        assert _unescape_header_field(fields[5]) == "suspicious\\process"

    def test_equals_in_finding_id_escaped_in_extension_msg(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(finding_id="find=123")
        event = mapper.map(detection)
        assert event.raw_text is not None
        extension = _split_escape_aware(
            event.raw_text[event.raw_text.index("CEF:0|") :], "|", maxsplit=7
        )[7]
        assert "msg=KronOS detection find\\=123 (NEW)" in extension

    def test_all_three_characters_together_in_one_header_field(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection(detector_name="a|b\\c=d")
        event = mapper.map(detection)
        assert event.raw_text is not None
        cef_part = event.raw_text[event.raw_text.index("CEF:0|") :]
        fields = _split_escape_aware(cef_part, "|", maxsplit=7)
        # detector_name is field index 4 (Device Event Class ID) -- the
        # escape-aware parser correctly keeps it as ONE token even though
        # it contains an escaped pipe, because that pipe is preceded by a
        # backslash the parser recognizes as an escape marker.
        assert fields[4] == "a\\|b\\\\c=d"
        # '=' survived completely untouched (real spec: no escaping needed
        # in the header zone); '|' and '\' both got escaped. Full real
        # round-trip recovers the exact original raw value.
        assert _unescape_header_field(fields[4]) == "a|b\\c=d"
        assert _unescape_header_field(fields[4]) == detection.detector_name


class TestCefDetectionMapperGeneral:
    def test_mapper_never_mutates_the_detection(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection()
        before = detection.model_copy(deep=True)
        mapper.map(detection)
        assert detection == before

    def test_mapper_metadata_records_target_config(self) -> None:
        mapper = CefDetectionMapper(device_vendor="V", device_product="P")
        detection = _make_detection()
        event = mapper.map(detection)
        assert event.mapper_metadata["device_vendor"] == "V"
        assert event.mapper_metadata["device_product"] == "P"
        assert event.mapper_metadata["device_event_class_id"] == detection.detector_name

    def test_triage_state_reflected_in_extension(self) -> None:
        mapper = CefDetectionMapper()
        detection = _make_detection().with_triage_state(DetectionTriageState.INVESTIGATING)
        event = mapper.map(detection)
        assert event.raw_text is not None
        extension = _split_escape_aware(
            event.raw_text[event.raw_text.index("CEF:0|") :], "|", maxsplit=7
        )[7]
        assert "cs3=INVESTIGATING" in extension
