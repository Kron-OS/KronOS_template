"""Unit tests for parse_stix21_bundle (roadmap M5/F2).

Bundle/indicator shapes mirror the real STIX 2.1 shapes confirmed against
the official OASIS spec and the official oasis-open/cti-python-stix2 test
suite -- see poc/threat_intel_stix_ingest/README.md for the exact sources
and poc/threat_intel_stix_ingest/sample_bundle.json for the real PoC run
against these same shapes."""

from __future__ import annotations

import json

import pytest

from src.application.stix_ioc_parser import (
    _MAX_BUNDLE_BYTES,
    _MAX_OBJECTS,
    parse_stix21_bundle,
)
from src.domain.ioc_feed import IOCType
from src.exceptions import ValidationError

_SHA256_HEX = "3059be08a17bebc0f4edb82e52a0297f32347b556c474a3f252d3b149a7b17ba"


def _indicator_obj(pattern: object, **overrides: object) -> dict[str, object]:
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--10000000-0000-4000-8000-000000000001",
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-01-01T00:00:00.000Z",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2024-01-01T00:00:00Z",
    }
    obj.update(overrides)
    return obj


def _bundle(*objects: dict[str, object]) -> bytes:
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": list(objects)}).encode()


class TestParseStix21BundleStructure:
    def test_not_json_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            parse_stix21_bundle(b"not json at all {{{")

    def test_json_but_not_object_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            parse_stix21_bundle(b"[1, 2, 3]")

    def test_missing_bundle_type_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            parse_stix21_bundle(b'{"type": "not-a-bundle", "objects": []}')

    def test_objects_not_a_list_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            parse_stix21_bundle(b'{"type": "bundle", "objects": "nope"}')

    def test_oversized_bundle_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            parse_stix21_bundle(b"0" * (_MAX_BUNDLE_BYTES + 1))

    def test_too_many_objects_raises_validation_error(self) -> None:
        pattern = "[ipv4-addr:value = '10.0.0.1']"
        objects = [_indicator_obj(pattern) for _ in range(_MAX_OBJECTS + 1)]
        with pytest.raises(ValidationError):
            parse_stix21_bundle(_bundle(*objects))

    def test_empty_objects_list_is_valid_and_yields_nothing(self) -> None:
        assert parse_stix21_bundle(_bundle()) == []


class TestParseStix21BundleRealPatternShapes:
    def test_ipv4_indicator_extracted(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(_indicator_obj("[ipv4-addr:value = '203.0.113.66']"))
        )
        assert len(indicators) == 1
        assert indicators[0].ioc_type == IOCType.IP
        assert indicators[0].value == "203.0.113.66"

    def test_ipv6_indicator_extracted(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(_indicator_obj("[ipv6-addr:value = '2001:db8::1']"))
        )
        assert len(indicators) == 1
        assert indicators[0].ioc_type == IOCType.IP
        assert indicators[0].value == "2001:db8::1"

    def test_domain_name_indicator_extracted(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(_indicator_obj("[domain-name:value = 'evil-poc-example.test']"))
        )
        assert len(indicators) == 1
        assert indicators[0].ioc_type == IOCType.DOMAIN
        assert indicators[0].value == "evil-poc-example.test"

    def test_sha256_quoted_key_indicator_extracted(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(_indicator_obj(f"[file:hashes.'SHA-256' = '{_SHA256_HEX}']"))
        )
        assert len(indicators) == 1
        assert indicators[0].ioc_type == IOCType.FILE_HASH_SHA256
        assert indicators[0].value == _SHA256_HEX

    def test_sha256_bare_key_indicator_extracted(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(_indicator_obj(f"[file:hashes.SHA256 = '{_SHA256_HEX}']"))
        )
        assert len(indicators) == 1
        assert indicators[0].ioc_type == IOCType.FILE_HASH_SHA256

    def test_confidence_and_description_and_source_ref_carried_through(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(
                _indicator_obj(
                    "[ipv4-addr:value = '203.0.113.66']",
                    confidence=85,
                    description="C2 IP",
                )
            )
        )
        assert indicators[0].confidence == 85
        assert indicators[0].description == "C2 IP"
        assert indicators[0].source_ref == "indicator--10000000-0000-4000-8000-000000000001"

    def test_out_of_range_confidence_is_dropped_not_clamped(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(_indicator_obj("[ipv4-addr:value = '203.0.113.66']", confidence=999))
        )
        assert indicators[0].confidence is None


class TestParseStix21BundleUntrustedInputHandling:
    """CLAUDE.md F2 objective: "treat feed content as untrusted input"."""

    def test_md5_only_hash_is_honestly_skipped_not_crashed(self) -> None:
        indicators = parse_stix21_bundle(
            _bundle(_indicator_obj("[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']"))
        )
        assert indicators == []

    def test_compound_and_pattern_is_honestly_skipped(self) -> None:
        """Real compound pattern from the OASIS STIX 2.1 spec's own examples."""
        indicators = parse_stix21_bundle(
            _bundle(
                _indicator_obj(
                    "[domain-name:value = 'www.5z8.info' AND "
                    "domain-name:resolves_to_refs[*].value = '198.51.100.5']"
                )
            )
        )
        assert indicators == []

    def test_non_string_pattern_is_honestly_skipped_not_crashed(self) -> None:
        indicators = parse_stix21_bundle(_bundle(_indicator_obj(12345)))
        assert indicators == []

    def test_overlong_pattern_is_honestly_skipped(self) -> None:
        huge_pattern = "[domain-name:value = '" + ("a" * 3000) + ".test']"
        indicators = parse_stix21_bundle(_bundle(_indicator_obj(huge_pattern)))
        assert indicators == []

    def test_non_indicator_sdo_is_ignored(self) -> None:
        malware_obj = {
            "type": "malware",
            "spec_version": "2.1",
            "id": "malware--00000000-0000-4000-8000-000000000003",
            "created": "2024-01-01T00:00:00.000Z",
            "modified": "2024-01-01T00:00:00.000Z",
            "name": "Cryptolocker",
            "malware_types": ["ransomware"],
            "is_family": False,
        }
        assert parse_stix21_bundle(_bundle(malware_obj)) == []

    def test_missing_pattern_field_is_honestly_skipped(self) -> None:
        obj = _indicator_obj("[ipv4-addr:value = '203.0.113.66']")
        del obj["pattern"]
        assert parse_stix21_bundle(_bundle(obj)) == []

    def test_object_not_a_dict_is_ignored(self) -> None:
        raw = {"type": "bundle", "id": "bundle--x", "objects": ["not-a-dict", 42]}
        assert parse_stix21_bundle(json.dumps(raw).encode()) == []

    def test_pattern_value_is_captured_as_inert_text_never_evaluated(self) -> None:
        """A value that would produce a DIFFERENT result if evaluated as a
        Python expression (arithmetic, an import call, ...) must come out
        exactly as the raw quoted string -- proving regex-only extraction,
        never eval()/exec() against untrusted feed content."""
        hostile_pattern = '[ipv4-addr:value = \'__import__("os").system("true")\']'
        indicators = parse_stix21_bundle(_bundle(_indicator_obj(hostile_pattern)))
        assert len(indicators) == 1
        assert indicators[0].value == '__import__("os").system("true")'

        arithmetic_pattern = "[domain-name:value = '2+2']"
        indicators2 = parse_stix21_bundle(_bundle(_indicator_obj(arithmetic_pattern)))
        assert indicators2[0].value == "2+2"  # never evaluated to "4"

    def test_mixed_bundle_one_bad_object_never_blocks_the_good_ones(self) -> None:
        """The exact PoC bundle shape: 3 real indicators + 3 unsupported/
        malformed + 1 non-indicator SDO -- must yield exactly 3."""
        objects = [
            _indicator_obj("[ipv4-addr:value = '203.0.113.66']"),
            _indicator_obj("[domain-name:value = 'evil-poc-example.test']"),
            _indicator_obj(f"[file:hashes.'SHA-256' = '{_SHA256_HEX}']"),
            _indicator_obj("[file:hashes.MD5 = '79054025255fb1a26e4bc422aef54eb4']"),
            _indicator_obj(
                "[domain-name:value = 'www.5z8.info' AND "
                "domain-name:resolves_to_refs[*].value = '198.51.100.5']"
            ),
            _indicator_obj(12345),
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--00000000-0000-4000-8000-000000000003",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": "Cryptolocker",
                "malware_types": ["ransomware"],
                "is_family": False,
            },
        ]
        indicators = parse_stix21_bundle(_bundle(*objects))
        assert len(indicators) == 3
        expected_types = {IOCType.IP, IOCType.DOMAIN, IOCType.FILE_HASH_SHA256}
        assert {i.ioc_type for i in indicators} == expected_types
