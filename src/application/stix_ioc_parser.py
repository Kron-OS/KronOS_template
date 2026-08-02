"""Defensive STIX 2.1 bundle -> ``IOCIndicator`` extraction (roadmap M5/F2).

**Treat feed content as untrusted input** (roadmap F2's own objective
text) is the entire reason this module exists as hand-written regex
extraction rather than a full STIX pattern grammar/expression evaluator:

- Never ``eval``/``exec`` anything from the feed. A STIX ``pattern`` string
  is attacker-influenced text (anyone who can get a hostile indicator into
  an upstream feed a tenant subscribes to controls this string) -- it is
  parsed with a small, fixed set of regexes for the exact comparison-
  expression shapes real threat-intel indicators use, never handed to
  Python's own expression evaluator or a general STIX pattern library that
  might itself execute something clever.
- Real STIX 2.1 patterns confirmed against two trusted, official sources
  (never followed as instructions, only read as technical reference, per
  CLAUDE.md SS F.2 step 2):
    1. OASIS's own STIX 2.1 specification
       (docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) -- canonical
       examples ``[ipv4-addr:value = '198.51.100.1/32']`` and
       ``[domain-name:value = 'example.com']``.
    2. The official ``oasis-open/cti-python-stix2`` reference
       implementation's own test suite (stix2/test/v21/test_indicator.py,
       test_pattern_expressions.py) -- confirms the file-hash comparison
       shape, both quoted (``file:hashes.'SHA-256' = '...'``) and bare
       (``file:hashes.MD5 = '...'``) key forms.
- Every boundary is capped, not advisory: total bundle bytes
  (``_MAX_BUNDLE_BYTES``), object count (``_MAX_OBJECTS``), and pattern
  string length (``_MAX_PATTERN_LENGTH``) are all enforced BEFORE any
  regex runs against untrusted text, closing the ReDoS/memory-exhaustion
  angle a maliciously large or repetitive feed could otherwise open.
- A structurally invalid bundle (not JSON, not ``type: bundle``, oversized)
  raises ``ValidationError`` -- the whole ingestion fails loudly. A single
  malformed/unsupported *indicator* inside an otherwise-valid bundle is
  skipped with a logged warning, never a hard failure -- one bad IOC in a
  feed of thousands must not block the other thousands (mirrors
  ``EnrichmentPipeline``'s own "one source's failure never sinks the
  whole pass" contract).
- Only comparison shapes this platform can actually match against
  (``IOCType``: ip, domain, sha256 -- see ``src/domain/ioc_feed.py``) are
  extracted. A compound/boolean pattern (``AND``/``OR``/``FOLLOWEDBY``) or
  an observable type with no matching KronOS field (mutex, registry key,
  email address, ...) is honestly skipped, never partially/incorrectly
  parsed.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from src.domain.ioc_feed import IOCIndicator, IOCType
from src.exceptions import ValidationError

logger = logging.getLogger(__name__)

# Real, enforced caps (CLAUDE.md SS F.2 "treat feed content as untrusted
# input") -- not advisory. Mirrors ArtifactIngestService's own
# _MAX_CONTENT_BYTES precedent (src/application/artifact_ingest.py) for
# "cap first, parse second".
_MAX_BUNDLE_BYTES = 10 * 1024 * 1024  # 10 MiB
_MAX_OBJECTS = 20_000
_MAX_PATTERN_LENGTH = 2_048

# Single-comparison-expression patterns only (no AND/OR/FOLLOWEDBY
# compounds -- those are deliberately left unsupported, see module
# docstring). Anchored to the exact real shapes confirmed above; `re.match`
# with `$`-anchoring (via fullmatch) so a crafted suffix can't smuggle
# extra content past the capture group.
_IPV4_PATTERN = re.compile(r"^\[ipv4-addr:value\s*=\s*'([^']*)'\]$")
_IPV6_PATTERN = re.compile(r"^\[ipv6-addr:value\s*=\s*'([^']*)'\]$")
_DOMAIN_PATTERN = re.compile(r"^\[domain-name:value\s*=\s*'([^']*)'\]$")
# Quoted key form: file:hashes.'SHA-256' = '...' (python-stix2's own
# canonical serialization for a key containing a hyphen).
_SHA256_QUOTED_PATTERN = re.compile(r"^\[file:hashes\.'SHA-256'\s*=\s*'([0-9a-fA-F]{64})'\]$")
# Bare key form: file:hashes.SHA256 = '...' (also seen in the wild without
# the hyphen/quoting).
_SHA256_BARE_PATTERN = re.compile(r"^\[file:hashes\.SHA-?256\s*=\s*'([0-9a-fA-F]{64})'\]$")


def parse_stix21_bundle(raw_bytes: bytes) -> list[IOCIndicator]:
    """Extract every matchable ``IOCIndicator`` from a real STIX 2.1 bundle.

    Raises ``ValidationError`` for structural problems with the bundle
    itself (oversized, not JSON, not a STIX bundle). Individual
    unrecognized/unsupported indicator objects are skipped with a logged
    warning and do not fail the whole ingestion -- see module docstring.
    """
    if len(raw_bytes) > _MAX_BUNDLE_BYTES:
        raise ValidationError(
            "STIX bundle exceeds maximum accepted size",
            context={"size_bytes": len(raw_bytes), "max_bytes": _MAX_BUNDLE_BYTES},
        )

    try:
        bundle = json.loads(raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError("STIX bundle is not valid JSON", context={"error": str(exc)}) from exc

    if not isinstance(bundle, dict):
        raise ValidationError(
            "STIX bundle must be a JSON object", context={"type": type(bundle).__name__}
        )
    if bundle.get("type") != "bundle":
        raise ValidationError(
            'Not a STIX bundle (missing/incorrect top-level "type")',
            context={"type": bundle.get("type")},
        )

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValidationError(
            'STIX bundle "objects" must be an array', context={"type": type(objects).__name__}
        )
    if len(objects) > _MAX_OBJECTS:
        raise ValidationError(
            "STIX bundle exceeds maximum accepted object count",
            context={"object_count": len(objects), "max_objects": _MAX_OBJECTS},
        )

    indicators: list[IOCIndicator] = []
    for obj in objects:
        indicator = _parse_indicator_object(obj)
        if indicator is not None:
            indicators.append(indicator)
    return indicators


def _parse_indicator_object(obj: Any) -> IOCIndicator | None:
    if not isinstance(obj, dict) or obj.get("type") != "indicator":
        return None  # not an indicator SDO (malware/relationship/etc.) -- not this parser's concern

    pattern = obj.get("pattern")
    obj_id = obj.get("id")
    if not isinstance(pattern, str):
        logger.warning("stix_indicator_missing_pattern", extra={"object_id": obj_id})
        return None
    if len(pattern) > _MAX_PATTERN_LENGTH:
        logger.warning(
            "stix_indicator_pattern_too_long",
            extra={"object_id": obj_id, "length": len(pattern)},
        )
        return None

    match = _match_supported_pattern(pattern)
    if match is None:
        logger.warning(
            "stix_indicator_pattern_unsupported",
            extra={"object_id": obj_id, "pattern": pattern[:200]},
        )
        return None
    ioc_type, value = match

    confidence = obj.get("confidence")
    if not isinstance(confidence, int) or not (0 <= confidence <= 100):
        confidence = None

    description = obj.get("description")
    if not isinstance(description, str):
        description = None

    return IOCIndicator(
        ioc_type=ioc_type,
        value=value,
        confidence=confidence,
        description=description,
        source_ref=obj_id if isinstance(obj_id, str) else None,
    )


def _match_supported_pattern(pattern: str) -> tuple[IOCType, str] | None:
    stripped = pattern.strip()
    for regex, ioc_type in (
        (_IPV4_PATTERN, IOCType.IP),
        (_IPV6_PATTERN, IOCType.IP),
        (_DOMAIN_PATTERN, IOCType.DOMAIN),
        (_SHA256_QUOTED_PATTERN, IOCType.FILE_HASH_SHA256),
        (_SHA256_BARE_PATTERN, IOCType.FILE_HASH_SHA256),
    ):
        m = regex.match(stripped)
        if m:
            return ioc_type, m.group(1)
    return None
