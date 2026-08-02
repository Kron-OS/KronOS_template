"""IOC feed lifecycle domain model: versioned, tenant-scoped threat-intel
indicators (roadmap M5/F2).

**Why KronOS-native, not OpenSearch Security Analytics' own threat-intel
feature.** SA's threat-intel REST namespace (source configs, monitors) was
verified NOT to exist on either OpenSearch version this repo pins:

- ``docker/docker-compose.dev.yml`` pins 2.11.1 (the real, live dev
  cluster) -- a real ``curl`` against the running container returned
  ``{"error":"no handler found for uri
  [/_plugins/_security_analytics/threat_intel/sources] and method [GET]"}``
  (HTTP 400) -- i.e. the REST action is not registered in this build at
  all, not merely empty.
- Checked against the real upstream project (opensearch-project/
  security-analytics GitHub, PR history): threat-intel work was originally
  targeted at 2.11 but reverted before release (PR #717, "Revert Threat
  Intel Changes for 2.11", merged into the ``2.11`` base branch on
  2023-11-08 -- before OpenSearch 2.11.1's own 2023-11-29 build). Real
  feature work (source-config CRUD, monitors, REST APIs) only resumed
  May-June 2024; the earliest release backports found for it start at
  2.15. ``docker-compose.test.yml``/``docker-compose.prod.yml`` pin 2.13.0
  -- still before the feature existed.

So neither pinned version has this feature, full stop -- not a maturity or
fit judgment call, a version-gap fact. See ``poc/threat_intel_sa_native/``
for the full captured evidence. This module is the KronOS-native fallback
the roadmap's own F2 entry anticipates ("using SA's own threat-intel
feature *where it fits*").

**Shape mirrors ``RulePack``/``RulePackVersion`` exactly**
(``src/domain/rule_pack.py``) -- the same real, load-bearing invariants
apply unchanged:

1. Append-only versioning: an ``IOCFeedVersion`` is never updated or
   deleted once persisted (``IOCFeedRepository.save_version``'s contract)
   -- re-ingesting a feed creates version N+1, never mutates version N
   (replayability).
2. Tenant scoping is always computed from the authenticated
   ``TenantContext``, never taken from feed content -- a STIX bundle has
   no notion of a KronOS org, so there is nothing in the untrusted input
   that could ever assign an indicator to the wrong tenant.

Zero framework imports (CLAUDE.md SS A.3) -- pure Pydantic.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    """The indicator kinds KronOS can actually match against.

    Deliberately limited to fields real parsers already emit today (see
    ``src/application/ioc_enrichment.py``'s module docstring for the exact
    field survey) -- not the full STIX cyber-observable catalogue. A STIX
    pattern for an observable KronOS has no matching field for (e.g. a
    registry key, a mutex name) is honestly skipped at parse time
    (``src/application/stix_ioc_parser.py``), never coerced into one of
    these three.
    """

    IP = "ip"
    DOMAIN = "domain"
    FILE_HASH_SHA256 = "sha256"


class IOCIndicator(BaseModel):
    """One indicator of compromise extracted from an ingested feed.

    ``value`` is stored exactly as extracted (original case) so it can be
    displayed faithfully; matching always goes through ``normalize()``
    below so a feed's ``EVIL.COM`` and a parsed record's ``evil.com`` still
    match. ``confidence``/``description`` are optional real STIX indicator
    fields (0-100 STIX confidence scale) -- ``None`` is an honest "the feed
    didn't say", never a fabricated default.
    """

    model_config = {"frozen": True}

    indicator_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ioc_type: IOCType
    value: str
    confidence: int | None = Field(default=None, ge=0, le=100)
    description: str | None = None
    # The feed's own object identifier (e.g. STIX "indicator--<uuid>") --
    # kept for audit traceability back to the exact upstream object a match
    # came from, never used for anything KronOS itself keys on.
    source_ref: str | None = None

    @staticmethod
    def normalize(ioc_type: IOCType, value: str) -> str:
        """Canonical comparison form for a value of this type.

        Lower-cased for domain/hash (case-insensitive by convention; a
        SHA-256 hex digest and a DNS name are never case-significant in
        practice) and stripped of incidental whitespace. IPs are also
        lower-cased (harmless for IPv4, normalizes IPv6 hex case) rather
        than parsed/validated here -- validation happens once, at parse
        time (``stix_ioc_parser.py``), not on every match lookup.
        """
        return value.strip().lower()


class IOCFeedVersion(BaseModel):
    """One immutable, append-only version of a feed's full indicator set.

    ``org_id`` is always the ingesting tenant's own ``TenantContext`` value
    -- never anything read out of feed content (see this module's
    docstring, invariant 2).
    """

    model_config = {"frozen": True}

    feed_id: uuid.UUID
    version: int
    org_id: uuid.UUID
    source_format: str = Field(description='e.g. "stix2.1" -- the ingestion path used')
    indicators: tuple[IOCIndicator, ...] = Field(default_factory=tuple)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IOCFeed(BaseModel):
    """A named feed identity; ``IOCFeedVersion`` rows carry the actual content.

    Unique per ``(org_id, name)`` -- enforced by ``IOCFeedRepository``, not
    by this model (domain layer has no persistence concerns).
    """

    model_config = {"frozen": True}

    feed_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    org_id: uuid.UUID
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IOCMatch(BaseModel):
    """The result of a real indicator match against an org's current feeds."""

    model_config = {"frozen": True}

    feed_name: str
    indicator: IOCIndicator
