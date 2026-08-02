"""IOCMatchEnricher: the concrete threat-intel Enricher (roadmap M5/F2).

Looks up whatever indicator-shaped fields a ``TimelineRecord`` actually
carries today against a real, org-scoped ``IOCFeedRepository``, and
attaches a match's own feed/confidence/description as derived,
``enrichment.ioc.*``-namespaced fields. See ``src/application/
enrichment.py``'s own module docstring for the full design rationale (why
``extra[]``, why computed once at ingest) -- this class adds nothing new
to that design, it is F1's second concrete enricher.

**Which fields are actually checked, and why** -- surveyed from every one
of today's six parsers (``src/external/parsers/*.py``) rather than
invented: ``source.ip``/``destination.ip`` (``cloudtrail.py``,
``nginx.py``, ``suricata.py``), ``url.domain``
(``chrome_history.py``) -- both real ``extra`` dotted keys already
produced. ``record.kronos.sha256`` (``EvidenceProvenance``, the *evidence
file's own* hash -- every one of the six file-based parsers sets this) is
also checked: "this uploaded evidence file's own hash matches a known-bad
file hash IOC" is a real, useful correlation, not a fabricated field.
``StreamProvenance`` records (no owning evidence file) simply have no
``sha256`` attribute -- ``getattr(..., None)`` handles that as an honest
"nothing to check", not an error.

**Priority when multiple fields would match** -- an ``Enricher`` returns
one namespaced result per record (see ``EnrichmentPipeline``'s own
contract), so when more than one field matches, the single MOST SPECIFIC
match is reported: file hash (an exact artifact match) before IP before
domain (domain names are the least specific/most reusable indicator of
the three). This is a real, documented tradeoff, not an oversight -- a
future iteration that needs to surface every match, not just the
strongest one, is legitimate follow-up scope (see this item's roadmap
STATUS note), not a change to make speculatively here.
"""

from __future__ import annotations

import uuid
from typing import Any

from src.adapter.repository.ioc_feed import IOCFeedRepository
from src.application.enrichment import Enricher
from src.domain.ioc_feed import IOCType
from src.domain.timeline import TimelineRecord


class IOCMatchEnricher(Enricher):
    """Enriches a record whose IP/domain/file-hash matches a real, org-owned IOC."""

    def __init__(self, repository: IOCFeedRepository) -> None:
        self._repo = repository

    @property
    def source_name(self) -> str:
        return "ioc"

    async def enrich(self, record: TimelineRecord, org_id: uuid.UUID) -> dict[str, Any] | None:
        for ioc_type, value in self._candidates(record):
            match = await self._repo.match_indicator(org_id, ioc_type, value)
            if match is None:
                continue

            result: dict[str, Any] = {
                "enrichment.ioc.matched": True,
                "enrichment.ioc.ioc_type": match.indicator.ioc_type.value,
                "enrichment.ioc.value": match.indicator.value,
                "enrichment.ioc.feed_name": match.feed_name,
            }
            if match.indicator.confidence is not None:
                result["enrichment.ioc.confidence"] = match.indicator.confidence
            if match.indicator.description:
                result["enrichment.ioc.description"] = match.indicator.description
            if match.indicator.source_ref:
                result["enrichment.ioc.source_ref"] = match.indicator.source_ref
            return result
        return None

    @staticmethod
    def _candidates(record: TimelineRecord) -> list[tuple[IOCType, str]]:
        """Every real, currently-matchable field on *record*, most specific first."""
        candidates: list[tuple[IOCType, str]] = []

        sha256 = getattr(record.kronos, "sha256", None)
        if sha256:
            candidates.append((IOCType.FILE_HASH_SHA256, sha256))

        source_ip = record.extra.get("source.ip")
        if isinstance(source_ip, str) and source_ip:
            candidates.append((IOCType.IP, source_ip))

        dest_ip = record.extra.get("destination.ip")
        if isinstance(dest_ip, str) and dest_ip:
            candidates.append((IOCType.IP, dest_ip))

        domain = record.extra.get("url.domain")
        if isinstance(domain, str) and domain:
            candidates.append((IOCType.DOMAIN, domain))

        return candidates
