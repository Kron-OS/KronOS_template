"""IOCFeedIngestionService: orchestrates parsing an untrusted feed payload
into a new, append-only ``IOCFeedVersion`` (roadmap M5/F2).

Deliberately thin -- mirrors ``RulePackService``'s own "parse, version,
persist" shape (``src/application/rule_pack_service.py``) minus the cost
gate (an IOC value has no analogous "expensive query" risk the way a Sigma
rule does; the risk here is untrusted-content parsing, already fully
contained in ``stix_ioc_parser.py``). Only STIX 2.1 is wired this pass --
MISP-JSON/TAXII-poll ingestion are real, legitimate follow-ups (see this
item's roadmap STATUS note), added as new ``ingest_*`` methods on this same
class when built, not a parallel abstraction.
"""

from __future__ import annotations

import logging
import uuid

from src.adapter.repository.ioc_feed import IOCFeedRepository
from src.application.stix_ioc_parser import parse_stix21_bundle
from src.domain.ioc_feed import IOCFeedVersion

logger = logging.getLogger(__name__)


class IOCFeedIngestionService:
    """Ingests a real threat-intel feed payload into a versioned, org-scoped feed."""

    def __init__(self, repository: IOCFeedRepository) -> None:
        self._repository = repository

    async def ingest_stix_bundle(
        self, org_id: uuid.UUID, feed_name: str, raw_bundle: bytes
    ) -> IOCFeedVersion:
        """Parse *raw_bundle* as a STIX 2.1 bundle and persist it as the next
        version of the (org_id, feed_name) feed.

        Raises ``ValidationError`` (propagated from ``parse_stix21_bundle``)
        if the bundle itself is structurally invalid -- a malformed feed
        never creates a new version, honest all-or-nothing ingestion.
        """
        indicators = parse_stix21_bundle(raw_bundle)

        feed = await self._repository.get_or_create_feed(org_id, feed_name)
        latest = await self._repository.get_latest_version(feed.feed_id)
        next_version = 1 if latest is None else latest.version + 1

        version = IOCFeedVersion(
            feed_id=feed.feed_id,
            version=next_version,
            org_id=org_id,
            source_format="stix2.1",
            indicators=tuple(indicators),
        )
        saved = await self._repository.save_version(version)
        logger.info(
            "ioc_feed_ingested",
            extra={
                "org_id": str(org_id),
                "feed_name": feed_name,
                "version": saved.version,
                "indicator_count": len(saved.indicators),
            },
        )
        return saved
