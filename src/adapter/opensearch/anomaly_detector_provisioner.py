"""Auto-provisions one per-org OpenSearch Anomaly Detection (AD/RCF)
detector for behavioral triage-prioritization signals (roadmap M6/G2).

Mirrors ``SecurityAnalyticsDetectorProvisioner``
(``src/adapter/opensearch/detector_provisioner.py``, C2)'s own per-org
scoping contract exactly: **the tenant boundary is this detector's own
``indices: ["kronos-{org_alias}-*"]``, computed here from the caller's own
``org_alias``, never anything read out of the detector's own
``category_field``/``entity`` values** (roadmap invariant #3;
``poc/anomaly_detection_baseline/README.md``'s own "Design decision: per-org
scoping is INDEX PATTERN" explains why ``category_field`` -- which this v1
deliberately does NOT use -- is an orthogonal, intra-org entity-slicing
mechanism, not a tenant boundary, and why per-org (not per-entity, not
cluster-wide-with-category_field) is the right granularity here for the
same reason C2 already established for Security Analytics detectors:
detectors are real, name-unique, cluster-level objects with a real
per-detector resource cost, and an org is the natural coarse-grained unit
they were designed for).

**Feature choice: event-volume anomaly (``value_count`` on ``@timestamp``),
not a format-specific numeric field.** Every ``kronos-*`` document has a
mapped ``@timestamp`` (``index_template.json``); a format-specific field
(source.bytes, process counts, ...) would only be aggregatable for SOME
log types and would silently fail detector-CREATE's own real validation
query for others (the exact real gap
``poc/anomaly_detection_baseline/README.md``'s "Finding 3" hit and fixed
for the PoC's own throwaway corpus). A generic per-interval event-count
feature is the one signal every org's detector can legitimately compute
regardless of which parsers fed it, and is itself a real, standard
UEBA/volume-anomaly signal (a sudden spike or drop in event rate is
exactly the kind of "hunting lead" this item exists to surface).

**Real, confirmed constraint: a detector cannot be created until the
org's own index pattern matches at least one REAL index with a mapped
time field** (``poc/anomaly_detection_baseline/README.md``'s idempotency
probe hit this live: ``"Timestamp field: (@timestamp) is not found in
index mapping"``, real HTTP 500, for an org with zero ingested indices
yet). ``ensure_org_detector`` treats this, and the sibling "empty
aggregated data" validation error, as "not ready yet" -- returns ``None``,
logs, and does NOT raise, mirroring ``DashboardsIndexPatternProvisioner``/
``SecurityAnalyticsDetectorProvisioner``'s own "never block the primary
action" contract. Any other real HTTP error is a genuine, unexpected
failure and propagates.

**Idempotency strategy: check-then-create, no update-in-place attempted --
a real, deliberate v1 scope decision, not because AD shares
SecurityAnalyticsDetectorProvisioner's own PUT-update defect (it does
NOT -- see below).** This detector's body is invariant (one fixed feature,
no per-org customization exists yet), so there is nothing to keep
"current" the way ``SecurityAnalyticsCorrelationRuleProvisioner``'s own
scenario content can legitimately change between calls -- adding
update-in-place now would be speculative scope with no real caller driving
it (YAGNI). This is independently, freshly confirmed for THIS plugin, not
assumed from either precedent (``poc/anomaly_detection_baseline/README.md``
"Finding 5"): a real duplicate-name CREATE is rejected server-side with
HTTP 500 and an explicit "already used by detector" message (AD enforces
detector-name uniqueness, unlike SA's own detector API), and a real
PUT-to-existing-id update returns a clean HTTP 200 with an incremented
``_version`` (AD does NOT share SA's documented 2.11.1 detector-PUT 500
defect) -- confirming neither prior precedent could have been safely
assumed to carry over to this different plugin without testing it for
real.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)

# Real, confirmed-live substrings of AD's own "not ready yet" validation
# errors (poc/anomaly_detection_baseline/README.md "Finding 3"/"Finding 4"
# and the idempotency probe's own timestamp-mapping gap) -- distinguished
# from any other, genuinely unexpected 500 so only these are swallowed as
# "org has no ingested data yet", never a real bug.
_NOT_READY_ERROR_MARKERS: tuple[str, ...] = (
    "returning empty aggregated data",
    "is not found in index mapping",
)


class AnomalyDetectorProvisioner(ABC):
    """Ensures the per-org behavioral AD detector exists."""

    @staticmethod
    def detector_name(org_alias: str) -> str:
        """The one, fixed per-org detector name -- shared, pure, no I/O, so
        callers (``BehavioralAnomalyScorer``) can label a signal without a
        second round-trip just to learn the name they already know."""
        safe_org = re.sub(r"[^a-z0-9-]", "-", org_alias.lower())
        return f"kronos-{safe_org}-behavioral-ad-detector"

    @abstractmethod
    async def ensure_org_detector(self, org_alias: str) -> str | None:
        """Idempotently create the org's detector if missing; return its
        real detector_id, or None if the org isn't ready yet (no ingested
        indices/time field mapping to validate against)."""


class OpenSearchAnomalyDetectorProvisioner(AnomalyDetectorProvisioner):
    """Real OpenSearch 2.11.1 Anomaly Detection implementation."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def ensure_org_detector(self, org_alias: str) -> str | None:
        name = self.detector_name(org_alias)
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            existing_id = await self._find(client, name)
            if existing_id is not None:
                logger.info(
                    "anomaly_detector_already_exists",
                    extra={
                        "org_alias": org_alias,
                        "detector_name": name,
                        "detector_id": existing_id,
                    },
                )
                return existing_id

            body = {
                "name": name,
                "description": f"KronOS auto-provisioned behavioral detector for org {org_alias}",
                "time_field": "@timestamp",
                "indices": [f"kronos-{org_alias}-*"],
                "feature_attributes": [
                    {
                        "feature_name": "event_volume",
                        "feature_enabled": True,
                        "aggregation_query": {
                            "event_volume": {"value_count": {"field": "@timestamp"}}
                        },
                    }
                ],
                "detection_interval": {"period": {"interval": 10, "unit": "MINUTES"}},
                "window_delay": {"period": {"interval": 1, "unit": "MINUTES"}},
            }
            try:
                create_resp = await client.post(
                    f"{self._base_url}/_plugins/_anomaly_detection/detectors",
                    auth=self._auth,
                    json=body,
                )
                create_resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                error_text = exc.response.text
                if exc.response.status_code == 500 and any(
                    marker in error_text for marker in _NOT_READY_ERROR_MARKERS
                ):
                    logger.info(
                        "anomaly_detector_org_not_ready",
                        extra={"org_alias": org_alias, "detector_name": name, "error": error_text},
                    )
                    return None
                # A concurrent caller may have created it between our
                # _find() and this create() -- AD's own real, server-side
                # unique-name enforcement (README.md "Finding 5") is the
                # backstop; treat that specific race honestly as success,
                # not a failure.
                if exc.response.status_code == 500 and "already used by detector" in error_text:
                    raced_id = await self._find(client, name)
                    if raced_id is not None:
                        logger.info(
                            "anomaly_detector_created_concurrently",
                            extra={
                                "org_alias": org_alias,
                                "detector_name": name,
                                "detector_id": raced_id,
                            },
                        )
                        return raced_id
                logger.error(
                    "anomaly_detector_provisioning_failed",
                    extra={"org_alias": org_alias, "detector_name": name, "error": error_text},
                )
                raise

            detector_id: str = create_resp.json()["_id"]
            logger.info(
                "anomaly_detector_provisioned",
                extra={"org_alias": org_alias, "detector_name": name, "detector_id": detector_id},
            )
            return detector_id

    async def _find(self, client: httpx.AsyncClient, name: str) -> str | None:
        # Real, confirmed-live: `name` is a FLAT top-level field on the
        # detector document (unlike SA's own nested `detector.name`) --
        # poc/anomaly_detection_baseline/README.md's real name-search probe.
        resp = await client.post(
            f"{self._base_url}/_plugins/_anomaly_detection/detectors/_search",
            auth=self._auth,
            json={"size": 1, "query": {"term": {"name.keyword": name}}},
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return hits[0]["_id"] if hits else None
