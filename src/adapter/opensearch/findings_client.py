"""Read-only client for real OpenSearch Security Analytics findings.

Roadmap M2/C4 (docs/NEXTGEN_SOC_ROADMAP.md). Findings are the raw material
DetectionSyncService (src/application/detection_sync.py) mirrors into
KronOS's own audited Detection entity. This class is deliberately
READ-ONLY -- it never calls a Security Analytics write endpoint -- and
scopes to an org exactly the way SecurityAnalyticsDetectorProvisioner (C2)
scopes detector creation: by the KronOS-computed
``kronos-{org_alias}-{log_type}-detector`` name, never by anything read out
of the finding document itself (roadmap invariant #3 -- tenant isolation is
computed, never supplied). Same admin-only trust tier as detector
provisioning (A3 gate, poc/security_analytics_tenant_isolation/): SA is
never touched with anything but admin credentials, and never exposed
directly to a tenant session.

Real finding document shape (verified against a live OpenSearch 2.11.1
cluster running a real detector over real data -- see
poc/detection_finding_sync/ for the captured run)::

    {
      "_index": ".opensearch-sap-network-findings-2026.07.29-1",
      "_id": "980b4d05-ce45-40eb-b246-f8a0b50bd6cc",
      "_source": {
        "id": "980b4d05-ce45-40eb-b246-f8a0b50bd6cc",   # == _id, also flat
        "related_doc_ids": ["f648d8e8-...-...-...-..."], # matched timeline doc ids
        "monitor_id": "S8yIs58BG52zb-VTinMn",
        "monitor_name": "kronos-kronos-dev-network-detector",
        "index": "kronos-kronos-dev-case-<uuid>-202309",
        "queries": [
          {"id": "1fc0809e-...", "name": "1fc0809e-...",
           "tags": ["high", "network", "attack.t1021.001"]}
        ],
        "timestamp": 1785423677843,
        "execution_id": null
      }
    }

Confirmed via a live ``GET .../.opensearch-sap-network-findings-*/_mapping``:
``id``, ``monitor_id``, ``monitor_name``, and ``index`` are all flat
``keyword`` fields -- safe for exact `terms`/`term` queries. ``queries`` is
``nested`` -- the exact same trap that defeated the detector-provisioner's
naive idempotency check in C2 (a flat query against a nested field silently
matches nothing). This class never filters on ``queries`` (only reads it
out of an already-matched hit's ``_source``), so that trap does not apply
here, but it is worth recording precisely because the roadmap brief for
this item flagged it as a real, precedented risk to re-check rather than
assume away.

Findings also confirmed to live in a **per-log-type** index
(``.opensearch-sap-{log_type}-findings-*``), never a single flat
``.opensearch-sap-findings-*`` -- querying the latter (as an earlier,
unverified check in this session's own history did) silently returns zero
hits even when hundreds of real findings exist. This class queries the
real wildcard ``.opensearch-sap-*-findings-*`` pattern that covers every
log type in one call.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class FindingsClient(ABC):
    """Read-only access to real SA findings, scoped by KronOS's own detector-name convention."""

    @abstractmethod
    async def fetch_org_findings(
        self, org_alias: str, log_types: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        """Return raw finding hits (with `_id`/`_source`) for this org's detectors.

        Strictly read-only. Scoped by `monitor_name` matching
        `kronos-{org_alias}-{log_type}-detector` for each of *log_types* --
        never by anything read out of the finding document itself.
        """


class SecurityAnalyticsFindingsClient(FindingsClient):
    """Real OpenSearch 2.11.1 Security Analytics findings reader."""

    # Covers every per-log-type findings index in one call (see module
    # docstring -- there is no single flat findings index).
    _FINDINGS_INDEX_PATTERN = ".opensearch-sap-*-findings-*"
    # PoC-scale cap; a production-scale sync would need search_after
    # pagination past this, which this v1 does not implement (see
    # poc/detection_finding_sync/README.md "not verified" section).
    _MAX_RESULTS = 1000

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def fetch_org_findings(
        self, org_alias: str, log_types: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        detector_names = [f"kronos-{org_alias}-{log_type}-detector" for log_type in log_types]
        # verify=False: same self-signed internal step-ca cert as
        # SecurityAnalyticsDetectorProvisioner and the main OpenSearchClient
        # (settings.opensearch_url is https://opensearch:9200 even
        # docker-internally).
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            try:
                resp = await client.post(
                    f"{self._base_url}/{self._FINDINGS_INDEX_PATTERN}/_search",
                    auth=self._auth,
                    json={
                        "size": self._MAX_RESULTS,
                        "query": {"terms": {"monitor_name": detector_names}},
                        "sort": [{"timestamp": "asc"}],
                    },
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    # No findings index exists yet for this cluster (e.g. no
                    # detector has ever produced a finding) -- an empty
                    # result, not an error.
                    logger.info(
                        "findings_index_not_found",
                        extra={"org_alias": org_alias},
                    )
                    return []
                raise
        return resp.json().get("hits", {}).get("hits", [])
