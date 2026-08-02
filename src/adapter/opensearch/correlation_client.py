"""Read-only client for real OpenSearch Security Analytics correlation matches.

Roadmap M2/F3 (docs/NEXTGEN_SOC_ROADMAP.md). Evaluated SA's native
correlation engine before building a bespoke entity graph -- confirmed real
and live on the pinned OpenSearch 2.11.1 cluster (see
poc/security_analytics_correlation/, 20/20 checks passed against a real
cross-log-type match). This class is deliberately READ-ONLY, mirroring
FindingsClient (src/adapter/opensearch/findings_client.py) exactly, and is
subject to the SAME A3 binding conditions: admin credentials only, never
exposed to a tenant session.

Real, confirmed API shape (poc/security_analytics_correlation/README.md,
read from the actual 2.11 branch source, not "latest" docs which may
describe a newer syntax)::

    GET /_plugins/_security_analytics/correlations?start_timestamp=<ms>&end_timestamp=<ms>
    -> {"findings": [
          {"finding1": "<id>", "logType1": "windows", "finding2": "<id>",
           "logType2": "network", "rules": ["<correlation_rule_id>", ...]},
          ...
       ]}

**Real, load-bearing tenant-isolation fact**: this endpoint takes ONLY a
time window -- no index/org/detector filter parameter exists at all. It is
genuinely cluster-wide, unlike `findings/_search` which FindingsClient scopes
by `monitor_name`. CorrelationSyncService (src/application/correlation_sync.py)
is therefore the ONLY place tenant isolation is enforced for correlation
data: it discards every pair unless BOTH finding ids already have a
synced Detection row for the calling org (never trusting anything read out
of this response as an org signal -- roadmap invariant #3).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class CorrelationClient(ABC):
    """Read-only access to real SA correlation matches within a time window."""

    @abstractmethod
    async def fetch_correlations(self, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
        """Return raw correlation pairs reported by SA for [start_ms, end_ms).

        Cluster-wide by construction (the real API has no narrower scope --
        see module docstring). Callers MUST filter by tenant ownership
        themselves; this class performs no org filtering of any kind.
        """


class SecurityAnalyticsCorrelationClient(CorrelationClient):
    """Real OpenSearch 2.11.1 Security Analytics correlation-match reader."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def fetch_correlations(self, start_ms: int, end_ms: int) -> list[dict[str, Any]]:
        # verify=False: same self-signed internal step-ca cert as every
        # other SA adapter in this repo (settings.opensearch_url is
        # https://opensearch:9200 even docker-internally).
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.get(
                f"{self._base_url}/_plugins/_security_analytics/correlations",
                auth=self._auth,
                params={"start_timestamp": start_ms, "end_timestamp": end_ms},
            )
            resp.raise_for_status()
        findings: list[dict[str, Any]] = resp.json().get("findings", [])
        logger.info(
            "correlations_fetched",
            extra={"start_ms": start_ms, "end_ms": end_ms, "pair_count": len(findings)},
        )
        return findings
