"""RuleCatalogClient: read-only lookup of real prepackaged Sigma rule ids
per log type, from OpenSearch Security Analytics (roadmap M8/I2).

A small, standalone sibling of ``SecurityAnalyticsDetectorProvisioner``
(``src/adapter/opensearch/detector_provisioner.py``) -- deliberately NOT
folded into that class, since this is a pure read (no detector
create/idempotency concerns) needed by a different caller
(``RuleCoverageCalculator``) with a different lifecycle. Reuses the exact
same real, verified query shape
(``_fetch_prepackaged_rule_ids``/``poc/security_analytics_field_mappings/``):
``POST _plugins/_security_analytics/rules/_search?pre_packaged=true`` with
a ``nested`` query on ``rule.category`` -- confirmed against the live,
pinned OpenSearch 2.11.1 cluster while building this module (see
``poc/metrics_kpis/output.txt``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx


class RuleCatalogClient(ABC):
    """Read-only source of "how many real prepackaged rules exist for a log type"."""

    @abstractmethod
    async def count_prepackaged_rules(self, log_type: str) -> int:
        """Real prepackaged Sigma rule count for *log_type*, right now."""


class SecurityAnalyticsRuleCatalog(RuleCatalogClient):
    """Real OpenSearch 2.11.1 Security Analytics implementation.

    Binding condition (A3 gate, ``poc/security_analytics_tenant_isolation/``):
    admin credentials only, mirroring every other Security Analytics client
    in this codebase (``FindingsClient``, ``DetectorProvisioner``, ...) --
    the prepackaged rule catalogue is a cluster-level object with no
    per-tenant scoping of its own.
    """

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def count_prepackaged_rules(self, log_type: str) -> int:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(
                f"{self._base_url}/_plugins/_security_analytics/rules/_search",
                auth=self._auth,
                params={"pre_packaged": "true"},
                json={
                    "size": 0,
                    "query": {
                        "nested": {
                            "path": "rule",
                            "query": {"match": {"rule.category": log_type}},
                        }
                    },
                },
            )
            resp.raise_for_status()
            return int(resp.json().get("hits", {}).get("total", {}).get("value", 0))
