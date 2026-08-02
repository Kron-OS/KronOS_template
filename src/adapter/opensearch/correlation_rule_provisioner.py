"""Provisions per-org OpenSearch Security Analytics correlation rules.

Roadmap M2/F3 (docs/NEXTGEN_SOC_ROADMAP.md). Builds on the real, verified
mechanism in poc/security_analytics_correlation/: a real correlation rule
joining two (or more) log-type categories via a declarative
index/query/category triple per category, evaluated by SA's own real-time
correlation engine.

Tenant scoping (roadmap invariant #3): a correlation rule has no dedicated
org/tenant field at all (confirmed from the real 2.11 source --
CorrelationRule.java/CorrelationQuery.java) -- `index` is exactly as
free-form as a Detector's own `indices` list. This class computes
`kronos-{org_alias}-*` for EVERY category entry itself, from the caller's
own org_alias, never from anything scenario-content-supplied -- mirroring
SecurityAnalyticsDetectorProvisioner (C2)'s identical contract for
detectors. Content curation (which specific category/query pairs are worth
shipping as a named attack-chain scenario) is explicitly out of scope for
this class and this pass -- see poc/security_analytics_correlation/README.md
"Not built this pass". Callers supply the scenario name and category/query
pairs; this class only ever adds the tenant-scoped index.

Idempotency strategy: check-then-create-or-UPDATE (via a real PUT), unlike
SecurityAnalyticsDetectorProvisioner (C2) and
SecurityAnalyticsCustomRuleDetectorProvisioner (C3), which both had to adopt
a never-update, delete-and-recreate strategy specifically because a real
2.11.1 detector PUT-update defect made in-place updates unsafe. A real
PUT-update was tried against a real correlation rule on this same pinned
cluster (poc/security_analytics_correlation/README.md "Real bug/gap found")
and worked cleanly -- confirmed by a real read-back showing the updated
`name`/`correlate` and an incremented `_version`. Correlation rules do not
share the detector's defect, so this class is free to use the simpler,
safer PUT-update contract SA's REST API actually offers.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CorrelationCategoryQuery:
    """One category/query leg of a correlation scenario -- the tenant-scoped
    `index` is computed by the provisioner, never supplied here."""

    category: str
    query: str


class CorrelationRuleProvisioner(ABC):
    """Ensures a named, per-org correlation scenario rule exists and is current."""

    @abstractmethod
    async def ensure_org_rule(
        self, org_alias: str, scenario_name: str, legs: tuple[CorrelationCategoryQuery, ...]
    ) -> None:
        """Idempotently create or update the (org_alias, scenario_name)
        correlation rule so its `correlate` array matches *legs* exactly,
        each scoped to this org's own `kronos-{org_alias}-*` index pattern."""


class SecurityAnalyticsCorrelationRuleProvisioner(CorrelationRuleProvisioner):
    """Real OpenSearch 2.11.1 Security Analytics implementation."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    def _rule_name(self, org_alias: str, scenario_name: str) -> str:
        # Real name-validation regex confirmed from source:
        # [a-zA-Z0-9 _,-.]{5,50} (IndexCorrelationRuleRequest.IS_VALID_RULE_NAME).
        return f"kronos-{org_alias}-{scenario_name}"[:50]

    async def ensure_org_rule(
        self, org_alias: str, scenario_name: str, legs: tuple[CorrelationCategoryQuery, ...]
    ) -> None:
        name = self._rule_name(org_alias, scenario_name)
        index_pattern = f"kronos-{org_alias}-*"
        body = {
            "name": name,
            "correlate": [
                {"index": index_pattern, "query": leg.query, "category": leg.category}
                for leg in legs
            ],
        }
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            existing = await self._find(client, name)
            if existing is not None and existing["_source"] == body:
                logger.info(
                    "correlation_rule_already_current",
                    extra={"org_alias": org_alias, "scenario_name": scenario_name},
                )
                return
            if existing is not None:
                resp = await client.put(
                    f"{self._base_url}/_plugins/_security_analytics/correlation/rules/{existing['_id']}",
                    auth=self._auth,
                    json=body,
                )
            else:
                resp = await client.post(
                    f"{self._base_url}/_plugins/_security_analytics/correlation/rules",
                    auth=self._auth,
                    json=body,
                )
            resp.raise_for_status()
            logger.info(
                "correlation_rule_provisioned",
                extra={
                    "org_alias": org_alias,
                    "scenario_name": scenario_name,
                    "updated": existing is not None,
                    "leg_count": len(legs),
                },
            )

    async def _find(self, client: httpx.AsyncClient, name: str) -> dict[str, Any] | None:
        # `correlate` is a NESTED field but this searches on the flat, real
        # top-level `name` field -- confirmed real and flat (unlike
        # `correlate`) by the real IT test's own testUpdateCorrelationRule,
        # which reads `rule.name` straight off the create/update response.
        resp = await client.post(
            f"{self._base_url}/_plugins/_security_analytics/correlation/rules/_search",
            auth=self._auth,
            json={"size": 1, "query": {"term": {"name.keyword": name}}},
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return hits[0] if hits else None
