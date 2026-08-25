"""Auto-provisions per-org OpenSearch Security Analytics detectors.

Roadmap M2/C2 (docs/NEXTGEN_SOC_ROADMAP.md). Builds directly on C1's
real, verified mechanism (poc/security_analytics_field_mappings/): a real
detector, scoped to an index pattern, using OpenSearch's own prepackaged
Sigma rule set for a log type.

Detectors are cluster-level objects -- they are not automatically created
for a new org. This closes that gap the same way
DashboardsIndexPatternProvisioner (src/adapter/opensearch/dashboards_client.py)
closed the analogous "no saved index pattern exists yet" gap for Dashboards:
idempotent, best-effort, called from the route layer at a natural trigger
point, never blocking the primary action on an SA outage.

Binding condition (A3 gate, poc/security_analytics_tenant_isolation/): every
call here uses admin credentials. This class is never constructed with, or
exposed to, a tenant-scoped session -- detectors/findings are surfaced to
tenants exclusively through KronOS's own audited Detection entity (C4),
never directly.

Scope, PER ORG not per case: a detector's index pattern here is
``kronos-{org_alias}-*`` -- covering every case-scoped AND stream-scoped
(roadmap B2) index for that org, in one detector per log type. This is
deliberately not per-case: a case can accumulate evidence of multiple log
types over its lifetime, evidence and log types aren't known in advance at
case-creation time, and a per-case detector set would multiply
unboundedly with the number of cases an org has -- an org realistically
has a small, stable set of relevant log types, so per-org is the scoping
that actually matches how detectors behave (cluster-level, coarse-grained
objects), not the finer-grained, high-cardinality unit (case) they were
never designed for.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)

# Confirmed via poc/security_analytics_field_mappings/ (C1): these three log
# types have real, working field mappings and produced real findings against
# real KronOS-parsed evidence. apache_access/others_web needed zero mapping
# (NginxParser output already matches ECS naming) but was not itself
# detector-tested; linux/plaso not tested at all yet. Extending this list is
# registration, not a code change to this class -- see get_default_log_types().
_VERIFIED_LOG_TYPES: tuple[str, ...] = ("windows", "cloudtrail", "network")


def get_default_log_types() -> tuple[str, ...]:
    """The log types this deployment provisions detectors for.

    A plain tuple, not a class, deliberately: there is no per-log-type
    *behavior* to abstract yet (every log type is provisioned identically
    -- fetch its prepackaged rules, create one detector). If a future log
    type needs different treatment (e.g. a curated rule subset instead of
    "all prepackaged rules"), that is the point to introduce a real
    LogTypeSpec type; inventing one now with a single field would be the
    premature abstraction CLAUDE.md warns against.
    """
    return _VERIFIED_LOG_TYPES


class DetectorProvisioner(ABC):
    """Ensures the right detection-rule detectors exist for an org."""

    @abstractmethod
    async def ensure_org_detectors(self, org_alias: str) -> None:
        """Idempotently create any missing detectors for this org."""


class SecurityAnalyticsDetectorProvisioner(DetectorProvisioner):
    """Real OpenSearch 2.11.1 Security Analytics implementation.

    Idempotency strategy: check-then-create-if-absent, not create-or-update.
    A real PUT-to-existing-detector-id update was tested against the live
    2.11.1 cluster with an empty ``triggers: []`` list (the same shape the
    initial CREATE call accepts) and returned a real 500
    ("kotlin.collections.EmptyMap cannot be cast to kotlin.collections.MutableMap")
    -- a genuine OpenSearch Security Analytics defect on the update path,
    not a KronOS bug. Rather than work around an undocumented internal cast
    bug, this provisioner only ever creates a detector that doesn't already
    exist by name; it never attempts to update one in place. "Ensure exists"
    is the contract, not "ensure exists and current" -- if a detector's rule
    set needs to change later, that is real, separate mutation-of-existing-
    detectors scope (tracked as follow-up, not silently attempted here).
    """

    def __init__(
        self,
        base_url: str,
        admin_username: str,
        admin_password: str,
        log_types: tuple[str, ...] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)
        self._log_types = log_types or get_default_log_types()

    async def ensure_org_detectors(self, org_alias: str) -> None:
        """Idempotently create one detector per configured log type for this org.

        Best-effort per log type: one log type's real API failure (e.g. an
        SA outage, or -- as observed for real against this exact API -- a
        request shape rejected for a reason worth knowing about) is logged
        and does not prevent provisioning the remaining log types, nor does
        it propagate to the caller (matching DashboardsIndexPatternProvisioner's
        established "must not block the primary action" contract).
        """
        # verify=False: same self-signed internal cert as the main
        # OpenSearchClient (verify_certs=False in src/external/startup.py) --
        # settings.opensearch_url is https://opensearch:9200 even on the
        # internal docker network (TLS 1.3 internally per CLAUDE.md), using
        # the dev step-ca chain that httpx has no reason to trust here.
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            for log_type in self._log_types:
                try:
                    await self._ensure_detector(client, org_alias, log_type)
                except httpx.HTTPError as exc:
                    logger.warning(
                        "detector_provisioning_failed",
                        extra={"org_alias": org_alias, "log_type": log_type, "error": str(exc)},
                    )

    def _detector_name(self, org_alias: str, log_type: str) -> str:
        return f"kronos-{org_alias}-{log_type}-detector"

    async def _ensure_detector(
        self, client: httpx.AsyncClient, org_alias: str, log_type: str
    ) -> None:
        name = self._detector_name(org_alias, log_type)

        # Idempotency check: does a detector with this exact name already
        # exist? Confirmed via a real GET
        # .../.opensearch-sap-detectors-config/_mapping: "detector" is a
        # `nested` object, so `name` is `detector.name` (text+keyword), not
        # a top-level field. A flat term query on "name.keyword" is not an
        # error -- OpenSearch just silently matches zero documents against a
        # nested field queried without a `nested` wrapper -- which is
        # exactly the bug a real run of this PoC caught: it made every
        # existence check report "not found" even for a detector created
        # moments earlier, defeating the idempotency this method exists for.
        search_resp = await client.post(
            f"{self._base_url}/_plugins/_security_analytics/detectors/_search",
            auth=self._auth,
            json={
                "size": 1,
                "query": {
                    "nested": {
                        "path": "detector",
                        "query": {"term": {"detector.name.keyword": name}},
                    }
                },
            },
        )
        search_resp.raise_for_status()
        if search_resp.json().get("hits", {}).get("total", {}).get("value", 0) > 0:
            logger.info(
                "detector_already_exists",
                extra={"org_alias": org_alias, "log_type": log_type, "detector_name": name},
            )
            return

        rule_ids = await self._fetch_prepackaged_rule_ids(client, log_type)
        if not rule_ids:
            logger.warning(
                "detector_provisioning_no_rules",
                extra={"org_alias": org_alias, "log_type": log_type},
            )
            return

        body = {
            "name": name,
            "detector_type": log_type,
            "enabled": True,
            "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
            "inputs": [
                {
                    "detector_input": {
                        "description": (
                            f"KronOS auto-provisioned detector for org {org_alias}, "
                            f"log type {log_type}"
                        ),
                        "indices": [f"kronos-{org_alias}-*"],
                        "pre_packaged_rules": [{"id": rid} for rid in rule_ids],
                        "custom_rules": [],
                    }
                }
            ],
            "triggers": [],
        }
        create_resp = await client.post(
            f"{self._base_url}/_plugins/_security_analytics/detectors",
            auth=self._auth,
            json=body,
        )
        create_resp.raise_for_status()
        logger.info(
            "detector_provisioned",
            extra={
                "org_alias": org_alias,
                "log_type": log_type,
                "detector_name": name,
                "rule_count": len(rule_ids),
            },
        )

    async def _fetch_prepackaged_rule_ids(
        self, client: httpx.AsyncClient, log_type: str
    ) -> list[str]:
        """All real prepackaged rule ids for this log type -- not a hand-picked
        subset, matching C1's own methodology."""
        resp = await client.post(
            f"{self._base_url}/_plugins/_security_analytics/rules/_search",
            auth=self._auth,
            params={"pre_packaged": "true"},
            json={
                "size": 10000,
                "query": {
                    "nested": {"path": "rule", "query": {"match": {"rule.category": log_type}}}
                },
            },
        )
        resp.raise_for_status()
        return [hit["_id"] for hit in resp.json().get("hits", {}).get("hits", [])]
