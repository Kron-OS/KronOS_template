"""Real OpenSearch 2.11.1 Security Analytics custom-rule REST client.

Roadmap M2/C3 (docs/NEXTGEN_SOC_ROADMAP.md). Confirmed empirically
(poc/rule_pack_lifecycle/, direct curl trials against the live cluster
before writing this class) against the pinned OpenSearch 2.11.1 Security
Analytics plugin:

- `POST _plugins/_security_analytics/rules?category={log_type}` takes the
  RAW Sigma YAML text as its request body -- not JSON -- with
  `Content-Type: application/json` still required (`text/plain` is
  rejected with a real 406). Passing a JSON object instead of YAML text
  raises a real 500 `ClassCastException`
  ("class java.lang.String cannot be cast to class java.util.Map"); a
  syntactically valid Sigma YAML document missing its own `date:` field
  raises a real 500 `NullPointerException`
  ("Cannot invoke ... getDate() because the return value ... is null") --
  neither documented anywhere found, both confirmed by direct trial, not
  assumed from the Sigma spec.
- The response's `_id` is OpenSearch's OWN generated id, independent of
  whatever `id:` the Sigma YAML itself declares -- confirmed by
  round-tripping a rule with a fixed UUID `id:` and observing a different
  server-generated `_id` come back. This is the id a detector's
  `custom_rules: [{"id": ...}]` must reference (see
  custom_rule_detector_provisioner.py), never the YAML's own `id:` field.
- Custom rules live in their own `.opensearch-sap-custom-rules-config`
  system index, disjoint from `.opensearch-sap-pre-packaged-rules-config`
  -- confirmed via `pre_packaged=false` on the search endpoint.
- `DELETE _plugins/_security_analytics/rules/{id}` takes no `category`
  query param (passing one is rejected with a real 400
  `illegal_argument_exception: unrecognized parameter`) -- unlike the
  create call, which requires it.

Admin-only (A3 binding condition, poc/security_analytics_tenant_isolation/)
-- never constructed with a tenant token, same trust tier as
SecurityAnalyticsDetectorProvisioner/SecurityAnalyticsFindingsClient. This
class never accepts raw OpenSearch Query DSL from a caller -- only a Sigma
YAML string -- so it structurally cannot be used to smuggle an
index-crossing query (roadmap risk (b)): Sigma has no field for an index
name, and the index pattern a rule ever runs against is decided entirely
by the detector wrapping it (see custom_rule_detector_provisioner.py),
never by rule content.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)


class CustomRuleClient(ABC):
    """Admin-only access to OpenSearch Security Analytics' real custom-rule store."""

    @abstractmethod
    async def create_rule(self, sigma_yaml: str, log_type: str) -> str:
        """Push *sigma_yaml* to OpenSearch's real custom-rule store.

        Returns the OpenSearch-assigned rule id (NOT the YAML's own `id:`
        field -- see module docstring).
        """

    @abstractmethod
    async def delete_rule(self, opensearch_rule_id: str) -> None:
        """Remove a previously-created custom rule.

        Idempotent: deleting an already-gone rule id is not an error.
        """


class SecurityAnalyticsCustomRuleClient(CustomRuleClient):
    """Real OpenSearch 2.11.1 Security Analytics custom-rule REST client."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def create_rule(self, sigma_yaml: str, log_type: str) -> str:
        # verify=False: same self-signed internal step-ca cert as every
        # other admin-only Security Analytics adapter in this repo
        # (detector_provisioner.py, findings_client.py) -- OPENSEARCH_URL
        # is https://opensearch:9200 even docker-internally.
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(
                f"{self._base_url}/_plugins/_security_analytics/rules",
                auth=self._auth,
                params={"category": log_type},
                headers={"Content-Type": "application/json"},
                content=sigma_yaml.encode("utf-8"),
            )
            resp.raise_for_status()
            return str(resp.json()["_id"])

    async def delete_rule(self, opensearch_rule_id: str) -> None:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.delete(
                f"{self._base_url}/_plugins/_security_analytics/rules/{opensearch_rule_id}",
                auth=self._auth,
            )
            if resp.status_code == 404:
                logger.info(
                    "custom_rule_already_deleted",
                    extra={"opensearch_rule_id": opensearch_rule_id},
                )
                return
            resp.raise_for_status()
