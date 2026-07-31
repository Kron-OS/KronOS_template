"""Wires accepted custom rules into a real, per-org, per-log-type detector.

Roadmap M2/C3 (docs/NEXTGEN_SOC_ROADMAP.md). A deliberate SIBLING to
``SecurityAnalyticsDetectorProvisioner`` (C2), not an extension of it: C2's
class idempotently bootstraps a *static* per-org detector set (the full
prepackaged rule catalogue for a fixed list of log types) once, at
case-creation time, and its own docstring documents a check-then-
create-only, never-update design specifically because a real OpenSearch
2.11.1 bug (`kotlin.collections.EmptyMap cannot be cast to
kotlin.collections.MutableMap`) makes PUT-updating an existing detector
unsafe. A custom-rule detector's content is the opposite of static -- it
must change every time a tenant adds/edits/removes a custom rule via
``RulePackService`` -- so forcing that responsibility onto C2's class would
either reintroduce the PUT bug or bolt a second, unrelated responsibility
(reacting to rule-pack CRUD) onto an already-complete, already-verified
class. Confirmed empirically (poc/rule_pack_lifecycle/) that the same
real PUT-update defect reproduces identically for this detector shape too,
so this class ALSO never updates in place: it deletes and recreates
whenever the desired custom-rule id set differs from what is currently
attached (idempotent: a no-op when they already match).

Real, empirically-confirmed detector shape (poc/rule_pack_lifecycle/):
``inputs[0].detector_input.custom_rules`` is a flat list of ``{"id": ...}``
objects (unlike the ``detector.name`` idempotency trap C2 hit -- this field
is NOT nested), so a plain read-back comparison is safe here.

Tenant isolation (roadmap risk (b)): ``indices`` is always
``kronos-{org_alias}-*``, computed by the caller from the authenticated
``TenantContext``/org alias -- never from rule or pack content, which have
no field to express an index or tenant at all (Sigma has no such field).
Admin-only (A3 binding condition) -- same trust tier as every other
Security Analytics adapter in this repo.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)


class CustomRuleDetectorBinder(ABC):
    """Ensures a real detector's custom-rule set matches KronOS's desired state."""

    @abstractmethod
    async def sync_custom_detector(
        self, org_alias: str, log_type: str, opensearch_rule_ids: tuple[str, ...]
    ) -> None:
        """Idempotently make the (org_alias, log_type) custom detector's
        ``custom_rules`` be exactly *opensearch_rule_ids*.

        An empty tuple deletes the detector if one exists (nothing left to
        detect). A no-op if the desired set already matches what's attached.
        """


class SecurityAnalyticsCustomRuleDetectorProvisioner(CustomRuleDetectorBinder):
    """Real OpenSearch 2.11.1 Security Analytics implementation.

    Delete-and-recreate idempotency strategy -- see module docstring for why
    this never attempts a PUT-update.
    """

    _DETECTOR_SUFFIX = "custom-detector"

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    def _detector_name(self, org_alias: str, log_type: str) -> str:
        return f"kronos-{org_alias}-{log_type}-{self._DETECTOR_SUFFIX}"

    async def sync_custom_detector(
        self, org_alias: str, log_type: str, opensearch_rule_ids: tuple[str, ...]
    ) -> None:
        name = self._detector_name(org_alias, log_type)
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            existing = await self._find(client, name)
            desired = tuple(sorted(opensearch_rule_ids))
            if existing is not None:
                current = tuple(
                    sorted(
                        r["id"]
                        for r in existing["_source"]["inputs"][0]["detector_input"]["custom_rules"]
                    )
                )
                if current == desired:
                    logger.info(
                        "custom_detector_already_current",
                        extra={"org_alias": org_alias, "log_type": log_type, "rule_count": len(desired)},
                    )
                    return
                await client.delete(
                    f"{self._base_url}/_plugins/_security_analytics/detectors/{existing['_id']}",
                    auth=self._auth,
                )
            if not desired:
                logger.info(
                    "custom_detector_removed_no_rules",
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
                                f"KronOS tenant custom-rule detector for org {org_alias}, "
                                f"log type {log_type}"
                            ),
                            "indices": [f"kronos-{org_alias}-*"],
                            "pre_packaged_rules": [],
                            "custom_rules": [{"id": rid} for rid in desired],
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
                "custom_detector_synced",
                extra={"org_alias": org_alias, "log_type": log_type, "rule_count": len(desired)},
            )

    async def _find(self, client: httpx.AsyncClient, name: str) -> dict | None:
        # Nested query: same real shape C2 found for detector.name -- see
        # SecurityAnalyticsDetectorProvisioner._ensure_detector's docstring.
        resp = await client.post(
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
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return hits[0] if hits else None
