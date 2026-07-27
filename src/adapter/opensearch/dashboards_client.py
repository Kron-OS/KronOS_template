"""OpenSearch Dashboards saved-object provisioning (per-case index patterns).

Fixes the gap flagged in poc/dashboards_embed/README.md and
poc/opensearch_dashboards_dls/README.md: get_dashboard_url() only ever put
a raw index-name string into the embed URL's filter, but Discover needs a
real saved index-pattern object to exist before it can show any data — with
none ever created, every real user landed on Dashboards' "create an index
pattern first" empty state. This auto-provisions one at case-creation time.

Real OpenSearch Dashboards 2.11.1 saved-objects API, verified against the
live dev stack (not assumed):
  - POST .../saved_objects/index-pattern/{id}?overwrite=true is the
    idempotent create-or-replace call. PUT is UPDATE-only and 404s if the
    object doesn't already exist (easy to reach for first, wrong).
  - The `osd-xsrf` header is mandatory on any non-GET call, or the API
    flatly 400s ("Request must contain the osd-xsrf header.").
  - `securitytenant` selects which OpenSearch Dashboards tenant to write
    into — must match the org's own tenant (kronos-{org_alias}, the same
    one scripts/provision_dashboards_tenant.sh creates) or the object is
    invisible to the org's real users.
  - IndexPatternAttributes (src/plugins/data/common/index_patterns/types.ts
    at tag 2.11.1) has no separate display-name field — `title` is both
    the matching pattern and the only label shown in the UI. Setting title
    to a human case title would break matching entirely, so this uses the
    real pattern as the title, by design (see that PoC's README for the
    version-specific constraint this is working around).
"""

from __future__ import annotations

import logging
import uuid

import httpx

logger = logging.getLogger(__name__)


class DashboardsIndexPatternProvisioner:
    """Auto-provisions the OpenSearch Dashboards index pattern for a case's timeline."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def ensure_case_index_pattern(self, org_alias: str, case_id: uuid.UUID) -> None:
        """Idempotently create (or replace) the case's timeline index pattern.

        Best-effort: logs and swallows failures rather than blocking case
        creation on a transient Dashboards outage. A real user can still
        create the pattern manually via the wizard if this never runs.
        """
        pattern_id = f"kronos-case-{case_id}-timeline"
        title = f"kronos-{org_alias}-case-{case_id}-*"
        tenant = f"kronos-{org_alias}"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{self._base_url}/api/saved_objects/index-pattern/{pattern_id}",
                    params={"overwrite": "true"},
                    headers={"securitytenant": tenant, "osd-xsrf": "true"},
                    auth=self._auth,
                    json={
                        "attributes": {
                            "title": title,
                            "timeFieldName": "@timestamp",
                            "fields": "[]",
                        }
                    },
                )
                resp.raise_for_status()
            logger.info(
                "dashboards_index_pattern_ensured",
                extra={"case_id": str(case_id), "org_alias": org_alias, "title": title},
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "dashboards_index_pattern_provisioning_failed",
                extra={"case_id": str(case_id), "org_alias": org_alias, "error": str(exc)},
            )
