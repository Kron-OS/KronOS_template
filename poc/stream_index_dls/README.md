# B2: stream index family + DLS/ISM extension

**Roadmap item:** `docs/NEXTGEN_SOC_ROADMAP.md` M1/B2.

## Conclusion: DLS and ISM already cover the new index family — no config change needed

`kronos-generic-tenant`'s DLS clause (`{"term": {"kronos.org_id": "..."}}`,
index pattern `kronos-*`) and the ISM rollover policy (`ism_template.index_patterns:
["kronos-*"]`) are both templated on the same wildcard `build_index_name`'s
case-scoped naming already relies on. `build_stream_index_name()`
(`src/application/timeline_normalization.py`) keeps the same `kronos-*`
prefix deliberately, so both inherit automatically — confirmed for real
against the live cluster, not assumed from the wildcard alone (12/12 checks,
`output.txt`).

## Real check performed

1. Created a real index in the exact shape `build_stream_index_name()`
   produces (`kronos-kronos-dev-stream-kronos-poc-source-202607`).
2. Confirmed it really inherited the hardened A1 template automatically
   (`dynamic: false`, `kronos.org_id` mapped `keyword`) — no explicit mapping
   given at creation time.
3. Logged in as the real, live `case-lead` analyst via the real Dashboards
   SSO OIDC flow (same mechanism `poc/security_analytics_tenant_isolation/`
   used).
4. Indexed two real documents in the new index: one tagged with the real
   analyst's real `org_id`, one tagged with a different org id (this dev
   stack only has one real provisioned Keycloak org, so the second value is
   synthetic — see "Not verified" below; it's still a valid test of the DLS
   *mechanism*, which filters purely on the field value, not on whether that
   value happens to correspond to a second real, distinct org).
5. Confirmed via admin credentials (no DLS) that both documents really exist.
6. Confirmed via the real tenant session that **only** the matching-org
   document is visible.
7. Confirmed via the real `_plugins/_ism/explain/<index>` API that the
   existing `kronos-rollover` policy actually attached to the new index
   (`policy_id: "kronos-rollover"`), not inferred from the policy file's
   `index_patterns` alone.
8. Cleaned up the throwaway index.

## Real bug found and fixed along the way

**The A1 index-template hardening had never actually been pushed to the live
cluster.** A1's own PoC (`poc/ecs_schema_hardening/`) verified the hardened
mapping against a manually-constructed test index (an explicit mapping body
derived from the file), which correctly proved the *design* — but nothing
in that pass called the real `ensure_index_template()` application code
path against the live cluster's registered `kronos-template`. Confirmed via
`GET /_index_template/kronos-template`: the live, registered template had
**no `dynamic` key at all** (pre-A1 shape) even after A1 was "done." This
meant every real `kronos-*` index created since A1 (via the actual running
backend/Celery workers) was still silently using the old, unhardened,
dynamically-mapped behavior the whole time.

Fixed by calling the real application code path directly —
`OpenSearchClient.ensure_index_template()` — against the live cluster (not
a hand-rolled `curl PUT`), confirmed via the same real-index-inherits-the-mapping
check above. This is also naturally self-healing going forward:
`TimelineIngestionService.ingest_records()` already calls
`ensure_index_template()` on every ingest task's first run (see its own
docstring at `timeline_ingest.py`), so the next real parse would have fixed
this anyway — but it's now confirmed fixed rather than left to happen
incidentally on the next ingest.

## Not verified

- Only one real Keycloak org (`kronos-dev`) is provisioned in this dev
  stack, so "the other org" in the cross-org check is a synthetic UUID, not
  a second real authenticated session. The DLS mechanism itself is
  identical regardless (it filters on the `kronos.org_id` field value), and
  this exact mechanism was already proven with two real distinct orgs in
  `poc/opensearch_dashboards_dls/` — this PoC's job was only to confirm the
  *new index family* inherits that already-proven mechanism, which it does.
- Did not build the full per-source ISM tiering system (hot/warm/cold,
  per-log-type retention) — that's explicitly B3's separate scope. Flagged
  below for whoever picks up B3.

## Flag for B3 (per-source ISM tiering)

The current flat `kronos-rollover` policy (30 day/30 GB rollover, 365 day
delete) now demonstrably also governs stream indices, which are likely much
higher-volume and lower-value-per-event than case evidence (continuous
telemetry vs. discrete forensic files) — B3 should not assume the same
tiering/retention defaults are appropriate for both index families just
because they currently share one policy correctly.
