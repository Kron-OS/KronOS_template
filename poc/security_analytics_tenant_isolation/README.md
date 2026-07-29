# A3 GATE: OpenSearch Security Analytics multi-tenant isolation

**Roadmap item:** `docs/NEXTGEN_SOC_ROADMAP.md` M0/A3. Blocks C1, C2, C4, C6
(the entire rule-based detection engine).

## Verdict: **GO — WITH CONDITIONS**

Security Analytics/Alerting can be used, but **only mediated through KronOS's
own backend using admin credentials, never exposed directly to a tenant's
OpenSearch session or the native Dashboards UI.** The conditions below are
not defensive boilerplate — they are the literal mechanism that makes this
safe, confirmed empirically.

## The real finding

OpenSearch Security Analytics and Alerting provide **no per-tenant scoping
mechanism at all** for detectors/findings/alerts — no DLS, no per-tenant
filter, nothing equivalent to `kronos-generic-tenant`'s
`{"term": {"kronos.org_id": "${attr.jwt.org_id}"}}` clause. Access is pure
cluster-action RBAC: a role either has (e.g.)
`cluster:admin/opensearch/securityanalytics/detector/search` or it doesn't.
If it does, it sees **every tenant's** detectors/findings/alerts, cluster-wide
— there is no middle ground.

**What makes this safe today, and what must never change:** KronOS has never
granted any tenant-facing role (`case-lead`, `analyst`, `org-admin`,
`read-only`, or their Dashboards-role equivalents) any of OpenSearch's own
built-in SA/alerting roles (`security_analytics_read_access`/`_full_access`,
`alerting_read_access`/`_full_access`, `*_ack_alerts`). Confirmed by
enumerating every OpenSearch role with an SA/alerting cluster permission and
checking their real rolesmappings — none include any KronOS tenant backend
role (check 8, `run_poc.py`). This is isolation by **absence of grant**, not
isolation by design in the plugin itself.

## Real experiment performed (not simulated)

Logged in as a real tenant analyst (`case-lead`, org `kronos-dev`) through
the **exact real OIDC flow a real Dashboards SSO login uses** — the
`opensearch-dashboards` confidential client
(`docker/keycloak/kronos-realm.json`), which is the one that actually emits
the combined `dashboard_roles` claim (`[org_id, role_name]`) that
`kronos-generic-tenant`'s rolesmapping keys on. This is deliberately **not**
`jwt_auth_domain` (confirmed via the real `securityconfig` API to be
`http_enabled: false` in this cluster — a plain Bearer JWT from the
`kronos-frontend` app client, tried first, correctly gets rejected with
`backend_roles=[]` since it lacks the Dashboards-specific claim) and not a
synthetic/hand-built token.

With that real session:

| # | Check | Result |
|---|---|---|
| 1-2 | Real token issued, resolves to `kronos-generic-tenant` + `kronos-dash-kronos-dev`, nothing SA/alerting-related | PASS |
| 3 | Sanity: `kronos-*` search works (DLS active, 200) | PASS |
| 4 | `_plugins/_security_analytics/detectors/_search` | **403** — no cluster permission |
| 5 | `_plugins/_alerting/monitors/_search` | **403** — separate plugin, also no permission |
| 6 | Direct raw read of `.opensearch-sap-pre-packaged-rules-config` (bypassing the plugin API layer entirely) | **403** — `kronos-generic-tenant`'s `index_permissions` cover only `kronos-*` |
| 7-8 | Enumerated OpenSearch's own SA/alerting roles; confirmed none mapped to any KronOS tenant role | PASS |

**9/9 checks pass.** See `output.txt` for the full captured run (real HTTP
status codes and error bodies, not paraphrased).

## Conditions for GO (binding on C1/C2/C4/C6)

1. **Never map `security_analytics_*`/`alerting_*` roles to any tenant-facing
   KronOS role.** If this ever happens — even by accident, e.g. a future
   provisioning script broadening `org-admin`'s grants — that user sees every
   org's detectors and findings, cluster-wide, with no isolation whatsoever.
   This should be a CI/provisioning-script assertion, not just a documented
   rule (worth adding to C2's own proof bar).
2. **Detectors, rules, and findings are created/read/managed exclusively by
   a KronOS backend service using OpenSearch admin credentials** — the same
   trust tier as today's `ensure_index_template`/`ensure_ism_policy`/
   `DashboardsIndexPatternProvisioner` calls (`src/adapter/opensearch/`). A
   tenant's own browser session must never receive admin credentials or any
   SA/alerting role.
3. **All tenant-facing access goes through KronOS's own `Detection` entity
   and API (roadmap C4/C6)**, which filters findings by `org_id` at the
   *application* layer before returning anything. This isn't a NO-GO
   fallback — it's now confirmed to be the only correct design, since the
   plugin itself has nothing to fall back *from*.
4. **The native Security Analytics UI in OpenSearch Dashboards must never be
   exposed or linked to tenant users.** Today it would show nothing (their
   role has no permission — safe but useless); if condition 1 is ever
   violated it would show everything (unsafe). Neither outcome is
   acceptable for a tenant-facing surface.
5. Detectors provisioned per-org (C2) must be scoped to that org's own index
   pattern (`kronos-{org}-*`) as an additional belt-and-braces control, even
   though the real isolation boundary is condition 1-2, not the detector's
   own index-pattern scoping (a detector with `security_analytics_full_access`
   could still query other orgs' `.opensearch-sap-*` finding entries directly
   regardless of which index pattern it monitors).

## Not verified in this pass

- Did not create a real detector + real cross-org finding and attempt a
  read with `security_analytics_read_access` granted to confirm the "sees
  everything" half of the RBAC model empirically (only enumerated that the
  permission model is coarse via the role definitions, backed by the 403s
  above proving the *absence* side). The absence side is what actually gates
  GO/NO-GO here, and it's fully verified; the "if granted, unscoped" half is
  a reasonable inference from OpenSearch's own documented RBAC model but
  wasn't independently reproduced live. Flagged as a possible follow-up
  check if a future change ever needs a detector-holding service account.
- Did not test the Dashboards Security Analytics plugin's own browser UI
  directly (only the underlying REST API a real session's browser calls
  hit). Condition 4 makes this moot for tenant users regardless.
