# PoC: OpenSearch Dashboards multi-tenancy (saved-object isolation) — new construction

**Scope note (same framing as `poc/opensearch_jwt/`):** this repo has
**zero** Dashboards-tenancy wiring today —
`docker/docker-compose.dev.yml` sets `DISABLE_SECURITY_DASHBOARDS_PLUGIN=true`
for the `opensearch-dashboards` service. This is genuinely new-construction
verification, not a re-check of existing code.

## Why this is a separate PoC from `poc/opensearch_jwt/`

The docs.opensearch.org page the user originally linked
(`multi-tenancy/multi-tenancy-config/`) covers **two different features**
that happen to share the word "multi-tenancy":

- **Document-Level Security (DLS)** — restricts which *documents* a query
  returns. Already built and verified in `poc/opensearch_jwt/` and
  `poc/keycloak_opensearch_dls/` (flat `org_id` JWT claim + one generic
  templated role).
- **Dashboards multi-tenancy** — isolates *saved objects* (index-patterns,
  visualizations, dashboards) per tenant. This is what `docs/subsystems/multi-tenancy.md`
  means by "One OS Dashboards tenant per org" — a completely separate
  mechanism, untouched until this PoC.

## Versions (pinned, read from this repo)
- `opensearchproject/opensearch:2.11.1` and
  `opensearchproject/opensearch-dashboards:2.11.1` (`docker/docker-compose.dev.yml`
  — the two versions must stay matched per that file's own comment).

## What this actually does
`run_poc.sh` starts real OpenSearch 2.11.1 (security enabled via the
image's bundled demo config) and real OpenSearch Dashboards 2.11.1 with
its security-dashboards plugin genuinely enabled (i.e. *not* setting
`DISABLE_SECURITY_DASHBOARDS_PLUGIN`) and `multitenancy.enabled: true`.
It creates two real per-org Dashboards tenants (`kronos-org-a`,
`kronos-org-b`), two roles each granted `kibana_all_write` on only their
own tenant, and two internal (basic-auth) users mapped to them.
`run_poc.py` then logs in as each user for real and drives the real
Dashboards Saved Objects HTTP API (`/api/saved_objects/*`, scoped per
request via the `securitytenant` header — the mechanism Dashboards itself
uses when a user picks a tenant from its UI dropdown).

Deliberately **not** wired to Keycloak OIDC here — internal (basic-auth)
users isolate the tenant/saved-object mechanism itself from the separate
question of how a user authenticates to Dashboards in the first place
(real Keycloak↔Dashboards SSO is `poc/dashboards_embed`'s concern, the
`cases.py` embed-URL route). Same "verify the mechanism before wiring SSO"
split already used for DLS in `poc/opensearch_jwt/option_a_flat_claim/`.

## Result: 11/11 real checks passed (`output.txt`)
- Real login for both users shows the correct, and only the correct, tenant
  in each one's authenticated tenant list (`user-a` sees `kronos-org-a`,
  never `kronos-org-b`, and vice versa) — confirmed straight from
  Dashboards' own `/auth/login` response, not inferred.
- Each user created a real saved object (index-pattern) in their own tenant
  via the real Saved Objects API.
- **Direct lookup**: each user's `GET` for the *other* org's object returns
  a plain `404` — the object genuinely doesn't exist in their tenant's
  storage, not a permission error that could leak existence.
- **Listing**: each user's `_find` call lists **only** their own object —
  the real UI-facing "what's available" call is correctly scoped too, not
  just single-object lookups.
- **Explicit tenant override**: a user explicitly requesting a
  `securitytenant` header for a tenant they have no role grant on is denied
  (`500` — a rough, undifferentiated error code rather than a clean `403`,
  worth noting as a minor API rough edge, but access is genuinely denied,
  not silently served).

## What this confirms for the production fix (not done here)
`docs/subsystems/multi-tenancy.md`'s "One OS Dashboards tenant per org"
design is now verified sound: per-org tenant + per-org role (granting
`kibana_all_write` on that tenant only) correctly isolates saved objects
two ways, using the same org-scoped backend-role pattern the realm's
`organization` claim already puts in every JWT's flat `roles`/`org_id`
claims. Not done here (separate follow-up, matches `poc/dashboards_embed`
in the existing PoC plan):
- Wiring real Keycloak OIDC login for Dashboards itself (this PoC used
  internal basic-auth users specifically to avoid that scope).
- Automating tenant + role + role-mapping provisioning per org (mirroring
  `scripts/provision_keycloak_org.sh`'s pattern for the DLS side) —
  currently these were created by hand in `run_poc.sh`, matching how
  `ensure_generic_tenant_role()` looked before its own production wiring.
- Wiring the actual `TimelineIngestionService`/OpenSearch adapter code
  path, if a Dashboards-tenant-provisioning step is added to production
  (this PoC only reaches into OpenSearch's Security API directly, not
  through any `src/` code, since none exists for this yet).

## Files
- `run_poc.sh` — full reproducible bootstrap (OpenSearch + Dashboards +
  tenants/roles/users) + `run_poc.py`
- `run_poc.py` — the actual verification, driving Dashboards' real Saved
  Objects HTTP API
- `output.txt` — captured transcript of the last real run (11/11 passed)

## Cleanup
```bash
docker rm -f kronos-poc-dash-opensearch kronos-poc-dash-dashboards
docker network rm kronos-poc-dash-net
```
