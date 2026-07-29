# OpenSearch Dashboards SSO users can't read `kronos-*` documents (DLS gap)

**Versions pinned:** `quay.io/keycloak/keycloak:26.2` (real 26.2.0 source read
for the mechanism below), `opensearchproject/opensearch:2.11.1` — matching
`docker/keycloak/kronos-realm.json` / `docker/docker-compose.dev.yml`.

## The bug

A real end user logging into OpenSearch Dashboards via SSO (Keycloak OIDC)
got `403 security_exception` on `indices:admin/resolve/index` (blocks
creating an index pattern / any Discover data view) and
`cluster:admin/opensearch/ql/datasources/read` (Query Workbench nag). Their
only granted roles were `own_index` (OpenSearch's built-in, irrelevant) and
`kronos-dash-${org_alias}` (saved-objects tenant access only — confirmed via
`scripts/provision_dashboards_tenant.sh`: `tenant_permissions` only,
`index_permissions: []`).

**Root cause, confirmed against the live `docker-compose.dev.yml` stack's
own OpenSearch `/_plugins/_security/api/securityconfig`:** the Dashboards
OIDC authc domain is configured `roles_key: "org_id"`
(`scripts/provision_opensearch_security.py`), so every Dashboards SSO
session's `backend_roles` is just `[their org_id UUID]`. The role that
actually grants index-level `read`/`search` on `kronos-*`
(`kronos-generic-tenant`) is mapped to
`backend_roles: ["org-admin","case-lead","analyst","read-only"]` — Keycloak
realm role **names**. An org-id UUID never equals one of those four
strings, so `kronos-generic-tenant` can never be granted to a Dashboards SSO
session. The comment in `provision_opensearch_security.py` claiming
`roles_key=org_id` gives "DLS enforcement for free" conflates the DLS
*filter template* (`${attr.jwt.org_id}`, which does work once a role is
granted) with the *role-mapping match* (which never succeeds here).

This happened because two separate PoCs each verified a **different,
mutually incompatible** `roles_key` for what was assumed to be the same
mechanism, and neither tested them together:
- `poc/keycloak_opensearch_dls/` verified the DLS arc with `roles_key: "roles"`.
- `poc/opensearch_dashboards_sso/` shipped the real Dashboards authc domain
  with `roles_key: "org_id"`, and only ever checked that `backend_roles`
  contains the org_id — never that the DLS role was actually granted.

OpenSearch's authenticator supports exactly one `roles_key` claim per authc
domain, so the two existing rolesmappings (`kronos-dash-${org_alias}` needs
`backend_roles ∋ org_id`; `kronos-generic-tenant` needs
`backend_roles ∋ {realm role names}`) structurally cannot both be satisfied
by a single-valued claim.

## Why this matters for security, not just UX

The FastAPI backend never queries OpenSearch on a user's behalf at all
(confirmed: no `.search()` call anywhere in `src/application`/`src/external/routes`,
and `src/external/middleware/{query_isolation,opensearch_isolation}.py`'s own
docstrings say so — they're unwired scaffolding). **Every real view of
timeline data goes through OpenSearch Dashboards' Discover UI, which the
browser calls directly — bypassing the backend and its `TenantContext`
entirely.** OpenSearch's own DLS role-mapping is therefore the *sole*
enforcement point for this data path. Before this fix, that boundary
fails safe-but-broken (denies everyone); a careless fix could instead make
it fail open (leak cross-org data) — hence PoC-first.

## The fix

Real Keycloak 26.2 source (`OIDCAttributeMapperHelper.mapClaim()`,
`AbstractUserRoleMappingMapper.setClaim()`) confirms: two protocol mappers
targeting the **same `claim.name`**, both with `multivalued: true`, get
their values **merged into one deduplicated collection** regardless of
mapper type or evaluation order (building on the sibling research in
`poc/opensearch_jwt/option_a_flat_claim/keycloak_mapper_research.md`, plus
direct reading of both classes for this PoC).

So: add one new client scope, **`kronos-dashboard-roles`**, with two
mappers sharing `claim.name: "dashboard_roles"`:
- a copy of the existing realm-role mapper (`oidc-usermodel-realm-role-mapper`)
- a copy of the existing org_id attribute mapper (`oidc-usermodel-attribute-mapper`)

Assign this scope **only** to the `opensearch-dashboards` Keycloak client
(least privilege — the SPA/backend clients never see this claim). Point
OpenSearch's Dashboards authc domain's `roles_key` at `dashboard_roles`
instead of bare `org_id`. The separate, existing `org_id` claim (used by
`${attr.jwt.org_id}` DLS templating) is untouched, so the actual per-request
document filter is unaffected by this change — only *whether* a legitimate
same-org read is granted at all changes, not the isolation boundary itself.

## What was verified, for real

`run_poc.sh` brings up real Keycloak 26.2 + real OpenSearch 2.11.1,
provisions two real Organizations (org A: two `analyst` members; org B: one
`case-lead` member — deliberately a *different* realm role, to prove the
merge isn't `analyst`-specific), wires OpenSearch exactly like production
(`kronos-generic-tenant` + per-org `kronos-dash-*` roles, both **byte-for-byte
unchanged** from the real `scripts/`), seeds one real document per org into
a `kronos-*`-patterned test index, then `run_poc.py` does real password-grant
logins and asserts against the real OpenSearch API. **18/18 real checks
passed** (`output.txt`):

- Combined `dashboard_roles` claim contains both the real org_id and the
  real realm role, for two different roles (`analyst`, `case-lead`) — not
  a coincidence specific to one role name.
- The separate `org_id` claim (DLS templating) is unaffected.
- Both users are granted `kronos-generic-tenant` (DLS/read) **and** their
  own org's `kronos-dash-*` (tenant) role from the **same** token — and
  explicitly **not** the other org's tenant role.
- A real authenticated search against the seeded index returns **exactly
  the caller's own org's document**, never the other org's — cross-org DLS
  isolation holds with the new `roles_key`.
- `kronos-frontend` (the SPA client) tokens have **no** `dashboard_roles`
  claim at all — the new scope's blast radius is confirmed contained to the
  Dashboards client only.

## Bugs found *while building this PoC* (both fixed, not part of the design finding)

1. The first realm file draft put a 538-character rationale in a client
   scope's `description` field — over Keycloak's own
   `CLIENT_SCOPE.DESCRIPTION VARCHAR(255)` column limit, crashing the H2
   realm import outright (`ERROR: Value too long for column "DESCRIPTION..."`).
   This is the *exact* bug class already hit and fixed once before in this
   repo's real history (`kronos-org-id`'s scope description, commit
   `ccb167d`'s fix) — recurred because the description was still authored
   in the JSON file instead of this README. Fixed: keep JSON descriptions
   short, put rationale in the PoC README.
2. `run_poc.sh`'s `until curl ...; do sleep 3; done` wait loops had no
   retry bound or failure output. Combined with bug #1's near-instant
   Keycloak crash, this made the first real run of this PoC hang silently
   for 33+ minutes (Keycloak was `Exited (1)` the whole time; the loop just
   kept polling a dead container with zero output) before a human noticed
   and killed it. Fixed: a bounded `wait_for()` helper that prints progress
   every 15s and, on timeout, prints the target container's actual status
   and log tail before exiting non-zero.
3. The test index's `kronos.org_id` field was left to OpenSearch's dynamic
   mapping, which made it a `text` field (+ `.keyword` subfield) — the DLS
   role's `term` filter (an exact-match query) then matched **zero**
   documents, even for an admin bypassing DLS entirely (confirmed via
   `GET .../_mapping` and a direct admin-credentialed `term` query).
   Production doesn't hit this because
   `TimelineIngestionService.ensure_index_template()` already maps
   `kronos.org_id` as `keyword` for real; this PoC's throwaway index just
   never had that template applied. Fixed: explicit `PUT` mapping
   (`kronos.org_id: keyword`) before seeding documents.

## Shipped, and verified for real against the actual dev stack

Shipped into `docker/keycloak/kronos-realm.json` (new `kronos-dashboard-roles`
client scope, assigned only to the real `opensearch-dashboards` client's
`defaultClientScopes`), `scripts/provision_opensearch_security.py`
(`roles_key: "dashboard_roles"`), and `scripts/provision_dashboards_tenant.sh`
(comment only — its logic was already correct and unaffected). Full clean
rebuild (`docker compose down -v && up -d --build`) — all 18 services and
init jobs green on the first try.

Real login as `analyst` through the actual `kronos.local` stack confirmed:
`backend_roles=[org_id, "analyst"]`, both `kronos-generic-tenant` and
`kronos-dash-kronos-dev` granted, `_resolve/index/kronos-*` → 200.
`_resolve/index/*` (bare wildcard) still 403s — confirmed **by design**,
not a bug: `kronos-generic-tenant`'s `index_permissions` is intentionally
scoped to `kronos-*` only, so a KronOS user correctly cannot enumerate the
whole cluster's indices. That 403 is Dashboards' own generic "suggest all
indices" empty-state probe, not something that blocks a real user.

**Real Playwright browser pass**, not just API calls: logged in as
`case-lead` through the real SSO flow (`Sign in with SSO` → real Keycloak
login form → real redirect back), opened a real case's Timeline tab (real
iframe to `kronos.local:5602`), selected the case's own custom tenant,
opened "Create index pattern", and typed the real case's index pattern
(`kronos-kronos-dev-case-ad2aaefe*`, from a real 5-parser ingestion via
`poc/full_ingestion_test/run_ingest.py` against this same rebuilt stack).
**Result: all 9 real monthly-rollover indices for that case resolved
correctly, with no error** — `browser_verification_index_pattern_resolves.png`.
This is the exact permission chain the fix repairs, confirmed working
end-to-end in an actual browser against real ingested evidence, not a
synthetic token/API check.

## Remaining (not this PoC's scope)

- The tenant-selector dialog Dashboards shows on first load ("Select your
  tenant") is a separate, already-documented gap (`PROGRESS.md`'s
  "Dashboards embed URL never sets an index-pattern app-state" flag) — the
  embed URL should ideally auto-select the case's org tenant so the user
  never sees this dialog. Unaffected by (and unrelated to) this fix.
