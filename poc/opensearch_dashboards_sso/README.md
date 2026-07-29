# PoC: real Keycloak OIDC SSO into real OpenSearch Dashboards + automated per-org tenant provisioning

## What this solves

`poc/opensearch_dashboards_tenancy/` already verified the Dashboards
saved-object tenant-isolation *mechanism* (11/11 passed) but deliberately
used internal basic-auth users, explicitly deferring "real Keycloak<->Dashboards
SSO" as a separate concern. `access-management-review.md`'s `[C-1]` finding
("OpenSearch Dashboards iframe bypasses all tenant isolation") calls this
the single most serious open finding in the repo. This PoC closes that gap:
real Keycloak 26.2 OIDC login into real OpenSearch Dashboards 2.11.1, plus
a real, automated per-org Dashboards tenant/role/rolesmapping provisioning
script — no internal users, no manual setup.

## Versions (pinned, read from this repo)
- `opensearchproject/opensearch:2.11.1` / `opensearchproject/opensearch-dashboards:2.11.1` (`docker/docker-compose.dev.yml`)
- `quay.io/keycloak/keycloak:26.2` (`docker/docker-compose.dev.yml`, standardized this session)

## Design questions resolved (verified against real docs/source, not guessed)

1. **Does OpenSearch's `${attr.jwt.org_id}` DLS templating (already shipped,
   `src/adapter/opensearch/client.py`'s `ensure_generic_tenant_role`) also
   work for openid-authenticated Dashboards sessions, or only the backend's
   own bearer-JWT calls?** Confirmed by reading the real
   `opensearch-project/security@2.11` source:
   `HTTPJwtKeyByOpenIdConnectAuthenticator extends AbstractHTTPJwtAuthenticator`
   — the *same* class the plain `"jwt"` authenticator uses. Every claim in
   the token, from either authenticator, gets stored under `attr.jwt.*`
   identically. Setting the openid authc domain's `roles_key: org_id`
   therefore reuses the exact same flat claim DLS already depends on, at
   zero extra Keycloak-side cost.

2. **Can a single generic role/tenant (mirroring the DLS design) cover
   Dashboards tenant isolation, or does it need one tenant per org?**
   Confirmed NOT generic: read the real OpenSearch 2.11 docs
   (`access-control/document-level-security.md`) — `${attr.<TYPE>.<NAME>}`
   parameter substitution is documented *only* for the `"dls"` field of
   index permissions, never for `tenant_permissions.tenant_patterns`. So
   Dashboards tenant isolation genuinely needs one real tenant + role +
   rolesmapping per org (`provision_dashboards_tenant.sh`), each
   rolesmapping's `backend_roles` set to that org's own `org_id` — which
   the openid authc domain's `roles_key: org_id` config turns into an
   automatic backend-role match, so **no per-member OpenSearch-side
   provisioning is ever needed after the org itself is created**, matching
   the same property already verified for DLS in
   `poc/keycloak_opensearch_dls/`.

## Real bugs found and fixed while building this (each confirmed via direct reproduction, not assumed)

1. **A `challenge: true` openid authc domain ordered before `basic`
   permanently broke `admin:admin` access.** Read the real
   `BackendRegistry.java` auth-domain loop: a domain with `challenge: true`
   that fails to extract credentials immediately short-circuits with *its
   own* 401 and never tries later domains — happened in both directions
   (openid-first, then basic-first) until both domains were set
   `challenge: false`.
2. **`subject_key: preferred_username`** (the real doc's own example) fails
   silently — this realm's actual token has no such claim; decoded a real
   token to confirm, switched to `subject_key: sub` (matching the
   already-proven `poc/opensearch_jwt/` choice).
3. **`OPENSEARCH_SECURITY_AUTH_TYPE`/`OPENSEARCH_SECURITY_OPENID_*` env vars
   are silently ignored** by the real 2.11.1 Dashboards image — read its
   own `opensearch-dashboards-docker-entrypoint.sh`: the `opensearch_dashboards_vars`
   allowlist (the only vars it translates to `--longopts`) has zero
   `opensearch_security.*` entries. (`opensearch_security.multitenancy.*`
   only *appeared* to work in `poc/opensearch_dashboards_tenancy/` because
   they're the image's own baked-in config-file defaults — a false
   positive, confirmed by inspecting a fresh unmodified container's config.)
4. **Dashboards' self-computed `redirect_uri` used `0.0.0.0`** (its bind
   address) instead of a real hostname, observed directly in a real 302
   response — fixed with `opensearch_security.openid.base_redirect_url`.
5. **Even after fixing #4, the redirect target Keycloak itself advertises
   was still unreachable from this script.** Dashboards computes the
   authorization-endpoint Location it sends the browser using *its own*
   view of Keycloak's hostname (its `openid.connect_url` config) — with a
   bridge network + published ports, that was Keycloak's container-DNS
   name, resolvable server-side but not from this host-side script. Fixed
   by running all three services on `--network host` instead, so a single
   `localhost:<port>` per service is genuinely reachable identically from
   Dashboards (server-side), Keycloak (`--hostname-strict=false` mirrors
   back whichever hostname reached it), and this script (the "browser").
6. **Dashboards' own default openid scope request
   (`openid profile email address phone`) fails with a real `invalid_scope`
   error.** Confirmed via `GET .../client-scopes`: the real production
   `kronos-realm.json` has no `profile`/`email`/`address`/`phone`
   client-scope objects at all (only the custom ones it explicitly
   defines) — true regardless of import method (`--import-realm` or
   `POST /admin/realms`), so this is a real property of the shipped realm,
   not a PoC artifact. Fixed by narrowing Dashboards'
   `opensearch_security.openid.scope` to `"openid"` alone (the one
   always-valid implicit scope) — KronOS's own flat-claim design never
   needed the others.
7. **A restart-based "start Dashboards, then append config, then restart"
   sequence hit a real migration collision**: the first boot's
   `.kibana_1` creation was mid-flight when the restart landed, and the
   second boot's own migration then failed with
   `resource_already_exists_exception`, leaving Dashboards permanently
   503. Fixed by appending the extra config *before* the dashboards
   process's single boot (a `--entrypoint bash -c "cat ... >> ...yml && exec ..."`
   wrapper), not via `docker restart`.
8. **Keycloak's `KC_RESTART` cookie is marked `Secure=True` even over plain
   HTTP**, causing a real `400 Restart login cookie not found` from
   Keycloak's own login-form POST. Same class of quirk `poc/auth_flow/auth_helpers.py`
   already documented; fixed the same way (bypass the `Secure` check for
   this scripted client only).

## Result: 11/11 real checks passed (`output.txt`)
- Direct OpenSearch `authinfo` check (a real ROPC-granted token, independent
  of Dashboards) confirms `roles_key=org_id` correctly populates
  `backend_roles` and `subject_key=sub` correctly resolves the username.
- Real Dashboards openid login, full redirect chain, both users.
- Real saved-object creation, cross-org 404s (not leaked), correctly-scoped
  `_find` listing, and denial of an explicit unauthorized tenant request —
  all through real OIDC-authenticated Dashboards sessions, not internal
  users.

## Files
- `run_poc.sh` — full bootstrap: Keycloak (real production realm, unmodified,
  imported via `--import-realm` matching `docker-compose.dev.yml` exactly) +
  OpenSearch (security enabled, openid authc domain + the real generic DLS
  role) + Dashboards (openid auth type, single-boot config), all on
  `--network host`; then runs `run_poc.py`.
- `run_poc.py` — provisions 2 real orgs + 2 real Dashboards tenants, then
  drives all 11 checks.
- `provision_dashboards_tenant.sh` — the new, reusable per-org provisioning
  script this PoC verified (candidate for `scripts/`, mirroring
  `scripts/provision_keycloak_org.sh`'s pattern).
- `output.txt` — captured transcript of the last real run (11/11 passed).

## Production wiring: now shipped

Everything below was ported into the real `docker-compose.dev.yml` stack
(not just this PoC) and re-verified end-to-end against all 18 real
services brought up together — see `docs/verification-pass-findings.md`
row 23 for the full account, including one more real bug
(`KC_HOSTNAME_BACKCHANNEL_DYNAMIC`) that only surfaced once the actual
multi-service stack was brought up:
- OpenSearch + Dashboards security plugins genuinely enabled in
  `docker-compose.dev.yml` (`DISABLE_SECURITY_PLUGIN`/
  `DISABLE_SECURITY_DASHBOARDS_PLUGIN` removed).
- `docker/opensearch/opensearch.yml` now exists for real (was missing per
  `access-management-review.md` `[C-2]`); the openid authc domain + generic
  DLS role are provisioned by a new `opensearch-init` service
  (`scripts/provision_opensearch_security.py`).
- Dashboards' `opensearch_dashboards.yml` gets the same additions verified
  here (`auth.type`, `openid.connect_url`, `client_id`, `client_secret`,
  `base_redirect_url`, `scope`), appended in a single container boot
  (`docker/opensearch-dashboards/opensearch_security_openid.yml`).
- `provision_dashboards_tenant.sh` promoted to `scripts/` (now resolves
  `org_id` itself via the Keycloak Admin API) and wired into a new
  `dashboards-tenant-init` service.
