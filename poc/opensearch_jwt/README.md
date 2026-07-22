# PoC: OpenSearch security plugin + JWT authc + real DLS enforcement (new construction)

**Scope note:** unlike every other PoC in this repo, this is not "verify
existing code" — this repo has **zero** OpenSearch security-plugin/JWT
wiring today (`DISABLE_SECURITY_PLUGIN=true` in `docker-compose.dev.yml`,
and `ensure_tenant_role()` — the one piece of related code that exists —
was already found in `poc/opensearch/README.md` to always fail in that
dev configuration). The user explicitly opted to build and verify this as
new capability (see CLAUDE.md Section F.4 / the conversation that scoped
this pass), not just re-verify something already claimed to work.

## Versions
- OpenSearch: `opensearchproject/opensearch:2.11.1` (same pinned version, security genuinely **enabled** this time — no `DISABLE_SECURITY_PLUGIN`)
- Keycloak: `quay.io/keycloak/keycloak:26.2` (same as every other Keycloak PoC)

## What this actually does

`run_poc.sh` bootstraps a real OpenSearch 2.11.1 with the security plugin
enabled (demo certs, `admin:admin` — 2.11.1 predates the
`OPENSEARCH_INITIAL_ADMIN_PASSWORD` requirement introduced in 2.12+), a
real Keycloak with a real Organization, configures OpenSearch's JWT authc
domain to trust Keycloak's real signing key, then `run_poc.py` drives the
real, unmodified `src/adapter/opensearch/client.py` (`OpenSearchClient.
ensure_tenant_role`, `ensure_index_template`, `bulk_index`) against it with
a real Keycloak-issued JWT.

## Two real, non-obvious build issues (found only by running it, fixed in this PoC's own config)

1. **OpenSearch's `securityconfig` REST endpoint refuses writes by
   default**, even for an authenticated admin: `{"status":"FORBIDDEN",
   "message":"Access denied"}`. Requires
   `plugins.security.unsupported.restapi.allow_securityconfig_modification:
   true` in `opensearch.yml` — not settable via REST or env var, only the
   config file itself (`run_poc.sh` adds it and restarts the node).

2. **`signing_key` must be the RAW base64 public key — no PEM headers, no
   newlines.** Configuring it as a standard PEM block (`-----BEGIN PUBLIC
   KEY-----\n...\n-----END PUBLIC KEY-----\n`, the natural thing to paste
   in) makes OpenSearch's `HTTPJwtAuthenticator` throw at startup:
   `io.jsonwebtoken.io.DecodingException: Illegal base64 character: '\n'`
   — it `Base64.decode()`s the config value directly, expecting one
   continuous base64 string. Confirmed via the real OpenSearch server log,
   not guessed. Fixed by stripping PEM headers/footers and joining the
   base64 lines before writing the config.

## Real result #1: JWT authentication + role extraction — works correctly

A real Keycloak-issued JWT authenticates to OpenSearch (`GET
_plugins/_security/authinfo` → 200, not 401), and `backend_roles` is
correctly populated from the flat top-level `roles` claim
(`roles_key: "roles"`) — confirming `docs/subsystems/multi-tenancy.md`'s
existing guidance ("`roles` is a flat, top-level array... OpenSearch
Security's `roles_key` cannot walk nested paths") is accurate, verified
against a real cluster.

## Real result #2: nested JWT claims are exposed as attributes, but NOT usable for DLS templating

The nested `organization` claim (`{"osjwt": {"id": "..."}}`) IS listed in
`authinfo`'s `custom_attribute_names` (`attr.jwt.organization`) — so it's
not simply dropped. But a DLS role templated as `${attr.jwt.organization}`
matched **none** of three real candidate values tested (the org alias, the
raw org_id, the JSON-stringified claim) — confirmed by testing all three
as literal field values against a real query through the templated role
and getting zero hits every time, while an unrestricted admin query
confirmed the documents genuinely existed. **This means OpenSearch's JWT
authenticator cannot drive dynamic, per-request DLS filtering directly off
a nested multi-org claim shape like this one** — which is exactly why the
codebase's actual design (`ensure_tenant_role(org_id, org_alias)`: one
statically pre-provisioned role per org, built server-side ahead of time,
not templated from the token at query time) is the necessary shape given
this constraint, not just one valid option among several.

## Real result #3 (the actual gap): `ensure_tenant_role()` creates the role but nothing ever maps a user to it

With security genuinely enabled (unlike `poc/opensearch/`'s dev-disabled
run), the real `ensure_tenant_role()` call **succeeds** this time — real
proof the role gets created correctly, DLS filter included:
```json
"kronos-tenant-<org_id>": {"index_permissions": [{"dls":
  "{\"term\": {\"kronos.org_id\": \"<org_id>\"}}", ...}]}
```
But `grep -rn "rolesmapping" src/` finds nothing — the method never PUTs
`/_plugins/_security/api/rolesmapping/kronos-tenant-{org_id}` linking any
actual user/backend_role to that role. Confirmed empirically: right after
a real `ensure_tenant_role()` call, the analyst's real `authinfo` still
shows `roles: ["own_index"]` — the tenant role exists but grants access to
**no one**. Manually adding the missing mapping
(`PUT rolesmapping/kronos-tenant-{org_id}` with the user's `sub`) makes it
appear in the user's effective roles immediately.

**Not fixed here — this needs a design decision, not a guess.**
`ensure_tenant_role(org_id, org_alias)`'s current signature has no user
identity to map, and a real fix has to pick an approach:
- map every org member individually (needs a user identity parameter and
  a call site for every membership change, not just once per org), or
- map by a `backend_role` unique to the org (would need Keycloak to mint
  an org-scoped backend role claim, not just the flat cross-org `roles`
  claim it has today), or
- some other pattern OpenSearch supports that wasn't explored here.

**Follow-up done, full chain (`option_a_flat_claim/` -> `../keycloak_opensearch_dls/` -> production):**
A flat, top-level scalar claim (not nested, unlike `organization`) DOES
resolve correctly in `${attr.jwt.X}` DLS templating — confirmed
Keycloak-free first (`option_a_flat_claim/`), then against real Keycloak
26.2 with real Organizations and real password-grant logins
(`../keycloak_opensearch_dls/`), then proven to scale to a brand-new member
added after the system is already configured with zero further OpenSearch
calls (`../keycloak_opensearch_dls/step4_new_member/`). The production fix
is now shipped: `src/adapter/opensearch/client.py`'s `ensure_tenant_role()`
was replaced with `ensure_generic_tenant_role()` (one static role + one
static mapping, created once ever), `scripts/provision_keycloak_org.sh` and
`docker/keycloak/kronos-realm.json` wire the flat `org_id` claim for real.
This gap is closed.

Flagging clearly rather than picking one blind, same reasoning as the
Keycloak step-up MFA bug in `poc/auth_flow/README.md`.

## Real result #4: with the gap manually closed, the full chain genuinely works

After manually adding the missing role mapping: real `bulk_index()`'d two
documents (one for the test org, one for a different org) into a
`ensure_index_template()`'d index (skipping that step reproduces
`poc/full_pipeline/`'s dynamic-mapping bug here too — DLS term queries
silently match nothing against a `text`+`.keyword` field instead of pure
`keyword`; worth remembering this is a real prerequisite, not a nice-to-have),
then queried as the real analyst JWT: **exactly one hit, the correct
document, the other org's document correctly excluded.** The whole
intended design works end-to-end once every piece (JWT authc, index
template, role, role mapping) is actually in place — this PoC proves the
design is sound, just incompletely wired in the current codebase.

## Full checklist — 10/10 passed

See `output.txt` for the complete captured transcript of an automated,
from-scratch re-run via `run_poc.sh`.

## Files
- `jwt_auth_domain.json` — reference OpenSearch JWT authc domain config (with the two fixes above already applied)
- `run_poc.sh` — full reproducible bootstrap (OpenSearch, Keycloak, org provisioning, JWT config) + `run_poc.py`
- `run_poc.py` — the actual verification, using the real `OpenSearchClient`
