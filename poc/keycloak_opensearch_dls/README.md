# PoC: real Keycloak 26.2 flat `org_id` claim + real OpenSearch DLS isolation (step 3)

Follow-up to `../opensearch_jwt/option_a_flat_claim/` (Keycloak-free,
hand-signed JWTs — confirmed the DLS templating mechanism works) and
`../opensearch_jwt/option_a_flat_claim/keycloak_mapper_research.md`
(source-verified the Keycloak-side mechanism: `oidc-usermodel-attribute-mapper`
reading a plain user attribute). This is the first time that design is run
against a **real** Keycloak-issued token instead of a hand-signed one.

## Versions (pinned, read from this repo)
- `quay.io/keycloak/keycloak:26.2` (`docker/docker-compose.dev.yml`)
- `opensearchproject/opensearch:2.11.1` (`poc/opensearch_jwt/README.md`)

## What this actually does
`run_poc.sh` starts a real Keycloak 26.2 (`kronos-poc-kcosdls-keycloak`,
port `18084`) importing `kronos-realm-poc.json` — which adds one new client
scope, `kronos-org-id` (`oidc-usermodel-attribute-mapper`, reading a plain
`org_id` user attribute, non-multivalued) — alongside the existing nested
`organization` scope (kept for comparison, not used for DLS). It provisions
**two real Organizations** via a step-3-extended copy of the repo's real
`scripts/provision_keycloak_org.sh` (`provision_keycloak_org.sh` in this
dir), with 3 real users: `user-a1`/`user-a2` in org A, `user-b1` in org B.
It brings up real OpenSearch 2.11.1 with security enabled, configures its
JWT authc domain to trust Keycloak's real signing key (same technique as
`../opensearch_jwt/run_poc.sh`), and creates the same **one** generic
`kronos-generic-tenant` DLS role + **one** static mapping as
`option_a_flat_claim/`. `run_poc.py` then does real password-grant logins
and real OpenSearch searches with the resulting real tokens.

## Two real bugs found and fixed before this worked (not anticipated from source-reading alone)

### Bug 1: `PUT /admin/realms/{realm}/users/{id}` is not a partial update
Confirmed empirically: a request body containing only
`{"attributes": {"org_id": ["..."]}}` returns `204` (looks successful) but
**silently clears the user's `firstName`, `lastName`, and `email`** —
confirmed via a direct before/after GET on a real user (see conversation
transcript / reproduce with the isolated `curl` sequence in this dir's
history). Keycloak's Declarative User Profile treats any profile-managed
field absent from the update body as "clear it," not "leave as-is." This
then made every real password-grant login fail with `invalid_grant:
"Account is not fully set up"` (the account's required `firstName`/
`lastName` were gone). **Fixed** in `provision_keycloak_org.sh`: GET the
current user representation first and splice the `attributes` object into
the fetched JSON text (rather than PUTing `attributes` alone), preserving
every other field. A fresh user never has a pre-existing `attributes` key
(confirmed via GET), so this is a correctness-preserving text splice, not a
fragile full JSON re-parse — safe for this script's actual real-world
provisioning pattern. Confirmed fixed: after the change, firstName/
lastName/email all survived and every real login succeeded (`output.txt`).

### Bug 2: `org_id` was silently dropped unless declared in the realm's User Profile
The first working attempt still failed — `org_id` never actually appeared
in `GET .../users/{id}` even though the PUT returned `204`. Root cause:
Keycloak 26's Declarative User Profile (enabled by default) only declares
`username`/`email`/`firstName`/`lastName` as managed attributes; any other
attribute sent via the admin API is silently accepted-but-dropped unless
explicitly declared. **Fixed**: `run_poc.sh` now calls
`PUT /admin/realms/kronos/users/profile` once, before any provisioning,
declaring `org_id` as an admin-only-editable (`view`/`edit`: `["admin"]`,
not `"user"`) managed attribute. Confirmed fixed: subsequent GETs show
`"attributes": {"org_id": ["<uuid>"]}` correctly.

Both bugs are genuinely orthogonal to the DLS design itself — they're
Keycloak Admin REST API mechanics that would bite *any* attempt to
provision a custom user attribute this way, not specific to org_id. Worth
carrying into whichever future code (the real `scripts/provision_keycloak_org.sh`,
or Helm provisioning) implements this for real.

## Result: 8/8 real checks passed (`output.txt`)
- Real password-grant logins succeeded for all 3 users against real Keycloak.
- `user-a1`'s real JWT carries a flat top-level `org_id` claim (not nested).
- `user-a2` (second member of org A) gets the identical flat `org_id` — same
  org, same value, with **zero individual OpenSearch-side provisioning**.
- `user-b1` (org B) gets a **different** flat `org_id`.
- Real `bulk_index()` (unmodified `src/adapter/opensearch/client.py`) indexed
  one doc per org.
- Real DLS search as each real token: `user-a1` and `user-a2` (org A) each
  see only `doc-org-a`; `user-b1` (org B) sees only `doc-org-b` — the exact
  same one-role/one-mapping design from `option_a_flat_claim/`, now proven
  against real Keycloak-issued tokens instead of hand-signed ones.

## What this confirms for the production fix (step 5, not done here)
The Option A design from `option_a_flat_claim/` is now verified end-to-end,
real Keycloak included:
- Keycloak-side: one new client scope (`kronos-org-id`) + one new managed
  User Profile attribute (`org_id`, admin-only) + one extra line in the
  existing per-membership provisioning call. No new trigger point.
- OpenSearch-side: **one** static role + DLS template, **one** static
  role-mapping, created once, ever — never per-org, never per-user.
- `ensure_tenant_role()`'s current per-org role-creation, and the still-missing
  rolesmapping call it never made (`../opensearch_jwt/README.md` result #3),
  can both be replaced by this simpler design.

Step 4 (`step4_new_member/`, done): proved a brand-new member added to an
**already-existing** real org, after OpenSearch is already fully configured,
gets correct DLS isolation with zero further `/_plugins/_security/*` calls
of any kind. Found two more real, orthogonal Keycloak REST gotchas along the
way (`POST /users` ignores a client-supplied `id`; `realmRoles` in the same
payload is also silently ignored) — see `step4_new_member/README.md`.

Not done here: porting these changes into the real
`scripts/provision_keycloak_org.sh` / `docker/keycloak/kronos-realm.json` /
`src/adapter/opensearch/client.py` (step 5).

## Files
- `kronos-realm-poc.json` — minimal PoC realm: 3 users, `kronos-org-id` scope
- `provision_keycloak_org.sh` — step-3-extended copy of the real
  `scripts/provision_keycloak_org.sh` (adds the org_id attribute splice)
- `run_poc.sh` — full reproducible bootstrap (OpenSearch + Keycloak + both
  orgs + user-profile schema fix) + `run_poc.py`
- `run_poc.py` — the actual verification, using the real `OpenSearchClient`
- `output.txt` — captured transcript of the last real run (8/8 passed)

## Cleanup
```bash
docker rm -f kronos-poc-kcosdls-opensearch kronos-poc-kcosdls-keycloak
```
