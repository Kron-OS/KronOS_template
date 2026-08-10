# PoC: Real-Keycloak verification for org-admin membership routes (Gap Audit P1-15 / Milestone V, item V5)

Verifies `src/external/routes/admin.py`'s `invite_user`/`update_user_role`/
`remove_user` against a real, running Keycloak 26.2 -- not the mocked
`httpx` `tests/unit/test_admin_routes.py` already exercises. CLAUDE.md §F's
verification-first bar (already applied to the six Q/R connectors and to
V3's OpenSearch-security/Keycloak-org stack) is applied here for the first
time to these three specific routes.

## Versions pinned (read from this repo, per CLAUDE.md §F.2 step 1)

- `quay.io/keycloak/keycloak:26.2` -- `docker/docker-compose.dev.yml`'s own
  pin; matches `docker-compose.test.yml` (V3's own pin).
- Real, unmodified `docker/keycloak/kronos-realm.json` realm import,
  already provisioned in the running dev stack (org `kronos-dev`, users
  `admin`/`analyst`/`case-lead`, `kronos-backend` confidential client with
  `serviceAccountsEnabled: true` and realm-management roles
  `manage-users`/`view-users`/`manage-realm`/`view-realm`).
- Real, unmodified `src/external/routes/admin.py` route handlers, called
  directly as coroutines (matching `tests/unit/test_admin_routes.py`'s own
  convention of bypassing FastAPI `Depends` wiring).

## Instance used, and why

The shared, already-running `docker-compose.dev.yml` stack's real Keycloak
(`docker-keycloak-1`, confirmed healthy via `docker ps`, reachable at
`http://localhost:8080` on this host) -- per this initiative's own standing
instructions ("it should already be up; use it directly"). A fresh
throwaway Keycloak was not needed. This instance already has the real
`kronos` realm imported and the real `kronos-dev` org provisioned
(`scripts/provision_keycloak_org.sh`, run by the `keycloak-init` compose
service) -- neither was touched by this PoC. Two throwaway orgs
(`kronos-v5-test-a`, `kronos-v5-test-b`) and their throwaway users were
created and fully deleted by this PoC's own fixtures (see
`tests/integration/test_admin_routes_real_keycloak.py`'s
`throwaway_orgs`/`org_b_member` fixtures) -- confirmed via a fresh Admin API
read after the run (`output.txt`, "Real cleanup verification" section).

## Real preconditions checked before writing anything (not assumed)

1. **Is the dev-stack Keycloak actually up and does it have the realm?**
   `curl http://localhost:8080/realms/kronos/.well-known/openid-configuration`
   -> 200.
2. **Can the `kronos-backend` service account (the one `admin.py`'s own
   `_get_service_account_token()` authenticates as) actually call the
   Organizations Admin API?** This was not obvious from a source read alone
   -- the realm.json only grants it `manage-users`/`view-users`/
   `manage-realm`/`view-realm`, none of which is named
   "manage-organizations". Tested directly (`output.txt`, "Real
   service-account permission check" section): a real client-credentials
   token for `kronos-backend` (secret `kronos-backend-secret`, matching
   `docker-compose.dev.yml`'s `KEYCLOAK_CLIENT_SECRET` default) genuinely
   lists organizations and reads org members with 200s. Confirms
   `manage-realm` is sufficient in Keycloak 26.2 for the Organizations
   endpoints this module depends on -- a real, previously-unverified
   assumption baked into every one of `admin.py`'s Keycloak calls.
3. **Does creating a throwaway org actually work the way
   `scripts/provision_keycloak_org.sh` implies (`domains: []` allowed)?**
   No -- first real attempt returned a real `400
   {"errorMessage":"You must provide at least one domain"}`. Every real
   org-creation call already in this repo (dev's `ORG_DOMAIN=kronos.dev`,
   V3's PoC `org-b.kronos-ci.test`) happens to always set one, so this path
   had never actually been exercised with `domains: []` despite the script
   nominally supporting it. Not a bug in `admin.py` (which never creates
   orgs), just this PoC's own fixture needing a real domain like every
   other real caller in the repo -- fixed by adding one.

## What was actually run (all captured in `output.txt`)

1. **`invite_user`**: created a brand-new user via the real route, then
   independently (via this PoC's own direct Admin API client, not the
   route's own helpers) confirmed real org-A membership, confirmed NOT
   linked to org B, confirmed the "analyst" realm role, and confirmed the
   `ORG_USER_INVITED` audit event by reading it back from a **fresh**
   `PostgresAuditLogRepository` connection (testcontainers Postgres, not the
   in-process object the route wrote through).
2. **`invite_user` cross-org negative case**: an org-A admin attempted to
   "invite" (reuse) an email that is a real member of org B only -- got a
   real 409, confirmed the org-B user's role/org-membership was untouched
   (AUTH-003/AUTH-011).
3. **`update_user_role`**: changed a real user's role, confirmed via a
   fresh Admin API read that the old managed role was removed and the new
   one persisted (not just present -- `_set_realm_role` is a set-replace,
   verified both directions), confirmed the `ORG_USER_ROLE_CHANGED` audit
   event read back fresh.
4. **`update_user_role` cross-org negative case**: org-A admin attempted to
   grant `org-admin` to the real org-B-only user -- real 403 from
   `_assert_user_in_org`, confirmed via a fresh Admin API read that the
   target's roles were completely unchanged, and confirmed no audit event
   was written for the rejected attempt.
5. **`remove_user`**: removed a real user's real org-A membership, confirmed
   via a fresh Admin API read that the org-membership link is gone.
   **Documented, not assumed**: the user's realm-level account (`GET
   /users/{id}`) still exists afterward -- `remove_user` only ever DELETEs
   `/organizations/{org}/members/{user}`, never `/users/{user}` itself.
6. **`remove_user` cross-org negative case**: org-A admin attempted to
   remove the real org-B-only user. The pytest assertion checks
   `status_code >= 400` and real non-removal; a separate standalone probe
   (`output.txt`, second section) captured the **exact** real value:
   `503` ("Keycloak Admin API returned server error"), because Keycloak's
   own real response to this DELETE against a non-member is a 404, and
   `_to_http_error()` only special-cases 400/409, falling through to the
   generic 503 branch for everything else including this real 404. The
   isolation guarantee genuinely holds (the org-B user remains a member of
   org B in both runs) -- this is a real, minor, non-security error-mapping
   imprecision, not a tenant-isolation bug, but worth a follow-up (flagged
   in `docs/GAP_AUDIT_2026-08.md`'s P1-15 V5 STATUS note).

**Result: 6/6 real pytest checks passed** against the real dev-stack
Keycloak (`output.txt`), plus the standalone cross-org-remove status-code
probe, plus real before/after cleanup verification confirming the shared
realm was left exactly as found (only the pre-existing `kronos-dev` org and
its three real users, plus one unrelated pre-existing `poc-h2-user-*`
account from an earlier, different milestone's PoC that this item did not
create and did not touch).

## Files

- `../../tests/integration/test_admin_routes_real_keycloak.py` -- the real,
  CI-shaped pytest suite (module-level-skips if Keycloak isn't reachable at
  `KRONOS_ADMIN_ROUTES_KC_BASE`, default `http://localhost:8080`, mirroring
  `test_security_enabled_stack.py`'s own skip convention). This *is* the
  PoC script for this item (CLAUDE.md §F.3 note: `poc/` doesn't require a
  separate throwaway script when the real automated test itself is the
  direct, real exercise of the integration -- this suite calls the real
  route handlers against the real Keycloak Admin REST API with zero mocks).
- `output.txt` -- captured transcript of the last real run (6/6 passed),
  the standalone cross-org-remove status-code probe, the pre-write
  service-account permission check, and the post-run cleanup verification.

## How to reproduce

```bash
# 1. Confirm the shared dev stack's Keycloak is up (it already should be):
docker ps | grep keycloak

# 2. Run the suite (defaults point at the shared dev-stack Keycloak):
pytest tests/integration/test_admin_routes_real_keycloak.py -v --no-cov

# Or against a different instance:
KRONOS_ADMIN_ROUTES_KC_BASE=http://some-other-keycloak:8080 \
  pytest tests/integration/test_admin_routes_real_keycloak.py -v --no-cov
```

## Cleanup

The suite's own `throwaway_orgs`/`org_b_member` fixtures delete every org
and user they create in teardown -- no manual cleanup step is needed. This
was independently re-verified (not assumed) via a fresh Admin API read
after the run (`output.txt`).
