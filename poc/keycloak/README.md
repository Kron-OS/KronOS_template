# PoC: real Keycloak 26.2 JWT/RBAC/multi-tenancy verification

## Component pair
`src/external/middleware/keycloak_auth.py` (`KeycloakTokenValidator.validate_and_extract`,
JWKS caching/refresh, `_extract_tenant`, `_map_roles`) and
`src/external/middleware/tenant_context.py` (`get_tenant_context`), run as the
actual classes/functions from `src/` — no reimplementation.

## Versions (pinned, read from this repo — not assumed)
- Keycloak: `quay.io/keycloak/keycloak:26.2`, exactly as pinned in
  `docker/docker-compose.dev.yml`. That file's comment: *"26.2 (not 26.0): the
  organization-id token claim (addOrganizationId) the backend's
  `_extract_tenant` requires only lands in 26.1+."* — confirmed true; see
  Finding 0 below.
- Realm: `docker/keycloak/kronos-realm.json` (copied verbatim to
  `kronos-realm-poc.json`, one deliberate PoC-only patch: `kronos-frontend`
  client's `directAccessGrantsEnabled` flipped `false -> true` so a real
  password-grant token can be obtained without standing up a browser/PKCE
  flow — the task brief explicitly allows this for verification purposes).
- Org provisioning: the repo's real `scripts/provision_keycloak_org.sh`, run
  unmodified against the containerized realm.
- `python-jose[cryptography]` `3.5.0`, `httpx` (both from `pyproject.toml`,
  installed in `~/venv`).

## What this actually does
`docker-compose.poc.yml` brings up Keycloak 26.2 (`kronos-poc-keycloak-server`,
host port `18080`) with `--import-realm`, then runs `keycloak-init`
(`kronos-poc-keycloak-init`) which execs the real
`scripts/provision_keycloak_org.sh` to create the `kronos-dev` Organization
via the real Admin REST API and link the three dev users
(admin/analyst/case-lead), exactly like the real dev stack does — because
Keycloak 26.2 cannot import an `organizations` block via `--import-realm`
(same limitation documented in `docker-compose.dev.yml`, confirmed by reading
`scripts/provision_keycloak_org.sh`'s own header comment).

```bash
cd poc/keycloak
docker compose -p kronos-poc-keycloak -f docker-compose.poc.yml up -d keycloak
# wait for healthy
docker compose -p kronos-poc-keycloak -f docker-compose.poc.yml up keycloak-init
cd ../..
~/venv/bin/python3 poc/keycloak/run_poc.py | tee poc/keycloak/output.txt
```

`run_poc.py` gets **real signed tokens** from Keycloak's own token endpoint
(password grant for `analyst`/`case-lead`, client-credentials for the
`kronos-backend` service account), then feeds them through the **real**
`KeycloakTokenValidator.validate_and_extract()` pointed at the real
`.../protocol/openid-connect/certs` JWKS endpoint, and the real
`get_tenant_context()` FastAPI dependency. Full captured output:
`output.txt`.

## Real findings

### Finding 0 (confirmed, not a bug): the 26.1+ organization-id claim requirement is real
Raw claims from a real analyst token (`output.txt`, step 1):
```json
"organization": { "kronos-dev": { "id": "d3978cec-b72b-4319-b33c-2b7736075b62" } }
```
`_extract_tenant()`'s assumption — `organization` is a dict keyed by org
*alias*, whose value is a dict with an `"id"` key — matches exactly what
Keycloak 26.2 actually emits with `addOrganizationId: true` on the
`oidc-organization-membership-mapper`. `org_id`/`org_alias`/`user_id`/`roles`
extracted by the real code were asserted equal to the raw claims
(`output.txt`, step 2) — genuinely verified working, not "follows the docs."

### Finding 1 (bug, fixed): audience check was a no-op for tokens with no `aud` claim at all
`KeycloakTokenValidator.validate_and_extract()` relied solely on
`jose.jwt.decode(audience=self._audience, options={"verify_aud": True, ...})`.
Isolated directly against python-jose `3.5.0` (`aud_bypass_isolated.txt`):

```
--- token with NO aud claim, decode(audience='kronos-backend') ---
SUCCEEDED (no exception): {'sub': 'x', 'iss': 'test'}

--- token with WRONG (present) aud claim, decode(audience='kronos-backend') ---
raised JWTClaimsError: Invalid audience
```

python-jose only enforces `audience=` when the token *has* an `aud` claim
with the wrong value; if `aud` is absent entirely, `verify_aud` is silently
skipped. Reproduced with a real token from this repo's own realm
(`aud_bypass_evidence.txt`): the `kronos-backend` service-account token
(client-credentials grant) carries no `aud` claim at all (no audience
mapper is configured on that client in `kronos-realm.json` — only
`kronos-frontend` has one), and before the fix, `validate_and_extract()`
decoded it successfully, failing closed only incidentally, at the later
`_extract_tenant()` step, because that particular service account happens
not to be an org member. Any real-Keycloak token sharing this realm's
signing key but lacking an `aud` claim — from a misconfigured client, a
future client, or a service account later added as an org member — would
have sailed straight past the intended audience restriction.

**Fixed** in `src/external/middleware/keycloak_auth.py`
(`validate_and_extract`): after `jwt.decode()`, explicitly check
`claims.get("aud")` against `self._audience` (handling both the string and
list-of-strings JWT `aud` forms) and raise `AuthenticationError` if it's
missing or doesn't match — instead of trusting jose's `verify_aud` alone.
Re-ran the same real service-account token afterward (`output.txt`, step 5):
```
Correctly rejected wrong-audience token: JWT audience claim missing or does not include 'kronos-backend'
```
now failing for the *correct* reason. All 20 pre-existing unit tests in
`tests/unit/middleware/test_keycloak_auth.py` still pass unchanged.

### Finding 2 (confirmed gap, not fixed — out of scope for this component pair): every real token has `username = "unknown"`
`_extract_tenant()` reads `claims.get("preferred_username", "unknown")`, and
every real token issued by this repo's `kronos-realm.json` hits the
fallback — `preferred_username` is never present. Root cause, confirmed via
the real Admin REST API (`GET
.../clients/{kronos-frontend}/default-client-scopes`): the client's assigned
default scopes are exactly `kronos-roles`, `acr`, `organization`,
`kronos-sub` — the realm's built-in `profile`/`email`/`roles`/`web-origins`
scopes (which is where `preferred_username` normally comes from) are never
attached to the client at all. This matches the `acr` client-scope
description's own comment in `kronos-realm.json` ("an explicit clientScopes
array suppresses Keycloak's built-in defaults") — expected Keycloak import
behavior, but it means `preferred_username` was never replaced by an
equivalent custom mapper the way `sub` was (via the `kronos-sub` scope).
This is a `docker/keycloak/kronos-realm.json` config gap, not a bug in
`keycloak_auth.py`/`tenant_context.py` (which correctly extract whatever is
actually in the claims) — flagged here per F.2, not fixed, since it's outside
this PoC's assigned component pair.

### Finding 3 (confirmed working): JWKS caching/refresh
`_JwksCache`/`_resolve_key`/`_refresh_jwks` genuinely fetch from the real
JWKS endpoint, not just from an initial cached load:
- An unknown `kid` correctly raises `AuthenticationError` after a real
  refresh attempt against the live JWKS endpoint (`output.txt`, step 3).
- After manually clearing the cached entry + `_fetched_at` for the real
  issuer/kid (`is_stale` confirmed `True`), `_resolve_key()` re-fetched the
  real key from the live JWKS endpoint and found it again
  (`kty=RSA, alg=RS256`).

### Finding 4 (confirmed working): expiry enforcement, with a caveat about the code's own 30s leeway
First pass used only a 3s sleep after minting a 1s-lifespan token and the
"expired" token was accepted — **not a code bug**: `validate_and_extract`
intentionally applies `_CLOCK_SKEW_SECONDS = 30` leeway, so a token only
~3s past its `exp` is still legitimately valid per the code's own tolerance.
Corrected test: 2s lifespan + a 40s sleep (clearing lifespan + leeway)
against the real server correctly raised `AuthenticationError: JWT has
expired` (`output.txt`, step 4).

### Finding 5 (confirmed working): role mapping
Real `roles` claims (`["analyst"]`, `["case-lead"]`) from real tokens for
the `analyst` and `case-lead` dev users were correctly mapped by
`_map_roles()`/`_extract_tenant()` to `Role.ANALYST` /
`Role.CASE_LEAD` — verified via `get_tenant_context()` (the actual FastAPI
dependency, with a stubbed `request.app.state.keycloak_validator`), not just
`validate_and_extract()` directly (`output.txt`, step 6).

## Gaps / not covered
- PKCE/authorization-code flow itself was not exercised (password grant was
  used per the task brief, deliberately enabling ROPC on a PoC-only realm
  copy) — this PoC verifies token *validation*, not the frontend's token
  *acquisition* flow.
- `rbac.py`'s `@requires_role` decorator and query-isolation middleware were
  not exercised here — out of scope for this component pair.
- Finding 2 (missing `preferred_username`) is flagged, not fixed — it's a
  realm-config issue, not in the two files this PoC targets.

## Cleanup
```bash
cd poc/keycloak
docker compose -p kronos-poc-keycloak -f docker-compose.poc.yml down -v
```
Containers used: `kronos-poc-keycloak-server`, `kronos-poc-keycloak-init`
(host port `18080`), per the `kronos-poc-keycloak-` naming convention to
avoid colliding with parallel subagents' containers.
