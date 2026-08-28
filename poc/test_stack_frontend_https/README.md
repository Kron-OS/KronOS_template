# PoC: wire `frontend/e2e/` against `docker-compose.test.yml`

**Scope:** docs/PLAYWRIGHT_E2E_TEST_PLAN.md §4 / docs/GAP_AUDIT_2026-08-28_MILESTONE_GGG.md's
own re-scoped remaining work. `docker-compose.test.yml`'s `nginx` service
never builds/serves the frontend SPA (API-proxy-only) and has no
`kronos.local`/TLS scaffolding. Decisive finding that settled the
plain-HTTP-vs-TLS question first (see commit history same day): the
backend's refresh-token cookie is hardcoded `secure=True`
(`src/external/routes/auth.py`) — plain HTTP is **not viable at all**,
not a preference. Real TLS is mandatory.

## Versions / real files reused, not re-derived (CLAUDE.md §F.2 step 1)

- `docker/nginx/nginx-lan-https.conf.template` — the real, already
  production-proven multi-port TLS-termination template
  (`poc/tls_lan_https/`), already baked into every image built from
  `docker/Dockerfile.frontend`. Reused verbatim; not modified.
- `docker/Dockerfile.frontend` — same real Dockerfile
  `docker-compose.dev.yml`'s own `nginx` service builds.
- Cert path `/etc/kronos/tls/{server.crt,server.key}` — fixed, hardcoded
  in the template; a throwaway self-signed cert (SAN=`kronos.local`,
  matching dev's real, reproduced finding that `kronos.local` must be the
  *only* SAN — `poc/tls_lan_https/README.md`) is generated locally rather
  than running a second step-ca instance (unnecessary complexity for a
  CI/test-only profile — `frontend/e2e/playwright.config.ts` already sets
  `ignoreHTTPSErrors: true` globally, so cert *validity* was never going
  to matter here, only that HTTPS is genuinely served).
- Port-remap pattern reused verbatim from
  `poc/ci_security_enabled_stack/docker-compose.override.yml` (same host,
  same live-dev-stack port collision, same `!override` tag requirement
  for Compose's list-concatenation merge behavior).

## What this PoC does

`docker-compose.override.yml` here, layered on top of the real
`docker-compose.test.yml`:
1. Remaps every base-service host port (same offsets as
   `ci_security_enabled_stack`, extended to cover `kronos-backend`).
2. Adds a `tls-init` one-shot service generating a real, throwaway
   self-signed cert into a named volume.
3. Rebuilds `keycloak` with `KC_HOSTNAME`/`KC_PROXY_HEADERS`/
   `KC_HOSTNAME_BACKCHANNEL_DYNAMIC` pointed at the remapped
   `https://kronos.local:<port>` origin (mirrors dev's own real,
   already-proven config).
4. Replaces `nginx` entirely: builds `docker/Dockerfile.frontend` (real
   `VITE_KEYCLOAK_URL` build arg for the remapped origin) instead of the
   base file's stock `nginx:alpine`, mounts the generated cert, sets the
   same `KEYCLOAK_PUBLIC_URL`/`BACKEND_PUBLIC_URL` env vars dev's own
   `nginx` service sets (remapped ports).

Run: `run_poc.sh`. Tears down its own isolated `kronos-poc-fe-tls`
project afterward; never touches the live dev stack (verified via
`docker ps` before/after, same discipline as every PoC this initiative
has run).

See `output.txt` for the full real captured run, including five real
bugs/gaps found and fixed along the way (missing `opensearch-dashboards`
upstream, wrong Keycloak public port, redirect_uri origin mismatch,
missing `kronos-backend` Settings fields at both startup AND per-request
in `/auth/refresh`).

## Result: mostly proven, one open item

**Proven for real**: `frontend/e2e/`'s real PKCE login flow, real Cases
navigation, and real Detections navigation all work end-to-end against
`docker-compose.test.yml` once genuinely served over real HTTPS at
`kronos.local` with a real, complete backend `Settings()`. The answer to
this PoC's own question ("can `frontend/e2e/` run against this profile at
all") is **yes**, with the concrete fixes above.

**[RESOLVED, Milestone III, same day]** `login.spec.ts`'s own final
assertion had gotten a real 401 `"Token refresh failed"` on this PoC's
test stack, reproduced twice, not flaky. Root-caused for real rather than
left as a hypothesis: forced two concurrent bare `fetch('/auth/refresh',
{credentials:'include'})` calls in a real browser against the (fast,
already-running) **dev** stack — reproduced the identical race on demand,
every time (one real 200, one real 401), proving this was never a
cold-stack timing artifact. Real cause: `api/client.ts`'s 401 interceptor
and `keycloak.ts`'s own `scheduleSilentRefresh` timer are two
independent, uncoordinated callers of `refreshAccessToken()` — if both
fire close together, each sends the browser's current cookie to Keycloak
independently, and Keycloak's real refresh-token rotation accepts exactly
one. The loser previously read this as "session actually invalid" and
forced the user through a full, unwanted re-login. Fixed with a
module-level single-flight promise in `keycloak.ts` shared by every
caller of `refreshAccessToken()`. Verified two ways: a new Vitest test
(`refreshAccessToken shares one in-flight request across concurrent
callers`) locks in the exact mechanism, and the full six-spec
`frontend/e2e/` suite stayed green. See
`docs/GAP_AUDIT_2026-08-28_MILESTONE_III.md` for the full account.

## [RESOLVED, Milestone JJJ] Folded into `docker-compose.test.yml` permanently

`tls-init`, the `nginx` rebuild (`docker/Dockerfile.frontend`), and the
`opensearch-dashboards` stub are now the real, shared
`docker/docker-compose.test.yml` — no longer PoC-only. Two more real bugs
were found and fixed while re-verifying this fold-in, both the kind
Section F exists to catch (looked right, weren't run against the real
dependency until now):

**Bug 1 — a verification-harness artifact, not a product bug, but it cost
real debugging time and is worth recording so it isn't re-hit.** Doing the
isolated re-verification with every port remapped (`19443:8443` etc.,
this PoC's own established pattern) made Keycloak embed the WRONG port in
its own `iss`/redirect URLs: `KC_PROXY_HEADERS=xforwarded` makes Keycloak
trust nginx's `X-Forwarded-Port`, but nginx's template sends `$server_port`
— the CONTAINER port (8443), not the externally-remapped host port
(19443). The real `docker-compose.test.yml` maps `8443:8443` 1:1, so this
can never happen there; it's an artifact of remapping only the host side
for local collision-avoidance. Real, reproduced symptom: Keycloak's own
"We are sorry... An error occurred" page after form submit.

**Fix for re-verifying against an isolated stack without this artifact,
without touching the live dev stack's ports at all**: don't remap nginx's
own ports/env — leave them exactly as the real file declares (`8443:8443`
etc.) and reach nginx via its own Docker bridge IP directly (`docker
inspect <nginx-container> --format '{{...IPAddress}}'`), never through a
host-published port. For a real browser (Playwright, running on the host,
not in a container) to resolve `kronos.local` to that container IP without
touching global `/etc/hosts` (already pointed at the live dev stack's own
`kronos.local`), Chromium's `--host-resolver-rules=MAP kronos.local <ip>`
launch arg scopes the override to just that one browser process. See
`verify_login_container_network.mjs` in this directory — a throwaway
script (not the real suite) that drives the exact `login.spec.ts` steps
this way; kept as the reusable pattern for any future re-verification of
this profile without a second `/etc/hosts` edit or a live-stack port
collision.

**Bug 2 — a real, previously-undiscovered product bug**, found via that
same container-network re-run: `kronos-backend`'s `/auth/refresh`
real REFRESH_TOKEN_ERROR "Invalid token issuer. Expected
'http://keycloak:8080/realms/kronos'" — with `KC_HOSTNAME` deliberately
left unset (Milestone III's own reasoning at the time, since superseded),
Keycloak derives `iss` per-request from whichever Host reached it. A
browser-minted refresh token (`iss=kronos.local:8443`, via nginx) was then
rejected when `kronos-backend` redeemed it through the internal
`keycloak:8080` short-circuit (`iss=keycloak:8080`) — exactly the class of
bug `docker-compose.dev.yml`'s own `KC_HOSTNAME` comment already
documented, just never actually hit in this profile before because nginx
never proxied real browser traffic to it here until this fold-in.

**Fix**: pinned `KC_HOSTNAME`/`KC_HOSTNAME_BACKCHANNEL_DYNAMIC` on
`docker-compose.test.yml`'s `keycloak` service, mirroring dev's own
already-proven config exactly. This reintroduced the *other* real risk
Milestone III's reasoning had correctly flagged (and is why KC_HOSTNAME
was left unset in the first place): `tests/integration/
test_security_enabled_stack.py` and `poc/ci_security_enabled_stack/
verify_security_stack.py` both construct their `KeycloakTokenValidator`
with `issuer=f"{KC_BASE}/realms/kronos"`, assuming `KC_BASE` (a direct,
unproxied `http://localhost:8080` in CI) equals the token's `iss` — no
longer true once `iss` is pinned to `kronos.local:8443` regardless of
which door reached Keycloak. Fixed at the source in both files: read the
real issuer from Keycloak's own `/.well-known/openid-configuration`
document instead of assuming it equals `KC_BASE` — correct whether or not
`KC_HOSTNAME` is pinned, present or future.

**Verified for real, in this order**, all against the real fold-in (not
a re-remapped throwaway compose file):
1. `verify_login_container_network.mjs` (real Chromium, real PKCE flow,
   real Keycloak hosted form) — landed authenticated, `/auth/refresh`
   bootstrap `200`.
2. The real `npx playwright test e2e/login.spec.ts` (unmodified spec,
   temporarily launched with the same `--host-resolver-rules` override,
   reverted immediately after) — 1 passed, including the token-claims
   assertion (`fetchDecodedAccessTokenClaims`) that exercises
   `/auth/refresh` a second time.
3. `poc/ci_security_enabled_stack/verify_security_stack.py` (real
   password-grant logins, real `KeycloakTokenValidator`, real OpenSearch
   DLS isolation) against the SAME pinned-`KC_HOSTNAME` isolated stack —
   11/11 checks passed.
4. The real pytest suite, `tests/integration/test_security_enabled_stack.py`
   — 3/3 passed.

Both real consumers of this Keycloak instance (real browser E2E via
nginx, and the direct-`:8080` pytest/PoC suite) now coexist correctly on
one shared, pinned-`KC_HOSTNAME` Keycloak service. See
`docs/GAP_AUDIT_2026-08-28_MILESTONE_JJJ.md` for the full account.
