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

**Not resolved this pass**: `login.spec.ts`'s own final assertion
(`fetchDecodedAccessTokenClaims()`, a *second*, explicit
`/auth/refresh` call after the login flow already completed) got a real
401 `"Token refresh failed"` — reproduced twice, not flaky. Real
hypothesis: Keycloak refresh-token rotation racing the app's own internal
bootstrap refresh call. `login.spec.ts` has passed dozens of times this
session against `docker-compose.dev.yml` with no such failure — open
question whether this is specific to this fresh/cold test stack's timing
or a rare, real race that dev's warmer stack usually avoids by luck.
**Next step for whoever picks this up**: instrument
`src/external/routes/auth.py`'s `/auth/refresh` (or the Keycloak-side
token endpoint call it makes) to log real refresh-token-rotation events,
then reproduce against both stacks to compare timing, before concluding
which explanation is correct.

## What would still be needed to fold this into the shared file permanently

This PoC's port remaps (`15432`, `18443`, `19443`, etc.) are
**local-verification-only**, matching `poc/ci_security_enabled_stack/`'s
own established precedent — a real GitHub Actions runner has no
conflicting stack and would use `docker-compose.test.yml`'s own standard
ports, at which point the redirect_uri origin mismatch this PoC hit
disappears entirely (the shared realm file's `https://kronos.local/*`
already matches the standard port). A permanent version of this addition
to `docker-compose.test.yml` would need: the new `tls-init` service, the
`nginx` service rebuilt from `docker/Dockerfile.frontend` instead of
stock `nginx:alpine`, an `opensearch-dashboards` stub or a
`nginx-lan-https.conf.template` change to make that upstream optional,
and the `kronos-backend`/`celery-worker` Settings fields (`keycloak_url`,
`keycloak_client_secret`, `vault_url`, `vault_token`, `celery_broker_url`,
`celery_result_backend`) added for real — the last of these is arguably
the most valuable fix on its own, independent of the frontend work,
since it means `kronos-backend` has never fully booted in this file at
all until now.
