# Gap Audit — Milestone HHH (2026-08-28)

**Scope:** continuation of the frontend↔backend connectivity initiative,
following directly from Milestone GGG's re-scoped remaining work: wiring
`frontend/e2e/` to run against `docker-compose.test.yml`. Decisive
question answered first (settles the file's whole design direction), a
new PoC built and run for real, one significant separate bug found and
fixed in the shared file, and one precise open item handed off.

---

## Part 1 — The plain-HTTP-vs-TLS decision, settled with evidence

Checked the actual code rather than debating preference:
`src/external/routes/auth.py`'s refresh-token cookie is unconditionally
`secure=True` (no environment branch). A `Secure` cookie is never sent by
a browser over plain HTTP. **Plain HTTP is not viable for this app at
all** — not a design preference, a hard constraint. This settles Milestone
GGG's own "plain-HTTP-vs-TLS decision... it gates the rest": real TLS
scaffolding is mandatory for `docker-compose.test.yml` to ever serve a
usable frontend session.

## Part 2 — `poc/test_stack_frontend_https/`: real, run, five bugs found and fixed

Built and ran a real PoC (isolated `kronos-poc-fe-tls` Compose project,
port-remapped, never touching the live dev stack) reusing real,
already-proven files rather than inventing new ones:
`docker/nginx/nginx-lan-https.conf.template` (already baked into every
`docker/Dockerfile.frontend` build), a throwaway self-signed cert
(`ignoreHTTPSErrors: true` already set globally in
`frontend/playwright.config.ts`, so cert validity was never going to
matter — only that HTTPS is genuinely served), and the same
`!override`-tagged port-remap pattern `poc/ci_security_enabled_stack/`
already established.

Five real, independent bugs found and fixed along the way, each verified
by actually running it and reading the real output, not assumed:

1. **`docker-compose.test.yml`'s `nginx` never builds/serves the frontend
   at all** (API-proxy-only stock `nginx:alpine`) — already known from
   Milestone GGG; this PoC is the first attempt to actually close it.
2. **`nginx-lan-https.conf.template` (real, shared, unmodified) statically
   `proxy_pass`es to `opensearch-dashboards:5601`**, and nginx fails HARD
   at config-parse time if that hostname doesn't resolve at all — not
   just at request time. `docker-compose.test.yml` has no such service.
   Fixed *for this PoC only* with a minimal DNS-resolvable stub, not the
   real (heavy, unneeded) Dashboards image.
3. **`KC_HOSTNAME`/`VITE_KEYCLOAK_URL`/etc. all pointed at the same port as
   the frontend** — but `nginx-lan-https.conf.template` routes Keycloak
   through its own, separate `:8443` server block. Real `"Not Found"`
   until fixed by publishing that port distinctly and repointing every
   Keycloak-public-URL reference at it.
4. **Real `400 Invalid redirect_uri`** — `kronos-realm.json`'s
   `kronos-frontend` client only allows the origin `https://kronos.local`
   (implicit port 443); this PoC's local-only port remap doesn't match.
   Confirmed this is a *local-verification-only* artifact (a real GitHub
   Actions runner has no conflicting stack and would use the file's own
   standard ports, where this mismatch doesn't exist) — fixed for the
   isolated instance only via a live Admin REST client-config PUT, the
   same class of post-import patch `keycloak-init` itself already does
   for organizations. The shared `kronos-realm.json` was never touched.
5. **The real payoff finding, promoted to a permanent fix (Part 3
   below)**: `kronos-backend` never fully wired up in this file at all.

After all five fixes: real PKCE login, real Cases navigation, and real
Detections navigation all passed against `docker-compose.test.yml`,
served over genuine HTTPS at `kronos.local`. Full account, including the
exact commands and captured output for each step:
`poc/test_stack_frontend_https/output.txt`.

## Part 3 — Promoted to a real, permanent fix: `kronos-backend`/`celery-worker` had never fully booted in this file

While chasing bug 5 above, found that `docker-compose.test.yml`'s
`kronos-backend` and `celery-worker` were missing six fields
`src/config.py::Settings` requires with no default:
`keycloak_url`, `keycloak_client_secret`, `vault_url`, `vault_token`,
`celery_broker_url`, `celery_result_backend`. Two distinct real severities:

- `kronos-backend`: `wire_dependencies_async()` catches the validation
  failure and logs a **warning**, not a crash — Uvicorn boots anyway, so
  nothing that only checks "did the container start" would ever catch
  this. But `src/external/routes/auth.py`'s `/auth/refresh` instantiates
  a **fresh `Settings()` per request**, not just at startup — so this
  wasn't a cosmetic gap, it was a genuine, reproduced 500 on every real
  token refresh (confirmed live: real login succeeded, real "case-lead"
  header rendered, but the Cases list spun forever because the app's own
  refresh call 500'd).
- `celery-worker`: `celery_app.py` instantiates `Settings()` at **import
  time** — this worker could never boot in this file at all, full stop.

This is real, separate, valuable, and **unrelated to whether the
frontend-TLS work above is ever fully folded in** — nothing in the
existing `.github/workflows/security-integration-tests.yml` starts either
service, so nothing was silently relying on the broken state, but any
*future* test that does would have hit this immediately. **Fixed directly
in the shared `docker-compose.test.yml`** (not just the PoC override):
`keycloak_url`/`keycloak_client_secret` point at the file's own real
`keycloak`/`keycloak-init` services; `celery_broker_url`/`result_backend`
reuse the real `redis` already present (DB1/DB2, matching
`docker-compose.dev.yml`'s pre-DB-role-split convention — this file has
no dedicated Celery redis instance); `vault_url`/`vault_token` are
syntactically-valid placeholders — this file has no real Vault service at
all (unlike `docker-compose.dev.yml`, which optionally layers in
`docker/vault/docker-compose.vault.yml`), and confirmed live that nothing
in a login/auth-only flow actually calls Vault. **Documented honestly,
not glossed over**: a future test exercising real evidence-upload/
encryption flows against this file would need the real Vault service
added, not this placeholder.

**Verified live, isolated, real** (reusing `poc/ci_security_enabled_stack/`'s
own proven port-remap pattern, separate from the frontend-TLS PoC):
both `kronos-backend` and `celery-worker` now boot with clean
`"startup: dependencies wired"` logs (previously: 4-6 validation errors
each), and `POST /auth/refresh` with no cookie now correctly returns
`401 "No refresh token cookie"` instead of `500`. Teardown confirmed
clean; live dev stack untouched throughout (`docker ps`: 15 containers,
unchanged before/after).

## Part 4 — What's still open

`poc/test_stack_frontend_https/`'s own remaining item, **not resolved
this pass**: `login.spec.ts`'s final assertion
(`fetchDecodedAccessTokenClaims()`, a second explicit `/auth/refresh`
call after the login flow already completed) got a real, reproduced
(twice, not flaky) `401 "Token refresh failed"`. Real hypothesis, not yet
confirmed: Keycloak refresh-token rotation racing the app's own internal
bootstrap refresh call. `login.spec.ts` has passed dozens of times this
session against `docker-compose.dev.yml` with no such failure — open
question whether this is a timing artifact specific to this fresh/cold
test stack, or a rare, real race the warmer dev stack usually avoids by
luck. Full detail and a concrete next-debugging-step in
`poc/test_stack_frontend_https/README.md`'s own "Result" section.

Also still open, unchanged from Milestone GGG: making this a *permanent*
addition to `docker-compose.test.yml` (the `tls-init`/`nginx`-build/
`opensearch-dashboards`-stub pieces are proven in the PoC but not yet
folded into the shared file — deliberately deferred until the refresh-token
race above is understood, since folding in a still-flaky flow would be
premature).

## Recommendation for the next cycle

1. Debug the refresh-token race — instrument `/auth/refresh` (or the
   Keycloak token-endpoint call it makes) to log rotation events, then
   reproduce against both stacks to compare timing.
2. Once understood, fold the proven `tls-init`/`nginx`-build pieces from
   `poc/test_stack_frontend_https/` into the real `docker-compose.test.yml`
   permanently, and wire at least a smoke-tier `frontend/e2e/` spec into
   `.github/workflows/security-integration-tests.yml`.
3. Otherwise, Milestone EEE's still-open maintainability findings (suite
   runtime scaling, TS+Python toolchain consolidation) or
   `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain available.
