# Gap Audit — Milestone JJJ (2026-08-28)

**Scope:** closes Milestone III's own recommendation #1 — fold
`poc/test_stack_frontend_https/`'s proven `tls-init`/`nginx`-build/
`opensearch-dashboards`-stub pieces into the real
`docker/docker-compose.test.yml` permanently. Two real, previously-latent
bugs were found and fixed while re-verifying the fold-in for real, per
CLAUDE.md §F.

---

## What changed in `docker/docker-compose.test.yml`

- New `tls-init` one-shot service: generates a real, throwaway self-signed
  cert (SAN=`kronos.local`) into a named volume (`fe_tls_certs`).
- New `opensearch-dashboards` stub (`nginx:alpine`) — nginx's shared
  `nginx-lan-https.conf.template` needs *an* upstream on that hostname to
  parse at all; a real SSO-integrated Dashboards service was judged
  disproportionate for this profile's stated CI/backend-integration-testing
  purpose (unchanged from Milestone HHH's original scoping decision).
- `nginx` service rebuilt from `docker/Dockerfile.frontend` (real frontend
  SPA + `nginx-lan-https.conf.template`) instead of stock `nginx:alpine`,
  standard ports `80`/`443`/`8443`, real `KEYCLOAK_PUBLIC_URL`/
  `BACKEND_PUBLIC_URL` env.
- `kronos-backend`: removed two DEAD env vars, `KEYCLOAK_ISSUER` and
  `KEYCLOAK_JWKS_URL` — confirmed by reading `src/external/fastapi_app.py`
  that neither name is read anywhere; the real bootstrap reads
  `KEYCLOAK_PUBLIC_URL`/`KEYCLOAK_URL` via `os.getenv()`. This means
  `kronos-backend`'s JWT validation in this profile was never correctly
  configured by these vars at any point before this fix.
- `keycloak`: **`KC_HOSTNAME` pinned** to `https://kronos.local:8443`,
  plus `KC_PROXY_HEADERS: xforwarded` and
  `KC_HOSTNAME_BACKCHANNEL_DYNAMIC: "true"` — mirrors
  `docker-compose.dev.yml`'s own already-proven config exactly. See "Bug 2"
  below for why this reverses Milestone III's original "leave it unset"
  decision.

## Bug 1: a verification-harness artifact (not a product bug)

Re-verifying the fold-in with every port remapped to avoid colliding with
this host's live dev stack (the same pattern every prior PoC cycle has
used) made Keycloak embed the **wrong port** in the `iss`/redirect URLs it
returned: `KC_PROXY_HEADERS=xforwarded` makes Keycloak trust nginx's
`X-Forwarded-Port`, but nginx's shared template sends `$server_port` — the
*container* port (`8443`), not whatever host port it happened to be
remapped to (`19443`). The real `docker-compose.test.yml` maps `8443:8443`
1:1, so this can never actually happen there — it's purely an artifact of
remapping only the host side for local collision-avoidance.

**Real, reproduced symptom**: Keycloak's own "We are sorry... An error
occurred, please login again through your application" page after
submitting the real hosted login form — a second, different-looking
failure from Milestone III's earlier "plain HTTP sent to HTTPS port" 400,
which had already been fixed by `KC_PROXY_HEADERS`. Traced via the actual
`iss` value embedded in Keycloak's own redirect response
(`iss=https%3A%2F%2Fkronos.local%3A8443...` while the browser was actually
on `:19443`) — confirmed by direct `curl` against Keycloak's `/auth`
endpoint through the remapped port, not assumed.

**Fix for future re-verification**: don't remap nginx's own ports/env at
all for an isolated re-verification stack — leave them exactly as the real
file declares, and reach nginx via its Docker bridge container IP
directly (`docker inspect <container> --format '{{...IPAddress}}'`)
instead of a host-published port. For a real browser running on the host
(Playwright) to resolve `kronos.local` to that IP without touching the
host's global `/etc/hosts` (already pointed at the live dev stack's own
`kronos.local` — editing it would be an unscoped change to a shared
resource), Chromium's `--host-resolver-rules=MAP kronos.local <ip>` launch
arg scopes the DNS override to just that one browser process, no host
config touched. Captured as a reusable throwaway script,
`poc/test_stack_frontend_https/verify_login_container_network.mjs`, for
any future re-verification of this profile.

## Bug 2: a real, previously-undiscovered product bug

That same container-network re-run surfaced a second, **real** failure:
`kronos-backend`'s `/auth/refresh` endpoint returned `401` on the bootstrap
call that follows a fresh login. Keycloak's own logs showed the actual
cause directly, not inferred:

```
type="REFRESH_TOKEN_ERROR" ... error="invalid_token"
reason="Invalid token issuer. Expected 'http://keycloak:8080/realms/kronos'"
```

With `KC_HOSTNAME` deliberately left unset (Milestone III's own reasoning,
made in good faith at the time but incomplete — it verified the login
*redirect* worked, not the backend's subsequent refresh-token redemption),
Keycloak derives `iss` per-request from whichever Host actually reached
it. A browser-minted refresh token carries `iss=kronos.local:8443` (it
went through nginx); `kronos-backend`'s own `/auth/refresh` redeems that
token by calling Keycloak directly via the internal `keycloak:8080`
short-circuit (`settings.keycloak_url`, `src/external/routes/auth.py`),
which arrives with no forwarded headers at all and gets `iss=keycloak:8080`
— a real, hard issuer mismatch. Keycloak correctly rejects it. This is
exactly the class of bug `docker-compose.dev.yml`'s own `KC_HOSTNAME`
comment already documented; it just had never actually been hit in the
*test* profile before, because nginx never proxied real browser traffic to
it there until this fold-in.

**Fix**: pinned `KC_HOSTNAME` (+ `KC_PROXY_HEADERS` + the already-present
`KC_HOSTNAME_BACKCHANNEL_DYNAMIC` for consistency with dev), mirroring the
dev stack's own proven config exactly rather than re-deriving a new
solution.

### The fix this reopened, fixed at the source instead of avoided

Pinning `KC_HOSTNAME` reintroduces the *other* real risk Milestone III's
original comment correctly flagged (and the reason it left `KC_HOSTNAME`
unset in the first place): `tests/integration/test_security_enabled_stack.py`
and `poc/ci_security_enabled_stack/verify_security_stack.py` both
construct their `KeycloakTokenValidator` with
`issuer=f"{KC_BASE}/realms/kronos"`, where `KC_BASE` is a direct,
unproxied `http://localhost:8080` in CI (`KRONOS_SECURITY_STACK_KC_BASE`,
`.github/workflows/security-integration-tests.yml`). That assumed
`KC_BASE == iss`; with `iss` now pinned to `kronos.local:8443` regardless
of which door reached Keycloak, the assumption breaks.

**Fixed in both files** (kept in sync per the existing convention): read
the real issuer from Keycloak's own `/.well-known/openid-configuration`
document instead of assuming it equals `KC_BASE`:

```python
_ISSUER = httpx.get(
    f"{_KC_BASE}/realms/{_REALM}/.well-known/openid-configuration", timeout=15.0
).json()["issuer"]
```

This is correct regardless of whether `KC_HOSTNAME` is pinned, now or in
the future — a more robust fix than either leaving `KC_HOSTNAME` unset
(which breaks the browser/backend refresh path) or hardcoding the pinned
value into the test (which would silently rot if the pinned value ever
changes).

## Verification (CLAUDE.md §F — actually run, output inspected)

All four steps run against the **same** isolated, pinned-`KC_HOSTNAME`
stack (project `kronos-poc-test-full`, torn down after), confirming both
real consumers of this one shared Keycloak instance now coexist correctly:

1. `verify_login_container_network.mjs` — real Chromium via
   `--host-resolver-rules`, real PKCE flow, real Keycloak hosted form:
   landed authenticated on `/cases`, `POST /auth/refresh` bootstrap `200`
   (confirmed via `kronos-backend`'s own access log, not just the browser
   console).
2. The real, unmodified `npx playwright test e2e/login.spec.ts` — 1
   passed, including `fetchDecodedAccessTokenClaims()` (which exercises
   `/auth/refresh` a second time, independently from the bootstrap call —
   this is the exact assertion that failed before either fix).
   Cross-checked via the isolated stack's own nginx access log (client IP
   on the Docker bridge, not the host LAN) to rule out the run silently
   hitting the live dev stack instead — an actual near-miss this same
   pass: an earlier attempt without the `--host-resolver-rules` override
   silently passed against the live dev stack via normal `/etc/hosts`
   resolution, which would have been a false positive if not caught and
   discarded.
3. `poc/ci_security_enabled_stack/verify_security_stack.py` (real
   password-grant logins for two orgs, real `KeycloakTokenValidator`, real
   OpenSearch DLS isolation) — 11/11 checks passed against the same
   pinned-`KC_HOSTNAME` stack.
4. The real pytest suite, `tests/integration/test_security_enabled_stack.py`
   — 3/3 passed (`--no-cov`; the repo-wide 80% coverage gate isn't
   meaningful when running one integration file in isolation).

Isolated stack torn down (`down -v --remove-orphans` + built-image
cleanup); live dev stack (`docker ps`, project `docker`) confirmed
untouched throughout, before and after.

## Status

Milestone III's recommendation #1 is now complete: the TLS/frontend-build
work is folded into the shared `docker-compose.test.yml` permanently, not
just proven in a PoC override. Two real bugs (the dead env vars, and the
KC_HOSTNAME/refresh-issuer mismatch) were found and fixed along the way —
neither was hypothetical, both were reproduced live and root-caused from
real Keycloak/nginx logs before being fixed.

## Recommendation for the next cycle

1. Wire at least a smoke-tier `frontend/e2e/` spec (e.g. `login.spec.ts`)
   into `.github/workflows/security-integration-tests.yml`, per Milestone
   III's own original recommendation #1 — now unblocked, since the profile
   it would run against is proven working end-to-end. Needs: the frontend
   image build step, `kronos.local` DNS resolution on the CI runner
   (`--host-resolver-rules` or an `extra_hosts` entry, not a global
   `/etc/hosts` edit, matching this milestone's own finding about not
   touching shared DNS state), and TLS-error tolerance
   (`ignoreHTTPSErrors`, already set).
2. Otherwise, `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards
   embed, resilience, a11y/visual) or Milestone EEE's still-open
   maintainability findings (suite runtime scaling, TS+Python toolchain
   consolidation, multi-tab session gap) remain available.
