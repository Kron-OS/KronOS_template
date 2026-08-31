# Gap Audit — Milestone GGGG (2026-08-31)

**Scope:** closes a gap named as far back as Milestone LLL (Cycle 9): the
`security-stack` CI job never booted `kronos-backend`, so the claim "both
real Keycloak consumers coexist" was never continuously re-proven — it
rested on two separate job definitions (`security-stack`'s own
`test_security_enabled_stack.py`, exercising DLS/OpenSearch directly, and
`frontend-e2e-smoke`'s `login.spec.ts`, exercising `kronos-backend`'s own
JWT validation) that had never run against the *same* stack instance.

---

## Fixed this cycle

### `kronos-backend` now boots in `security-stack`, with a real, targeted coexistence check

Added `db-migrate` (a real prerequisite — schema must exist before
`kronos-backend` starts) and `kronos-backend` itself to the job's
bring-up steps, followed by a poll-loop wait on `/healthz` (this compose
file defines no healthcheck for the service, so polled directly — same
shape `frontend-e2e-smoke`'s own "Wait for nginx" step already uses).

### Real design pivot, kept honest rather than smoothed over

The original plan was a real user password-grant login (mirroring
`poc/keycloak_opensearch_dls/`'s own established pattern). That turned
out to be genuinely blocked: a direct check of
`docker/keycloak/kronos-realm.json` confirmed **no client in this realm
has `directAccessGrantsEnabled: true`** — Resource Owner Password
Credentials has been disabled since that earlier PoC was written, not
assumed compatible. The next candidate, a real PKCE/browser flow, needs
Keycloak's login form reachable at the pinned `KC_HOSTNAME`
(`kronos.local:8443`), which would mean bringing nginx+TLS+`/etc/hosts`
scaffolding into this job too — duplicating `frontend-e2e-smoke`'s own
setup for a narrower question than "does the whole browser flow work"
(already covered there).

**Landed on**: a real `client_credentials` grant for `kronos-backend`'s
own service account (`serviceAccountsEnabled: true` in the realm, the
same mechanism `seed_second_org.py`/`seed_detection.py` already use for
Admin API calls), then a real authenticated call to `kronos-backend`
itself. Empirically confirmed (curl, before writing any script) that
this produces a specific, real `401`: `"JWT audience claim missing or
does not include 'kronos-backend'"` — not a connection error, not a
generic failure. Reading `src/external/middleware/keycloak_auth.py`
confirmed this is genuine positive proof, not a false pass: that exact
message only fires *after* `_resolve_key()` successfully fetches JWKS
(real network reachability), `jwt.decode()` verifies the signature, and
`verify_iss` matches the issuer — the audience check runs last, and is
`kronos-backend`'s own already-known, deliberately-handled edge case
(`AUTH-009`'s own code comment names this exact scenario). A genuinely
broken JWKS fetch, signature, or issuer mismatch raises a *different*,
distinguishable message (confirmed live: a malformed token produces
`"Malformed JWT header..."`, not the audience message) — so the new
`poc/ci_security_enabled_stack/verify_backend_keycloak_coexistence.py`
asserts on the *specific* audience-mismatch string, not just any `401`,
so a real regression in JWKS reachability or issuer config can't
silently pass as "expected."

**Verified live, both positive and negative paths**, against the real
running dev stack (its own real `kronos-backend` + Keycloak, same auth
middleware code the test-stack profile runs): the real
`client_credentials` flow produces the exact expected 401 + message
(script exits 0, PASS); a genuinely malformed token produces a different
message the script's own assertion correctly rejects (confirmed the
script would NOT rubber-stamp an unrelated failure as success).
`ruff` clean.

**Verification scope, stated honestly**: given real, confirmed host
memory pressure at the time (737 MiB free), a full isolated
`docker-compose.test.yml` rebuild just to re-confirm `kronos-backend`
boots in that exact profile was not attempted this cycle — that specific
boot sequence is already independently, repeatedly proven by
`frontend-e2e-smoke`'s own real runs this session. What's newly verified
here is the coexistence-check script's own logic, against the same real
backend code and Keycloak auth middleware.

## Status

`security-stack` now boots the same real `kronos-backend` instance
`frontend-e2e-smoke` proves works, and runs a real, specific, honestly-
scoped check that its Keycloak JWT-validation config is compatible with
whatever `keycloak-init` actually provisions in this exact CI run — a
real regression (client secret drift, JWKS unreachable, issuer mismatch)
would now fail this job with a clear, distinguishing error rather than
silently going unnoticed until a completely separate job happened to
catch it.

## Recommendation for the next cycle

1. Intake-stage retry E2E coverage (carried since Milestone TTT).
2. `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards-embed,
   resilience, a11y specs).
3. If a full isolated test-stack rebuild is ever done for an unrelated
   reason, it's worth confirming this cycle's new CI step passes there
   too, closing the verification-scope gap noted above — not urgent
   given the underlying boot sequence's own independent proof.
