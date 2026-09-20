# Gap Audit — Milestone III (2026-08-28)

**Scope:** closes Milestone HHH's one open item. A real, previously-unknown
frontend bug — not a test-stack timing artifact — found, root-caused, and
fixed the same day.

---

## The bug

Milestone HHH's PoC (`poc/test_stack_frontend_https/`) hit a real,
reproduced-twice `401 "Token refresh failed"` on `login.spec.ts`'s own
final assertion, left open as "possibly a cold-test-stack timing
artifact, possibly a real race — not yet confirmed."

Root-caused for real rather than left as a hypothesis: ran the exact same
race directly against the live **dev** stack (fast, already-running, no
cold-boot involved) by forcing two concurrent bare
`fetch('/auth/refresh', {credentials:'include'})` calls in a real
browser. **Reproduced the identical race on demand, every single time**
— one real `200`, one real `401`. This conclusively ruled out "slow test
stack" as the explanation.

Real cause, traced in the actual frontend source:
`frontend/src/api/client.ts`'s 401 response interceptor and
`frontend/src/keycloak.ts`'s own `scheduleSilentRefresh`-driven timer are
**two independent, uncoordinated callers** of the exported
`refreshAccessToken()` function. `client.ts` already queues *other*
requests' 401s behind its own in-flight refresh (`isRefreshing`/
`pendingRequests`) — but that coordination is scoped entirely to its own
module; it has zero visibility into `keycloak.ts`'s own timer-triggered
calls. If both fire within the same narrow window (routine in real usage
— e.g. an API call 401s at almost the same moment the silent-refresh
timer independently fires), each sends the browser's *same* current
`refresh_token` cookie to `POST /auth/refresh` independently. Keycloak's
real refresh-token rotation accepts exactly one; the other gets a real,
correct-from-Keycloak's-perspective rejection.

**The real, severe consequence**: `refreshAccessToken()`'s existing
failure handling doesn't distinguish "the refresh token really is
invalid" from "this specific call lost an entirely avoidable race" — both
paths call `clearAuth()` and `keycloak.login()`, forcing the user through
a full, unwanted re-login. **A real, active, perfectly valid session
could be silently kicked out from under a real user for no reason other
than internal timing**, not because anything about their session was
actually wrong.

## The fix

`frontend/src/keycloak.ts`: a module-level single-flight promise
(`inFlightRefresh`) shared by every caller of `refreshAccessToken()`.
Since both `client.ts`'s interceptor and `keycloak.ts`'s own timer import
and call this same exported function, wrapping it once fixes both call
sites — a second caller while one refresh is already in flight now
`await`s the *same* real HTTP round trip instead of firing a second,
racing one.

Deliberately scoped to exactly the confirmed mechanism: `initKeycloak()`'s
own one-time bootstrap call (`callRefreshEndpoint(keycloak.refreshToken)`,
right after a fresh login, before any timer exists yet or any API call
could plausibly have fired) was left as a separate, direct call — nothing
can race it in practice at that point in the app's lifecycle, and folding
it into the same guard would need a small signature change for
marginal-to-no real benefit.

## Verification

Real fix, verified two independent ways per this initiative's own
verification-first standard — not just "the logic looks right":

1. **New Vitest unit test**
   (`refreshAccessToken shares one in-flight request across concurrent
   callers`, `frontend/src/__tests__/keycloak.test.ts`): calls
   `refreshAccessToken()` twice concurrently against a controllable mock
   `fetch`, asserts the mock was called exactly once before either
   promise resolves, and that both callers correctly receive the same
   successful outcome once it does. Passes (7/7 in that file, 104/104
   full suite).
2. **Real E2E regression**: rebuilt and redeployed the real frontend into
   the live dev stack, ran the full six-spec `frontend/e2e/` suite
   (login, evidence-upload, evidence-retry, detection-triage,
   detection-triage-race, cross-tenant-isolation) — all six passed
   together in one run (2.8 min), confirming the fix doesn't regress any
   of the real, previously-verified user journeys this suite covers.

`poc/test_stack_frontend_https/README.md` updated in place marking this
item resolved, closing out Milestone HHH's last open thread.

## Status

E2E delivery-order items 2-4 remain fully complete. The
`docker-compose.test.yml`-frontend-TLS work (Milestone HHH) can now
proceed to being folded into the shared file permanently, since the one
thing blocking it (an unexplained failure) is now explained and fixed —
though that folding-in itself is still separate, not-yet-done work.
Milestone EEE's still-open maintainability findings (suite runtime
scaling, TS+Python toolchain consolidation, multi-tab session gap) remain
untouched.

## Recommendation for the next cycle

1. Fold `poc/test_stack_frontend_https/`'s proven `tls-init`/
   `nginx`-build/`opensearch-dashboards`-stub pieces into the real
   `docker-compose.test.yml` permanently, and wire at least a smoke-tier
   `frontend/e2e/` spec into `.github/workflows/security-integration-tests.yml`.
2. Otherwise, `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards
   embed, resilience, a11y/visual) or Milestone EEE's maintainability
   findings remain available.
