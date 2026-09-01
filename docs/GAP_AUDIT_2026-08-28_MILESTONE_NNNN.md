# Gap Audit — Milestone NNNN (2026-09-01)

**Scope:** closes Milestone KKKK's own coverage-gap finding — no spec had
ever covered a role changing while a session is already active. Per this
initiative's own established discipline (CLAUDE.md § F), the real design
question was answered by reading source first, then verified live — not
guessed and not left as an assumption.

## The design question, answered

Read `src/external/middleware/keycloak_auth.py` and `src/keycloak.ts`
before writing anything:

- **Backend**: role authorization is 100% stateless. `_extract_tenant()`
  reads `roles` directly off the JWT's own claims; `KeycloakTokenValidator`
  never re-checks them against Keycloak per-request — "Token introspection
  is never used" is the class's own docstring.
- **Frontend**: `keycloak.ts`'s in-memory access token is only ever
  replaced reactively (a `401` from `api/client.ts`'s interceptor) or on a
  genuine page load (`initKeycloak()`'s own real `POST /auth/refresh`
  call) — there is no proactive/periodic silent refresh.
- **Real, checked config**: `accessTokenLifespan: 900` (15 min),
  `docker/keycloak/kronos-realm.json`.

**Conclusion, now verified rather than assumed**: a role change (e.g. an
org-admin demoting a case-lead) takes effect only once the affected
session's own token store is refreshed — a page reload, or whenever the
existing token naturally expires and the next request 401s — not the
instant the change is made in Keycloak.

## `frontend/e2e/role-change-mid-session.spec.ts` (new)

1. A fresh, real throwaway case-lead (`SecondCaseLeadSeeder`) creates a
   baseline case (sanity — the role genuinely works before anything
   changes).
2. Real org-admin action, live, via the Admin API (`UserRoleUpdater`,
   new): swaps this SAME, already-logged-in user's realm role from
   `case-lead` to `analyst`.
3. A direct `POST /auth/refresh` round trip (bypassing the app's own
   token store) already reflects `analyst`, not `case-lead` — confirms
   Keycloak 26.2's real `refresh_token` grant re-evaluates realm-role
   mappings at redemption time, not just that this codebase trusts
   whatever it's handed. This is the one part of the finding that isn't
   provable by reading this repo's own source alone (a claim about a
   pinned external dependency's behavior), so it's verified live per
   CLAUDE.md § F rather than assumed from general OIDC knowledge.
4. **Without a reload**, the same browser session still creates a case
   successfully — the real, load-bearing "not instant" proof.
5. A real `page.reload()` (forcing `initKeycloak()`'s own refresh) then a
   denied case-creation attempt confirms the demotion is now honored.

### Two real, found-live test bugs, fixed the way this initiative always fixes findings from an actual run

1. **First live run** (an earlier draft with no explicit "still
   privileged" step) accidentally proved the core finding by tripping
   over it: a case-creation attempt placed after the Admin API demotion
   but before any reload still succeeded — the case genuinely appeared in
   the list. Real, not a fluke; rewritten to assert this deliberately
   instead of stumbling into it.
2. **Second live run** (this draft's first attempt at the deliberate
   assertion) found a bug in the *test itself*: navigating back to
   `/cases` via `page.goto("/cases")` between steps is a genuine browser
   navigation, which itself triggers `initKeycloak()`'s real refresh and
   silently adopts the demoted token early — invalidating the "still
   privileged" assertion before it could run. Fixed by navigating via a
   real in-app link click (`page.click("text=Cases")`, client-side
   routing) instead, reserving an actual `page.reload()` for the one step
   meant to trigger the refresh.

## New shared infrastructure

- `frontend/e2e/fixtures/update_user_realm_role.py` + `UserRoleUpdater.ts`
  (new) — real Keycloak Admin API realm-role swap (`DELETE`/`POST`
  `role-mappings/realm`) on an *existing* user id. Unlike every other
  `seed_*.py` fixture (which provisions a fresh throwaway account), this
  acts on a user that's already logged in — required for the "mid-session"
  scenario to be real.
- `SecondCaseLeadSeeder`/`seed_second_case_lead.py` gained a real `userId`
  field (additive; existing callers unaffected) so a caller can target the
  exact seeded account afterward.

## Real verification

- `npx tsc -b`: clean.
- `npx oxlint`: 0 errors, 1 pre-existing unrelated warning.
- `npm run test` (vitest): 104/104 passed, unaffected.
- New spec: two real failures on the first two live runs (see above,
  both understood and fixed, not retried blindly), then `1 passed (3.8s)`.
- Run together with the RBAC cluster (6 specs): `6 passed (14.9s)`, no
  interference.
- Wired into `security-integration-tests.yml` (`KRONOS_E2E_PYTHON` needed
  for the same Python-fixture reason the other `SecondCaseLeadSeeder`-based
  specs already require it); `timeout-minutes: 70`'s justification
  comment updated with the real measured cost.

## Status

Closes Milestone KKKK's mid-session role-change gap with a real, verified
answer (not a guess) and a real, passing spec. Also closes Milestone
KKKK's other named coverage gap not yet addressed: this is the last of
that cycle's two newly-surfaced items with a spec; case-member removal
(`DELETE /cases/{id}/members/{user_id}`) remains a real, un-built feature
gap, not a test gap — see below.

## Recommendation for the next cycle

1. Case-member removal — `DELETE /cases/{id}/members/{user_id}` doesn't
   exist yet. Real feature work: design the endpoint (mirroring
   `delete_case`'s `assert_case_lead_or_admin` gating, presumably), build
   it, then add E2E coverage the same way this thread has for every other
   mutation.
2. Intake-retry test-stack CI-wiring — still blocked on host memory as of
   this cycle's own last check; re-check when the dev stack's footprint is
   lower or on a host with more headroom.
3. `add_case_member`'s server-side `userId` existence/org validation —
   real fix, low urgency, needs its own verification cycle against a real
   Keycloak Admin API call.
