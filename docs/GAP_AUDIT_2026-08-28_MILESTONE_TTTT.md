# Gap Audit — Milestone TTTT (2026-09-01)

**Scope:** same real-product-gap pattern as Milestone RRRR, found while
continuing the same audit: `GET`/`PATCH /api/admin/org/quota`
(`src/external/routes/admin.py`, `docs/TENANT_USAGE_QUOTA.md`) is a
mature, well-tested backend feature (real storage-quota enforcement, soft
ceiling, auto-resume of held evidence, its own dedicated backend test
file `tests/unit/test_admin_quota_routes.py`) with **zero** frontend UI —
confirmed via `grep -rn "Quota\|quota" frontend/src/pages/*.tsx` before
writing anything: no matches. No backend changes this cycle; this is a
pure frontend addition on top of an already-solid, already-tested route.

## New `QuotaSection` (`AdminPage.tsx`)

Shows real current usage vs. the configured limit (or "unlimited"), a
progress bar (turns red past 90%), a form to set a new limit in GB, and a
"Clear (unlimited)" action. `frontend/src/types/index.ts` gained
`OrgQuota`; `frontend/src/api/admin.ts` gained `getOrgQuota`/`updateOrgQuota`.

## A genuinely new kind of verification: real step-up (MFA) through a real browser

`PATCH .../quota` is `_assert_aal2`-gated (step-up MFA) — the same gating
`inviteUser`/`updateUserRole` already have and have had for a while. Before
writing this spec, `grep -rl "acr.*aal2\|acrValues\|step-up"
frontend/e2e/*.spec.ts` found **zero** matches: despite those two other
admin actions requiring step-up, neither had ever been driven through a
real step-up re-authentication in this entire E2E suite. This spec is the
first.

### Real findings from actually running it, not read off the code

1. **The dev-seeded `admin` account's normal login is `acr=aal1`**,
   confirmed live by decoding its real token — despite `admin` already
   requiring TOTP just to complete ordinary login (Milestone JJJJ), that
   is a *different* Keycloak flow from the conditional-OTP step-up flow
   this route needs. One does not imply the other.
2. **`apiClient`'s global interceptor performs a real, full browser
   redirect** to Keycloak for step-up (`keycloak.login({acrValues:
   'aal2', prompt: 'login'})`), not an in-page silent refresh — confirmed
   live: a full password + real TOTP re-authentication is required
   (reused `poc/admin_totp_enrollment/output.txt`'s captured secret and
   `frontend/e2e/totp.ts`'s existing RFC 6238 helper — no new
   infrastructure needed for this part).
3. **A real, pre-existing UX rough edge, not introduced by this UI**: a
   full page redirect cannot resume the original in-flight JS mutation
   Promise. Confirmed live: after completing step-up and landing back on
   `/admin/org`, the quota was still unchanged, *and* the form's own
   local React state (the typed value) was gone — a full remount, not a
   resumed session. The user must re-enter the value and click Save a
   **second** time; that second call then succeeds directly, no further
   redirect (the token is aal2 for the rest of the session). This equally
   affects the already-shipped `inviteUser`/`updateUserRole` flows —
   named here rather than silently worked around, and **not fixed** in
   this pass: persisting pending form state across a redirect is a real
   architectural question spanning three existing features, out of scope
   for one new admin-settings section.

### A real, found-live test flakiness, fixed the way this initiative always fixes findings from an actual run

The first version of the step-up test helper generated one TOTP code and
retried once after a fixed 2s wait on rejection. Live testing (not
assumed reliable after one green run) found this genuinely insufficient
— roughly 1 in 3 runs still failed with "Invalid authenticator code",
including with the naive retry. Root cause, found by testing repeated
quick successive runs: `generateTotp()` is deterministic within a given
30s window, so a 2s wait usually does **not** cross a window boundary,
producing the identical code as the just-rejected one — and Keycloak
26.2's default OTP policy also rejects reuse of the same code within its
replay cache, which presents identically to a stale/skewed code but has
a different real cause. Fixed by waiting out the actual remaining time in
the current 30s window (not a fixed short guess) before generating the
retry code — confirmed across 4 repeated live runs, including two that
genuinely took the retry path and still passed cleanly.

## Real verification

- `npx tsc -b`: clean. `npx oxlint`: 0 errors, 1 pre-existing unrelated
  warning. `npm run test` (vitest): 104/104 passed. `npm run build`:
  clean.
- Real rebuild + redeploy of `docker-nginx-1` before any live check, same
  established practice as Milestones RRRR/SSSS.
- New spec: 4 repeated live runs, `7.3s / 11.8s / 28.6s / 28.6s` — all
  passed; the two ~28.6s runs took the fixed retry path and still
  succeeded, the real proof the fix works, not just that the happy path
  does.
- Run together with the full `a11y.spec.ts` (7 tests) + `login.spec.ts`:
  `9 passed (22.2s)`, no interference.
- Backend: no changes; `tests/unit/test_admin_quota_routes.py` already
  exists and already covers `get_org_quota`/`update_org_quota`
  independently of this UI work.
- Wired into `security-integration-tests.yml`; `timeout-minutes: 70`'s
  justification comment updated with the real measured cost and an
  explicit note about this step's own worst-case shape (a bounded ~30s
  TOTP-window wait, not just Playwright's per-test default) — the first
  step in this whole file for which that distinction actually matters.

## Status

Closes another real "backend fully built and tested, zero UI" gap in the
same vein as RRRR. Also closes a genuine, previously-unexercised category
of coverage for this suite: real step-up/MFA-gated mutations, now proven
end-to-end through an actual browser for the first time.

## Recommendation for the next cycle

1. Persisting pending form state across a step-up redirect (named above)
   — a real UX improvement affecting three existing features
   (`inviteUser`, `updateUserRole`, this new quota UI), not a bug, but a
   real rough edge worth a dedicated design pass if step-up-gated actions
   get more common.
2. Now that a real step-up E2E pattern exists (`completeStepUpReauth`),
   consider real E2E coverage for `inviteUser`/`updateUserRole`'s own
   step-up completion too — both currently untested end-to-end despite
   having the exact same gating this cycle just proved is real and
   working.
3. RRRR's still-open items remain unchanged: convenient user discovery
   for adding a case member, intake-retry test-stack CI-wiring,
   `admin.py`/`KeycloakAdminClient` duplication.
