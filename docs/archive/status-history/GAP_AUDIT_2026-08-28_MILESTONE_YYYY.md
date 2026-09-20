# Gap Audit — Milestone YYYY (2026-09-02)

**Scope:** Tier 1 item 3 from `docs/HANDOFF_AND_ORCHESTRATION.md`: persist
pending form state across a step-up (MFA) redirect. Named in Milestone
TTTT, confirmed to equally affect `inviteUser`/`updateUserRole` in
Milestone XXXX — three real features shared the identical rough edge:
`apiClient`'s global response interceptor (`api/client.ts`) performs a
full browser redirect on a step-up challenge, abandoning both the
in-flight mutation and the submitting component's own local React state (a
full remount, not a resumed session).

## The design decision made here

The doc flagged this as needing "a deliberate design pass, not a quick
patch." The design chosen: stash the form's current (non-sensitive)
values into `sessionStorage` right before the request that might need
step-up goes out; restore them into the form on the next mount (i.e. after
returning from the redirect). **Never auto-submit the mutation on the
user's behalf** — this only saves retyping, the user still takes one
explicit action (click Save again, or an explicit "Apply" for the one case
that has no separate submit step) to actually commit a security-sensitive
change. `frontend/src/lib/stepUpFormPersistence.ts` is the shared,
three-function primitive (`stashPendingStepUpForm`/`takePendingStepUpForm`/
`clearPendingStepUpForm`) all three forms use.

Two sub-decisions worth naming explicitly:

1. **Password is deliberately excluded** from `InviteModal`'s persisted
   fields. It's already shown in the clear in that modal by design (the
   admin copies/shares it out of band), but there's no reason to widen
   *where* a freshly-typed or generated credential also sits at rest, even
   briefly, when the rest of the form is a strictly lower sensitivity.
   `PendingInviteForm = Omit<InviteUserInput, 'password'>` enforces this at
   the type level, not just by convention.
2. **The role-change `<select>` gets a distinct "Pending: X — Apply /
   Dismiss" banner**, not a silently pre-selected value. A `<select>` has
   no separate submit step — its `onChange` *is* the mutation — so
   pre-filling its value the same way the two Save-button forms do would
   mean the row's own state could look already-correct without the user
   having taken any action, or silently produce no `onChange` if they
   picked the same value back. The explicit banner keeps the "never
   auto-submit" rule true here too.

## Real, live verification

New `frontend/src/__tests__/stepUpFormPersistence.test.ts` (6 tests) covers
the storage primitive itself. The real proof is a real browser, though: new
`frontend/e2e/admin-stepup-form-persistence.spec.ts` (3 tests) drives all
three forms through an actual step-up redirect against the real dev-stack
Keycloak and confirms restoration — not assumed from reading the diff:

- Quota: `#quota-gb-input` shows `"7"` immediately on return (no retyping),
  Save then succeeds directly.
- Invite: first/last name, email, and role are all restored on reopening
  the modal; **the password field is confirmed empty** (the deliberate
  exclusion, verified, not just claimed).
- Role change: the `<select>` still shows the OLD role on return (proving
  it does NOT auto-apply), a "Pending: analyst" banner is visible, and only
  clicking the banner's own "Apply" button completes the change — then a
  full page reload independently confirms it persisted server-side.

All 3 passed on the first live run (48.7s total) against the real,
freshly rebuilt `docker-nginx-1` (real `docker compose build nginx && up
-d nginx`, not just `npm run build` — this is a UI behavior change,
verified in a real browser per CLAUDE.md's UI-verification requirement,
not just typechecked). `tsc`/`oxlint`/`vitest` (110/110, up from 104)/
production build all clean.

## Status

The pending-form-state-loss UX rough edge named across Milestones
TTTT/WWWW/XXXX is now fixed for all three affected actions, with a
consistent, documented, never-auto-submit design applied uniformly.

## Recommendation for the next cycle

`admin-stepup-form-persistence.spec.ts` is not yet wired into
`security-integration-tests.yml` as of writing this doc — intended as an
immediate follow-up in the same push, not a deferred gap (see the commit
this doc ships alongside).
