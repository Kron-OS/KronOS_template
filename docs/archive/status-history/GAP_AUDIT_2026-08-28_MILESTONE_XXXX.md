# Gap Audit — Milestone XXXX (2026-09-02)

**Scope:** Tier 1 item 4 from `docs/HANDOFF_AND_ORCHESTRATION.md`: real E2E
coverage for `inviteUser`/`updateUserRole`'s own step-up (MFA) completion.
Both routes share the exact same `_assert_aal2` gating `PATCH
/api/admin/org/quota` does (Milestone TTTT — the first spec in this suite
to ever drive a real step-up flow), but neither had been exercised through
a real browser step-up before this.

## What this closes

- `completeStepUpReauth` (the real, window-aligned TOTP-retry helper
  proven in Milestone TTTT) extracted from `admin-quota-ui.spec.ts` into a
  shared `frontend/e2e/stepup.ts` so it's reused, not duplicated.
- New `frontend/e2e/admin-user-management-stepup.spec.ts`, two specs:
  - `inviteUser completes a real step-up redirect and creates the real
    user` — a genuinely fresh (aal1) admin session submits the Create
    User form, hits the real redirect, completes it, then (per the
    already-documented abandoned-mutation behavior) re-submits the same
    form with a fresh aal2 token, which succeeds directly. Confirms the
    created row shows the right role, then cleans up via the UI's own
    Remove action.
  - `updateUserRole completes a real step-up redirect and persists the new
    role` — seeds a throwaway `case-lead` user **out-of-band**
    (`SecondCaseLeadSeeder`, a real Admin API call outside the browser
    session) specifically so the admin session in this test starts
    genuinely aal1 — if the target user were instead created through the
    invite UI first, that would already elevate the session to aal2 and
    hide whether `update_user_role`'s *own* redirect trigger actually
    fires. Changes the seeded user's role via the real role `<select>`,
    completes the real redirect, retries, then confirms via a full
    `page.reload()` that the change genuinely persisted server-side (not
    just optimistic client state).

## A real, useful finding along the way

Confirmed live (not assumed) that once a step-up redirect completes, the
session's token is aal2 for the **rest of that browser context** — a
second aal2-gated action in the same session succeeds directly with no
further redirect. `test_invite_user_...` above deliberately exploits this
for real, low-cost cleanup (removing the just-created user needs no second
step-up); `test_update_user_role_...` deliberately avoids it (seeds via a
non-browser path) so it doesn't accidentally skip proving
`update_user_role`'s own gate.

## Real, live verification

Both new specs run against the real dev-stack Keycloak 26.2 + real
backend, no mocks: `2 passed` standalone; `4 passed (1.5m)` alongside
`admin-quota-ui.spec.ts` and `role-change-mid-session.spec.ts` together
(no interference, no shared-state pollution — each seeds/cleans its own
throwaway user). `tsc`/`oxlint`/`vitest` (104/104)/production build all
clean.

## Status

Both step-up-gated admin-user-management actions now have real,
live-verified browser coverage, matching quota's. The pending-form-state-
loss UX rough edge these tests deliberately work around (Tier 1 item 3)
remains open and unfixed — this cycle proves the redirect mechanics work
correctly for all three actions, it doesn't change the UX.

## Recommendation for the next cycle

Tier 1 item 3 (persist pending form state across the step-up redirect) is
now the more valuable next architectural piece — three real features
(quota, invite, role-change) all share the identical abandoned-mutation
rough edge these three specs independently demonstrate.
