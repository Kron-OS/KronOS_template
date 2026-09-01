# Gap Audit — Milestone MMMM (2026-09-01)

**Scope:** closes Milestone LLLL's own recommendation — `delete_case`
(`src/external/routes/cases.py`) was the one remaining call site of
`assert_case_lead_or_admin` (`src/external/middleware/rbac.py`) with zero
E2E coverage on either branch, confirmed via `grep` before LLLL closed.
Completes the trilogy: `add_case_member` (Milestones DDDD/EEEE/LLLL),
`list_case_audit_events` (Milestone LLLL), `delete_case` (this cycle) all
now have real, explicit ALLOW and DENY coverage.

## `frontend/e2e/case-delete-ownership-denial.spec.ts` (new)

Mirrors `case-lead-ownership-access-denial.spec.ts`'s (Milestone DDDD)
structure exactly, for a different route on the same boundary: a real,
freshly-seeded second case-lead (`SecondCaseLeadSeeder`) attempts
`DELETE /api/cases/{id}` on a case the static `case-lead` dev user owns —
asserts a real `403`.

### A real, found-live test-design bug, fixed the way this initiative always fixes findings from an actual run — not assumed away

The first live run failed for a reason that had nothing to do with the
application: the test tried to confirm "the case wasn't actually archived"
by having the *denied second case-lead* issue a follow-up
`GET /api/cases/{id}` — but that account is neither owner nor member of
this case, so `assert_case_access` (a *separate* boundary,
`case-membership-access-denial.spec.ts`'s own subject) rejects that GET
too, with no `CaseOut` body to read an `id` off. `expect(stillThere.id).toBe(caseId)`
failed with `Received: undefined` — a real, reproducible failure, not
flakiness. Fixed by keeping the *owner's* browser context open and using
it for the confirmation GET instead (the owner can always read its own
case) — the correct, general lesson being: a denied account's own session
generally can't be reused to independently verify a DENY's absence of side
effects, since it may be blocked by an entirely different check from
reading the result at all.

## `frontend/e2e/case-delete-ownership-grant.spec.ts` (new)

The positive counterpart — no second account needed, the static case-lead
always owns whatever case it creates. Confirmed by reading the route
before writing anything: `delete_case` is a **soft archive**
(`case.with_status(CaseStatus.ARCHIVED)`), not a row deletion, and
`CaseRepository.get_by_id` (`postgres_case.py`) has no status filter, so a
subsequent `GET /api/cases/{id}` still returns a real `200` with
`status: "archived"` — asserted directly (not just that the DELETE call
itself returned `204`), proving the mutation genuinely persisted through
an independent read, per this suite's own established "not trusted from
the same page load" discipline.

## New shared infrastructure

- `KronosPage.deleteWithStatus(path)` (`frontend/e2e/pages/KronosPage.ts`) —
  a `DELETE`-method sibling of the already-existing `postJsonWithStatus`,
  same reasoning (real HTTP status for a route with no frontend UI yet).
- `CasesPage.attemptDeleteCase(caseId)` — thin wrapper, mirrors
  `attemptAddMember`.
- `CasesPage.fetchCaseById()`'s return type extended with a real `status`
  field (was `{id, title}`, now `{id, title, status}`) — additive, no
  existing caller broken (confirmed via `grep` across all 3 existing
  usages before changing the signature).

## Real verification

- `npx tsc -b`: clean.
- `npx oxlint`: 0 errors, 1 pre-existing unrelated warning
  (`ErrorCatalogue.tsx`, same one every prior milestone has noted).
- `npm run test` (vitest): 104/104 passed, unaffected.
- Both new specs run standalone: denial failed for a real reason on the
  first run (see above), fixed, re-run clean: `2 passed (5.9s)`.
- Run together with the full RBAC spec cluster (`case-lead-ownership-access-denial`,
  `case-lead-ownership-access-grant`, `case-membership-access-grant`,
  `case-membership-access-denial`, `rbac-access-denial`, plus this cycle's
  two): `7 passed (21.8s)`, no interference.
- Wired into `security-integration-tests.yml`'s `frontend-e2e-smoke` job
  (two new steps, `case-delete-ownership-denial` needs
  `KRONOS_E2E_PYTHON` for the same `SecondCaseLeadSeeder`/Python-fixture
  reason `case-lead-ownership-access-denial` already does);
  `timeout-minutes: 70`'s justification comment updated with the real
  measured cost.

## Status

`assert_case_lead_or_admin`'s three call sites (`add_case_member`,
`list_case_audit_events`, `delete_case`) all now have real, explicitly-named
ALLOW and DENY coverage. This closes out the ownership-RBAC coverage-gap
thread Milestones CCCC → DDDD → EEEE → KKKK → LLLL → MMMM has been working
through incrementally.

## Recommendation for the next cycle

Milestone KKKK's other named recommendations remain open and unchanged:

1. Intake-retry test-stack CI-wiring — still blocked on host memory
   (re-check when the dev stack's own footprint is lower, or on a host
   with more headroom).
2. Mid-session role-change coverage — needs a `keycloak_auth.py` design
   read first (does the platform re-validate role live per-request, or
   does a demotion only take effect on token refresh/expiry?) before a
   spec can assert the *correct* behavior rather than *a* behavior.
3. Case-member removal — `DELETE /cases/{id}/members/{user_id}` doesn't
   exist yet; a real, un-built feature gap, not a test gap.
4. `add_case_member`'s server-side `userId` existence/org validation —
   real fix, low urgency, needs its own verification cycle against a real
   Keycloak Admin API call.
