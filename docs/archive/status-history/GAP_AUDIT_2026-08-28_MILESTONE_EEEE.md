# Gap Audit — Milestone EEEE (2026-08-31)

**Scope:** closes the positive counterpart every prior RBAC spec in this
initiative deferred. `rbac-access-denial.spec.ts` (pure role check),
`case-membership-access-denial.spec.ts` (owner-OR-member read access), and
`case-lead-ownership-access-denial.spec.ts` (strict ownership) each prove
a real *denial*. None of them proves the other half of the contract:
`assert_case_access`'s own ALLOW branch — that a real, successful
`POST /api/cases/{id}/members` grant actually turns into real read access
for the newly-added member, not just that the grant call itself
succeeds.

---

## Fixed this cycle

### New spec: `frontend/e2e/case-membership-access-grant.spec.ts`

`add_case_member` (`src/external/routes/cases.py`) takes a real target
`userId` in its request body and calls `case.with_member(body.userId)`
directly — no server-side lookup happens, so a *real* Keycloak user id is
required, not a placeholder (the placeholder the denial spec uses only
works there because that request is rejected by
`assert_case_lead_or_admin` before the body is ever read). Confirmed from
`src/external/middleware/keycloak_auth.py` before writing the test, not
assumed: `TenantContext.user_id` is parsed directly from the JWT's own
`sub` claim — so the real, static, dev-seeded `analyst` account's own
`sub`, read off a freshly-issued access token
(`fetchDecodedAccessTokenClaims()`, the same pattern
`case-lead-ownership-access-denial.spec.ts` already established), is the
correct real id to grant.

The spec: `case-lead` creates a real case (owns it), performs a real,
successful grant using analyst's real `sub`, then a **fresh** analyst
session (not the same page/context the grant happened in) navigates
directly to the case and confirms genuine access: every observed
`GET /api/cases/{id}` response is a real `200`, the case's real title is
visible in the DOM (not just a status code), and a fresh, independent
`GET` (new `CasesPage.fetchCaseById()`, mirroring this suite's own
"not trusted from the same page load" convention,
`docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.3) returns the real case data —
proving the grant's effect persisted server-side (Postgres
`case.member_user_ids`), not something only visible within the granting
call's own session.

**Verified live**: passes alone (~4.2s) and alongside
`case-membership-access-denial.spec.ts`,
`case-lead-ownership-access-denial.spec.ts`, `rbac-access-denial.spec.ts`,
and `login.spec.ts` (5 tests total) with no interference. `tsc --noEmit`
and the real project-wide `oxlint` (bare invocation, matching this
repo's actual `npm run lint` script — per-file invocation is known to
give false positives here) both clean.

Wired into `security-integration-tests.yml` right after
`case-lead-ownership-access-denial`, no extra services/env needed.

## Status

Every RBAC/authz boundary this initiative has named across five
milestones (BBBB/CCCC/DDDD's denials, EEEE's grant) now has real,
live-verified E2E proof on both sides — a caller who shouldn't have
access is genuinely denied, and a caller who's granted access genuinely
gets it, confirmed independently of the granting session.

## Recommendation for the next cycle

1. `assert_case_lead_or_admin`'s own ALLOW branch (a case-lead who
   genuinely owns the case successfully performing a gated mutation) is
   implicitly exercised by this spec's own grant step, but has never been
   asserted on directly as its own scenario — a cheap follow-up, not
   urgent.
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`.
4. `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards-embed,
   resilience, a11y specs).
