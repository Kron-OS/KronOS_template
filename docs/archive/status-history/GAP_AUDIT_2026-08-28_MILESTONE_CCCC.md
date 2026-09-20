# Gap Audit — Milestone CCCC (2026-08-31)

**Scope:** closes Milestone BBBB's recommendation #1 — broaden RBAC
coverage beyond the pure role check `rbac-access-denial.spec.ts` proved,
to the *ownership/membership* qualifier
(`assert_case_access`/AUTH-007, `src/external/middleware/rbac.py`), a
real, distinct security boundary neither `rbac-access-denial.spec.ts`
(a role check, `requires_role`) nor `cross-tenant-isolation.spec.ts`
(a different org entirely — rejected earlier, by the org-scoped
repository query returning nothing, a 404) actually exercises.

---

## Fixed this cycle

### New spec: `frontend/e2e/case-membership-access-denial.spec.ts`

Real, confirmed premise (read directly from `assert_case_access`'s own
source before writing the test, not assumed): for a same-org, non-`org_admin`
caller, `org_id` equality alone is not sufficient — the caller must
either own the case (`case.owner_user_id`) or be listed in
`case.member_user_ids`. `GET /api/cases/{case_id}`
(`src/external/routes/cases.py`) first does an org-scoped repository
lookup (`case_repo.get_by_id(case_id, tenant.org_id)` — this is what
`cross-tenant-isolation.spec.ts` already proves returns nothing, hence a
404, for a genuinely different org), and only *then* calls
`assert_case_access`, which is what must reject a same-org caller who
just isn't entitled to this specific case — a real 403, a genuinely
different code path and a genuinely different HTTP status than the
cross-org case.

The spec: `case-lead` creates a real case (becomes `owner_user_id`);
`analyst` (a real, same-org, same-tenant dev-seeded user, deliberately
never added as a member) navigates directly to that case's URL. Watches
real network responses (same pattern `cross-tenant-isolation.spec.ts`
already established) and asserts every observed `/api/cases/{id}`
response is a real `403` — not `404` (which would mean the org-scoping
check ran instead of the membership one) and not `200` (a real
access-control leak) — plus confirms the case's title never appears
anywhere in the denied caller's rendered DOM.

**Verified live**: passes alone (~4.1s) and alongside
`cross-tenant-isolation.spec.ts`, `rbac-access-denial.spec.ts`, and
`login.spec.ts` (4 tests total) with no interference — confirming the
new spec's real 403 assertion doesn't collide with either sibling
spec's own real 404/403 assertions on a similarly-shaped request.

Wired into `security-integration-tests.yml` right after
`rbac-access-denial`, matching that step's shape (no extra
services/env needed).

## Documented, not fixed this cycle

**The positive-side counterpart** (case-lead adds analyst as a real
member via `POST /{case_id}/members`, then analyst's own direct-URL
navigation succeeds) was investigated but deliberately deferred, not
built as a stretch addition this cycle: the frontend has no existing UI
surface for "add member" that this suite's page objects already drive
(unlike the negative case, which reuses `createCase()`/direct
navigation exactly as `cross-tenant-isolation.spec.ts` already
established), and finding/supplying `analyst`'s real `userId` for a
direct API call would need new setup machinery this cycle didn't have
grounds to build hastily. The negative case is also the one that matters
most for proving the security boundary actually holds; the positive case
is a completeness nicety, not a security-critical proof, so leaving it
for a cycle with room to build the setup machinery properly is the
right call, not a shortcut.

## Status

`assert_case_access`'s ownership/membership qualifier — a real, distinct
authorization boundary this platform's own permission matrix defines —
now has real E2E proof it holds, alongside the pure role check
(Milestone BBBB) and the cross-org case (existing since earlier in this
initiative). All three of the RBAC/authz scenarios most concretely named
across the last several milestones' own recommendations are now closed.

## Recommendation for the next cycle

1. The positive-membership-grants-access counterpart (see above) — needs
   either a frontend "add member" UI to drive, or a small, real
   Admin-API-based setup helper (matching `SecondOrgSeeder`'s own
   established pattern of direct API setup where the UI doesn't cover
   it) to fetch `analyst`'s real `userId`.
2. `assert_case_lead_or_admin`'s own stricter qualifier (delete, assign
   members, legal hold, audit log — all case-lead "of case"/"own" rows)
   is a third, still-untested boundary: a case-lead who leads a
   DIFFERENT case attempting one of these actions on this one should
   also get a real 403, distinct from analyst's plain membership denial.
3. Intake-stage retry E2E coverage (carried since Milestone TTT).
4. `security-stack` also booting `kronos-backend`,
   `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8.
5. Periodically re-check whether Milestone RRR's CI-never-ran finding has
   changed.
