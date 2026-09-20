# Gap Audit — Milestone DDDD (2026-08-31)

**Scope:** closes Milestone CCCC's recommendation #2 —
`assert_case_lead_or_admin`'s stricter "of case"/"own" qualifier
(`src/external/middleware/rbac.py`, AUTH-007), the third distinct
RBAC/authz boundary this initiative has now closed, after the pure role
check (Milestone BBBB) and the weaker owner-OR-member read-access check
(Milestone CCCC).

---

## Fixed this cycle

### New fixture: `SecondCaseLeadSeeder` / `seed_second_case_lead.py`

`assert_case_lead_or_admin` requires actual case *ownership*, not mere
role possession or membership — used for the stricter case-lead-gated
mutations (add member, delete, legal hold, audit log read). The single
static `case-lead` dev user (`docker/keycloak/kronos-realm.json`) cannot
exercise this boundary on its own: whatever case it creates, it owns.
Proving the boundary needs a genuinely *second*, real account that has
`Role.CASE_LEAD` (so `requires_role` lets it through) but does not own
the specific case under test.

New `frontend/e2e/fixtures/seed_second_case_lead.py` provisions exactly
that — a fresh, real, throwaway user added to the *existing* target org
(default `kronos-dev`, not a new throwaway org) with the real
`case-lead` realm role. Reuses `seed_second_org.py`'s own proven
Keycloak Admin API building blocks (user creation, org-membership add,
`org_id` attribute read-then-splice PUT, separate realm-role-mapping
POST) and `seed_detection.py`'s own `get_org_id` (existing-org lookup,
not creation) rather than re-deriving either — and the same
self-cleans-at-start-of-run hygiene pattern `seed_second_org.py`
established after its own real incident. New
`frontend/e2e/SecondCaseLeadSeeder.ts` TypeScript wrapper, matching
`SecondOrgSeeder.ts`'s shape exactly.

### New shared page-object capability: `KronosPage.postJsonWithStatus()`

`POST /api/cases/{id}/members` has no frontend UI yet (confirmed by
reading `CasesPage.tsx` before writing this test, not assumed) — the
spec issues the real API call directly. Added `postJsonWithStatus()` to
the shared `KronosPage` base class (mirroring the existing `fetchJson()`
GET helper's "fresh, independent bearer token per call" pattern) since
it returns the real HTTP status code, not just a parsed body — necessary
because a real 403 response isn't shaped like the `CaseOut` a success
response would be, and the status code itself is the actual thing under
test. New `CasesPage.attemptAddMember(caseId, userId)` public wrapper.

### New spec: `frontend/e2e/case-lead-ownership-access-denial.spec.ts`

The static `case-lead` account creates a real case (owns it). A freshly
seeded second case-lead, real member of the same org, attempts
`POST /api/cases/{id}/members` on that case. Before asserting the 403,
the spec first confirms (via `fetchDecodedAccessTokenClaims()`) that the
second account's token genuinely carries `case-lead` — otherwise a 403
here could just be `requires_role` rejecting for lack of the role
entirely, silently duplicating `rbac-access-denial.spec.ts`'s own
coverage instead of proving the new, stricter boundary. Confirmed from
`add_case_member`'s own route source before writing the assertion: the
ownership check runs immediately after the case lookup, before the
request body's `userId` is ever read — so an arbitrary placeholder UUID
in the body is fine, the rejection happens before it would matter.

**Verified live**: passes alone (~3.2s) and alongside
`case-membership-access-denial.spec.ts`, `rbac-access-denial.spec.ts`,
`cross-tenant-isolation.spec.ts`, and `login.spec.ts` (5 tests total)
with no interference — confirming this spec's own 403 assertion doesn't
collide with either sibling RBAC spec's own status-code assertions on
similarly-shaped requests. Self-cleanup verified for real across two
consecutive runs (each run's own stale user from the prior run correctly
removed at start).

Wired into `security-integration-tests.yml` right after
`case-membership-access-denial`, with `KRONOS_E2E_PYTHON: "python3"`
(matching `cross-tenant-isolation`'s own env block — the same Python
fixture machinery, same requirement).

## Status

All three distinct RBAC/authz boundaries this platform's own permission
matrix defines and that recent milestone docs have concretely named
(`requires_role`, `assert_case_access`, `assert_case_lead_or_admin`) now
have real, live-verified E2E proof they hold — not just that the route
handler has the right decorator, but that a real, differently-privileged
account genuinely gets denied end-to-end, with the frontend/backend
response observed directly.

## Recommendation for the next cycle

1. The positive-membership-grants-access counterpart deferred since
   Milestone CCCC — now unblocked: `SecondCaseLeadSeeder`'s pattern
   (or a same-shaped `analyst`-role seeder targeting the existing org)
   plus the now-existing `attemptAddMember()`/`postJsonWithStatus()`
   machinery makes this cheap to build this time, unlike when it was
   first deferred.
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`,
   `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8.
4. Periodically re-check whether Milestone RRR's CI-never-ran finding has
   changed.
5. This initiative's own ~4-cycle assessment rhythm: two implementation
   cycles (CCCC, DDDD) have landed since Milestone BBBB's own assessment
   — not yet due for another, but worth tracking as more land.
