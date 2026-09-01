# Gap Audit — Milestone OOOO (2026-09-01)

**Scope:** closes Milestone KKKK/NNNN's own named feature gap — case
membership was add-only. `DELETE /api/cases/{id}/members/{user_id}` did
not exist at all; the existing org-member-removal endpoint
(`admin.py::remove_user`) is a *different*, org-scoped operation, not a
per-case one. This is a real, un-built product gap, not just a missing
test — the first Milestone in this thread to add a genuinely new route
rather than covering an existing one.

## `src/domain/case.py` — `Case.without_member()`

Mirrors `with_member()` exactly: immutable (`model_copy`), same
`updated_at` bump, `frozenset` difference instead of union. Two new unit
tests in `tests/unit/domain/test_case.py` (`test_without_member`,
`test_without_member_idempotent_for_non_member`), mirroring
`test_with_member`'s own shape.

## `src/external/routes/cases.py` — `remove_case_member`

`DELETE /{case_id}/members/{user_id}`, placed directly after
`add_case_member` for the same reason `delete_case` sits after it —
same file region, same boundary. Mirrors `add_case_member` exactly:

- Same `requires_role(Role.ORG_ADMIN, Role.CASE_LEAD)` + `assert_case_lead_or_admin`
  gating (a case-lead may only remove members from a case they lead).
- Same `AuditEventType.CASE_UPDATED` audit event, `details={"action":
  "case.member_removed", "member_user_id": ...}` — the audit log now has a
  real, distinguishable event for both halves of membership lifecycle.
- **Idempotent, matching `add_case_member`'s own union semantics**:
  removing a user who isn't currently a member returns `200`, not `404` —
  the caller's intent ("this user should not be a member") is already
  satisfied either way. A deliberate design choice, not an oversight;
  stated in the route's own docstring.

Three new unit tests in `tests/unit/test_cases_routes.py`
(`TestRemoveCaseMember`): persists a real removal (confirmed via a direct
repository read, not just the response), 404s for a missing case,
confirms the idempotent-success behavior for a non-member.

## `frontend/e2e/case-member-removal-revokes-access.spec.ts` (new)

The real, load-bearing scenario, mirroring `case-membership-access-grant.spec.ts`'s
(Milestone EEEE) own structure for the grant half and extending it with
the removal half that spec never covered: a case-lead grants analyst real
membership (real Keycloak `sub`, not a placeholder — `add_case_member`
never does a server-side lookup, same established reasoning), confirms
the removal call itself returns `200`, then — in a genuinely fresh
session, not trusted from the same page load — confirms the removed
member's own `GET /api/cases/{id}` now returns a real `403` on every
response, and that `fetchCaseById()`'s resolved body has no `id` field
(not that the call throws — `fetch()` only rejects on a network error,
not an HTTP error status, the same real lesson
`case-delete-ownership-denial.spec.ts` already established and re-applied
here directly rather than re-discovered the hard way).

## `frontend/e2e/case-member-removal-ownership-denial.spec.ts` (new)

The DENY-branch mirror of `case-lead-ownership-access-denial.spec.ts`,
same `SecondCaseLeadSeeder`: a real, freshly-seeded second case-lead is
denied removing a member from a case it doesn't own — real `403`.

## New shared infra

`CasesPage.attemptRemoveMember(caseId, userId)` — thin wrapper around the
already-existing `deleteWithStatus`, mirroring `attemptAddMember`/
`attemptDeleteCase`.

## Real verification

- `~/venv/bin/python3 -m pytest tests/unit/domain/test_case.py
  tests/unit/test_cases_routes.py`: 41/41 passed (7 domain + 34 routes,
  including the 5 new tests). Confirms this host's Python 3.14 CAN run
  these specific unit-test files without the deadlock previously
  documented for the full suite/asyncpg-backed integration tests —
  narrower than `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md`'s current
  "Tooling/environment gaps" wording implies; worth a follow-up
  correction pass to that doc (not made this cycle — out of scope for a
  feature milestone, noted for the next docs-focused cycle).
- `~/venv/bin/python3 -m ruff check`: clean on all 4 changed backend
  files.
- `~/venv/bin/python3 -m mypy src/domain/case.py src/external/routes/cases.py`:
  clean.
- Confirmed the dev stack's `kronos-backend` container picked up both
  backend changes via its own live `--reload` (volume-mounted source,
  confirmed via `docker logs` showing `StatReload detected changes in
  'src/domain/case.py'`/`'...cases.py'`. Reloading...`) — no manual
  rebuild needed, real live verification against the actual running
  service.
- Both new specs: `2 passed (8.3s)` standalone on the first real run.
- Run together with the full 10-spec RBAC/membership cluster
  (`case-lead-ownership-access-denial`, `case-lead-ownership-access-grant`,
  `case-membership-access-grant`, `case-membership-access-denial`,
  `case-delete-ownership-denial`, `case-delete-ownership-grant`,
  `role-change-mid-session`, `rbac-access-denial`, plus this cycle's two):
  `10 passed (30.1s)`, no interference.
- `npx tsc -b`: clean. `npx oxlint`: 0 errors, 1 pre-existing unrelated
  warning. `npm run test` (vitest): 104/104 passed. `npm run build`:
  clean production build.
- Wired into `security-integration-tests.yml`; `timeout-minutes: 70`'s
  justification comment updated with the real measured cost.

## Status

The two coverage/feature gaps Milestone KKKK's coverage-gap assessment
surfaced (mid-session role change, case-member removal) are both now
closed with real, verified, CI-wired coverage — Milestone NNNN and this
one respectively.

## Recommendation for the next cycle

1. Correct `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md`'s "Tooling/environment
   gaps" section — this cycle found the Python 3.14 deadlock is narrower
   than currently stated (isolated unit-test files run fine; the
   documented issue was specific to full-suite collection/asyncpg-backed
   integration tests). Re-verify the exact boundary before rewriting the
   claim, rather than assuming from this cycle's own narrow spot-check.
2. Intake-retry test-stack CI-wiring — still blocked on host memory as of
   this cycle's own last check.
3. `add_case_member`'s server-side `userId` existence/org validation —
   the same gap now also applies to `remove_case_member` (both take a
   caller-supplied `userId` with no existence check) — real fix, low
   urgency, needs its own verification cycle against a real Keycloak
   Admin API call.
