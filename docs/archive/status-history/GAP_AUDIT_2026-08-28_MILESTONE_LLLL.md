# Gap Audit — Milestone LLLL (2026-09-01)

**Scope:** closes Milestone KKKK's coverage-gap finding — `assert_case_lead_or_admin`
(`src/external/middleware/rbac.py`) gates three call sites in
`src/external/routes/cases.py`: `add_case_member`, `delete_case`, and
`list_case_audit_events`. Its DENY branch has real coverage
(`case-lead-ownership-access-denial.spec.ts`, Milestone DDDD); its ALLOW
branch was only ever asserted as a side effect of
`case-membership-access-grant.spec.ts`'s (Milestone EEEE) own setup step —
that spec's real, named purpose is `assert_case_access`'s separate ALLOW
branch (does a granted member get real read access), not this one.

## What was actually checked before writing anything

Re-examined the KKKK coverage-gap finding's own framing before acting on
it: EEEE's spec *does* assert `add_case_member`'s status code
(`expect(grantStatus).toBeGreaterThanOrEqual(200)`), so a spec whose only
purpose was re-asserting that exact call would be low-value, near-duplicate
work — not what this initiative's own discipline calls for. Grepped
`frontend/e2e/` for any coverage of the audit-log endpoint first
(`grep -rln "auditlog\|Audit Log\|/audit\b" frontend/e2e/*.spec.ts
frontend/e2e/pages/*.ts` — no matches) and confirmed `list_case_audit_events`
has **zero** E2E coverage on either branch, and `delete_case` likewise has
none. Redirected scope toward the genuinely uncovered call site rather than
duplicating EEEE's own assertion under a new name.

## `frontend/e2e/case-lead-ownership-access-grant.spec.ts` (new)

Single spec, static `case-lead` dev user, no second account needed (this
boundary only requires *ownership*, which the static user always has over
a case it creates itself):

1. Creates a real case. `create_case` itself logs
   `AuditEventType.CASE_CREATED` (`case.created`) — confirmed by reading
   the route before relying on it — so the case already has real,
   non-empty audit content with zero extra setup.
2. Opens the real Audit Log tab (`AuditLogTab`, `CaseDetailPage.tsx`) and
   asserts a `case.created` row is visible and the real "N total events"
   footer reads `1 total events` — `list_case_audit_events`'s
   `assert_case_lead_or_admin` ALLOW branch, exercised and asserted for
   the first time.
3. Calls `attemptAddMember` (real target `userId`, its value doesn't
   matter for this boundary — `add_case_member` never looks it up
   server-side, same reasoning `case-lead-ownership-access-denial.spec.ts`
   already established) and asserts a real `200` — `add_case_member`'s own
   ALLOW branch, this time named as its own explicit scenario rather than
   an incidental side effect of a differently-framed spec.
4. Reloads the page (a fresh load, not the same in-memory query-cache
   state that rendered step 2) and re-opens the Audit Log tab, confirming
   a `case.updated` row now appears and the total is `2 total events` —
   proves the mutation genuinely persisted and is visible through the same
   case-lead-gated read path, not just trusted from the POST's own
   response body.

New `CaseDetailPage.ts` methods: `openAuditLogTab()`,
`waitForAuditEventRow(eventType)`, `getAuditLogTotalText()` — all real
selectors read directly off `AuditLogTab`'s JSX before writing anything
(`td:has-text(...)` for the event-type cell, the real "N total events"
footer text), not guessed.

## Real verification

- `npx tsc -b`: clean.
- `npx oxlint`: 0 errors, 1 pre-existing unrelated warning
  (`ErrorCatalogue.tsx`, same one every prior milestone has noted).
- `npm run test` (vitest): 104/104 passed, unaffected.
- New spec run standalone against the live dev stack: `1 passed (3.4s)`.
- Run together with the full RBAC spec cluster (`case-lead-ownership-access-denial`,
  `case-membership-access-grant`, `case-membership-access-denial`,
  `rbac-access-denial`) to confirm no interference: `5 passed (16.9s)`.
- Wired into `security-integration-tests.yml`'s `frontend-e2e-smoke` job
  (new `"E2E: case-lead-ownership-access-grant"` step, no extra
  services/env needed); `timeout-minutes: 70`'s justification comment
  updated with the real measured cost (~3.4s standalone, negligible
  against the existing margin), per this job's established practice.

## Status

`assert_case_lead_or_admin`'s ALLOW branch now has a real, explicitly-named
scenario covering two of its three call sites (`add_case_member`,
`list_case_audit_events`). `delete_case`'s ALLOW branch (successfully
archiving a case one owns) remains untested on either branch — not
addressed this cycle; see below.

## Recommendation for the next cycle

1. `delete_case`'s ALLOW/DENY branches have zero E2E coverage at all
   (confirmed via the same grep this cycle used) — a real, small,
   well-scoped gap for a future cycle, though a destructive-action spec
   needs a moment's more care about cleanup/isolation than a read-only one.
2. Milestone KKKK's other named recommendations remain open and
   unchanged by this cycle: intake-retry test-stack CI-wiring (blocked on
   host memory), mid-session role-change coverage (needs a
   `keycloak_auth.py` design read first), case-member removal (real,
   un-built feature gap — `DELETE /cases/{id}/members/{user_id}` doesn't
   exist), and `add_case_member`'s server-side `userId` validation.
