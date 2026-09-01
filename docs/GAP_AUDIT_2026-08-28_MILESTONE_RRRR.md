# Gap Audit — Milestone RRRR (2026-09-01)

**Scope:** not a coverage/RBAC-boundary cycle like KKKK–QQQQ — a real,
previously-invisible **product** gap, found while continuing the RBAC
work: `add_case_member`, `remove_case_member`, and `delete_case` had all
been fully built, tested (unit + E2E, both branches, both directions),
and audited across Milestones CCCC through QQQQ — but every single one of
those specs exercised the route via a raw, direct `fetch()`
(`CasesPage.attemptAddMember()`/`attemptRemoveMember()`/`attemptDeleteCase()`).
Confirmed via `grep -n "member\|Member\|delete\|Delete\|archive\|Archive"
frontend/src/pages/CaseDetailPage.tsx` before writing anything: **zero
matches**. A real user of the actual product has never had any way to add
a teammate to a case, remove them, or archive a case — despite the
backend capability being complete and thoroughly proven. This is core
v1 case-management functionality, not a v2 feature (search, collaboration,
reporting, rate-limiting — the deferred list `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md`
§2 names).

## A second, compounding real gap found investigating the first

`CaseOut` (`src/external/routes/cases.py`) never exposed `member_user_ids`
at all — even a UI that wanted to *show* current members had no field to
read. Also: `CaseStatus` (open/closed/archived) was never surfaced in the
frontend `Case` TypeScript type or anywhere in the UI (confirmed via
`grep -rn "\.status\b"` across `CaseDetailPage.tsx`/`CasesPage.tsx` — zero
matches) — a case could be archived and a user would see no visible
difference at all.

## A real, deliberate scope decision: manual user-id entry, not a picker

Building "Add Member" surfaced a design question, not just a UI gap: a
case-lead (non-admin) has **no** way to discover which users exist in
their org — `GET /api/admin/users` is `requires_role(*_ADMIN_ROLES)`
(org-admin only). Two options were weighed:

1. Expand `/api/admin/users` (or a lighter equivalent) to case-leads too
   — a real RBAC-boundary expansion decision.
2. Ship the UI against exactly what the API already supports today (a
   raw Keycloak user id, org-admins can find one via the Admin page) and
   treat convenient user discovery as a separate, later UX enhancement.

Chose (2), documented explicitly in the component's own docstring and
here — this keeps the pass scoped to "give the existing, already-audited
backend capability a UI," not "also decide a new security boundary" in
the same change.

## Backend: `CaseOut.memberUserIds` (new)

Additive field, `list[str]` of real Keycloak user ids (`case.member_user_ids`).
Two new unit tests (`TestGetCase::test_get_case_includes_empty_member_list`,
`::test_get_case_includes_real_member_ids`) lock in the shape. Considered
whether this needed extra RBAC gating beyond what already exists —
`list_cases` already returns every case's title/owner/etc. to every
authenticated org member regardless of case membership (an existing,
already-shipped behavior, not something this change introduces), so
`memberUserIds` sitting in the same DTO doesn't create a new class of
exposure.

## Frontend: `Case.status`/`Case.memberUserIds` (new), `CaseMembersSection`/`DeleteCaseSection`

`frontend/src/types/index.ts`'s `Case` interface gained both real fields.
`frontend/src/api/cases.ts` gained `addCaseMember`/`removeCaseMember`/`deleteCase`.
`CaseDetailPage.tsx`'s Settings tab — previously **entirely** org-admin-gated,
showing only org-wide retention settings, with no case-specific content
at all — now shows, for the case's owner or an org-admin
(`assert_case_lead_or_admin`'s exact real semantics, mirrored client-side
via `user.userId === caseData.createdBy || isAdmin`):

- **Case Members**: real member list (raw ids), remove button per row, add
  form (manual Keycloak user id).
- **Danger Zone**: archive button behind a real two-step confirm (a bare
  click reveals a confirm step; only "Confirm Delete" calls the real
  `DELETE`), redirects to `/cases` on success. Already-archived cases show
  a static "This case has been archived." message instead of the button.
- Org-wide retention settings (pre-existing) stay admin-only, now nested
  under the same tab rather than being the tab's *only* possible content.

An "Archived" badge next to the case title (`CaseDetailPage`'s header)
makes the status visible for the first time anywhere in the UI.

## Real, live verification — a real browser, not just a green build

Per this project's own established practice (CLAUDE.md: "start the dev
server and use the feature in a browser before reporting the task as
complete"): `npm run build` passing is necessary but not sufficient for a
UI change, and the dev stack's `nginx` serves a **built** image
(`docker/Dockerfile.frontend`), not a live dev server — `docker compose
-p docker -f docker-compose.dev.yml build nginx` (real rebuild, real
`vite build` inside) then `up -d nginx` (real redeploy) were both run
before any live spec against it, mirroring Milestone JJJJ's own
established precedent for this exact situation.

New `frontend/e2e/case-members-ui.spec.ts` (add + remove through the real
Settings UI, a real analyst's real Keycloak `sub`) and
`frontend/e2e/case-delete-archive-ui.spec.ts` (the real two-step confirm
flow, a fresh independent `GET` before AND after confirming to prove the
first click alone didn't mutate anything, then real navigation back to
the case showing the "Archived" badge and the archived-state message) —
both **passed on the first live run** against the rebuilt dev stack.

New `CaseDetailPage.ts` page-object methods: `openSettingsTab()`,
`addMemberViaUI()`, `waitForMemberRow()`/`waitForMemberRowGone()`,
`removeMemberViaUI()`, `deleteCaseViaUI()`.

### A real gap this pass itself would have missed without checking

`a11y.spec.ts`'s existing "case detail page" scan only ever exercises the
default Evidence tab — the new Settings-tab UI (a real form, real
buttons) had never been WCAG-scanned. Added a genuinely separate new test
(`"case detail page's Settings tab has no real WCAG violations"`) rather
than assuming the existing scan already covered it. Passed clean on the
first run — no violations found, but the check itself is what matters
(an unchecked new form is exactly the kind of surface Milestone JJJJ's
own 3 real violations came from).

## Real verification summary

- `~/venv/bin/python3 -m ruff check`/`mypy`: clean on `cases.py`.
- `~/venv/bin/python3 -m pytest tests/unit/test_cases_routes.py`: 38/38
  passed (2 new).
- `npx tsc -b`: clean. `npx oxlint`: 0 errors, 1 pre-existing unrelated
  warning. `npm run test` (vitest): 104/104 passed. `npm run build`:
  clean.
- `docker compose -p docker -f docker-compose.dev.yml build nginx && up
  -d nginx`: real rebuild + redeploy, confirmed via a `login.spec.ts`
  sanity pass before anything else.
- New UI specs: `2 passed (6.6s)` on the first live run.
- Full 15-spec RBAC/membership/UI regression cluster (every spec from
  Milestones DDDD through RRRR, plus `login`/`evidence-upload` as a wider
  smoke check): `15 passed (46.0s)`, no interference.
- `a11y.spec.ts` (now 7 tests, +1 for the new Settings-tab scan):
  `7 passed (16.2s)`, clean.
- Wired into `security-integration-tests.yml` (CI's own frontend build
  step already rebuilds the nginx image fresh every run by design, so no
  CI-specific extra step was needed there — only the local dev-stack
  rebuild required a manual step); `timeout-minutes: 70`'s justification
  comment updated with the real measured cost.

## Status

Case management now has a real, usable, verified UI for its full
lifecycle (create → add/remove members → archive), not just a
fully-tested-but-invisible API surface. This closes what was arguably the
largest remaining "the tool doesn't actually do what the backend can do"
gap in the current v1 scope.

## Recommendation for the next cycle

1. Convenient user discovery for adding a member (username/email search,
   scoped to the caller's own org, available to case-leads not just
   org-admins) — a real, deliberately-deferred UX/RBAC design question,
   not bundled into this pass.
2. `CasesPage.tsx`'s own list view doesn't show the "Archived" badge
   either — only the detail page does. A small, easy follow-up if
   surfacing archived status in the list itself turns out to matter.
3. Intake-retry test-stack CI-wiring — still blocked on host memory as of
   this cycle's own last check.
4. `admin.py`'s `_is_org_member`/`KeycloakAdminClient.is_org_member`
   duplication (named in Milestone QQQQ) remains unaddressed.
