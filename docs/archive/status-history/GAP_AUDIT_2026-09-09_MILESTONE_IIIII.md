# Gap Audit — Milestone IIIII (2026-09-09)

**Scope:** the project owner asked to enhance Case navigation/filtering
(many parameters, search by name) and the Alerts/Detections view (many
parameters, bulk state-change on multiple alerts at once, default view of
new alerts, ability to switch to other views filtered by case/severity/
date). Explicit process requested: plan objectives, research current code,
design a filtering strategy, PoC, then push to dev (prod only if a real
target exists).

## Research findings (before any code changed)

Two research passes (Explore subagents) over the real, current code found:

- **Cases** had zero filter/search params (`GET /api/cases` only took
  `page`/`pageSize`); the frontend didn't even use those.
- **Detections** already had a partial in-memory filter set from Milestone
  BBBBB (`triageState`, `caseId`, `severity`, `q`), single-select only, no
  date range, and the frontend never persisted filter state in the URL.
- **No bulk-action precedent existed anywhere in the codebase** (confirmed
  by repo-wide grep) — a real gap, not an extension of an existing pattern.
- **No saved/named-view concept existed.** Resolved this design question by
  using TanStack Router URL search params as the persistence mechanism for
  "switching to another view" (bookmarkable/shareable/back-forward
  navigable) rather than building a new backend-persisted saved-views
  subsystem — a smaller, real answer to what was actually asked.

## What was built

### Backend
- `CaseFilter` (`src/adapter/repository/case_repository.py`) — `q` (OR'd
  ILIKE across title/description/reference_number), `status`,
  `classification`, `created_from`/`created_to`, `sort_by`/`sort_order`.
  Pushed into real SQL in `PostgresCaseRepository.list_by_org` (dynamic
  WHERE/ORDER BY via SQLAlchemy Core) — Cases already did real SQL
  pagination, so this keeps that scalability property rather than
  regressing to an in-memory scan. `GET /api/cases` exposes all of it;
  `CaseOut` now also returns `classification` (existed on the domain model,
  was never exposed).
- `GET /api/detections` — `triageState`/`severity` are now repeatable
  (multi-select), plus `dateFrom`/`dateTo` on `finding_timestamp`. Kept as
  in-memory predicates over the existing repository stream, matching the
  established Milestone BBBBB pattern (not rewritten to push into SQL this
  cycle — flagged as a known scaling limitation, not silently ignored).
- **New** `POST /api/detections/bulk-triage` — body
  `{detectionIds, targetState}` (max 200 ids), same RBAC as the single-item
  route. Loops the existing `DetectionTriageService.transition` per id
  (FSM-checked, individually audited — CLAUDE.md §A.2 — no new audit-event
  type needed since each transition already produces its own). Always
  200; per-item `{detectionId, status, detail}` so a mixed-state selection
  (e.g. one row already terminal) reports a real partial result instead of
  aborting the whole batch or silently dropping the failure.
- **Real bug found and fixed along the way:** a client-supplied bare date
  (e.g. `"2020-01-01"`, no tz offset) parses via pydantic as a *naive*
  datetime; comparing that directly against `Case.created_at`/
  `Detection.finding_timestamp` (always UTC-aware) raised an unhandled
  `TypeError`, turning an otherwise-valid filter request into a 500.
  Confirmed live with a 3-line repro before fixing. Both routes now
  normalize a naive input to UTC; regression tests added for both
  (`test_naive_date_param_does_not_500` in each route's test file).

### Frontend
- `App.tsx` — real `validateSearch` schemas for `/cases` and `/detections`
  (`CasesSearch`/`DetectionsSearch`, exported types), defensively parsed
  (a hand-edited/bookmarked URL can contain anything). This is the actual
  mechanism satisfying "see other views": every filter combination is a
  real, bookmarkable, back/forward-navigable URL — no new saved-view
  storage was built.
- `CasesPage.tsx` — search/status/classification/sort filter bar, filter
  state fully in URL search params (`useSearch`/`useNavigate({ from:
  '/cases' })`), real pagination controls (backend supported them, the UI
  never called them before this).
- `DetectionsPage.tsx` — filter state moved to URL search params; default
  view (`triageState` absent from the URL) is `NEW` only — an explicit
  selection, including "All" (all four states) or a partial set, is a real,
  distinguishable-from-absent value once the analyst touches the filter, so
  it's never silently reset. Multi-select toggle pills for triage state and
  severity, a case dropdown, a date range, row-selection checkboxes +
  "select all on page," and a bulk-action toolbar offering only the target
  states reachable from at least one selected row's real current state
  (mirrors `DetectionTriageState._VALID_TRANSITIONS`), with a per-batch
  success/skip summary.

## Verification (real, not assumed)

- Backend: 2 new unit-test classes (`TestListCasesFilters` in
  `tests/unit/test_cases_routes.py`; new tests in
  `tests/unit/application/test_routes_detections.py` for repeatable
  triageState/severity, date range, and `TestBulkTriageDetections` —
  success, partial-failure, unknown-id, cross-org, RBAC-denied,
  per-item-audited, empty-list-rejected). New real Postgres-testcontainer
  integration file `tests/integration/test_case_repository_postgres.py`
  (7 tests: q/status/classification/date-range/sort/pagination/no-filter
  backward-compat) — run for real against a real `postgres:16-alpine`
  container, 7 passed. Full suite: **2121 passed, 3 skipped, 89.97%
  coverage**, `ruff`/`mypy` clean.
- Frontend: `tsc -b`, `oxlint`, `vitest` (120 passed), `npm run build` —
  all clean.
- **Real dev-stack E2E** (rebuilt+redeployed `kronos-backend`+`nginx`,
  real browser against `https://kronos.local`):
  - New `detection-bulk-triage.spec.ts` (2 tests) — default-NEW view
    correctly hides an INVESTIGATING row until widened to "All"; bulk-
    selecting two real seeded NEW detections and marking them
    Investigating transitions both, confirmed by re-querying after
    widening the filter (not just trusting the success toast).
  - New `case-filtering.spec.ts` (2 tests) — free-text search across the
    org's full real case history; status filter narrows to a real archived
    case.
  - Existing `detection-filtering.spec.ts` — its severity filter used the
    old single-`<select>`; updated the `DetectionsPage` E2E page object's
    `filterBySeverity` to work against the new multi-select toggle-pill UI
    (deselect-all-then-select-target), both tests still pass.
  - Regression pass: `case-delete-archive-ui`, `case-members-ui`,
    `detection-triage`, `detection-triage-race`, `detection-why-triggered`
    all still pass unmodified. `case-artifacts-ui.spec.ts` failed — root
    cause confirmed via `celery-worker`/`celery-worker-plaso` logs to be
    the **pre-existing, already-documented** OpenSearch
    `cluster.max_shards_per_node` exhaustion
    (`docs/HANDOFF_AND_ORCHESTRATION.md` Tier 2 item 11), not a regression
    from this cycle's changes (that spec exercises evidence parsing/
    Artifacts, not Cases/Detections filtering).
  - `a11y.spec.ts` real WCAG scans for both `/cases` and `/detections`
    pass with the new filter bars/checkboxes/toolbar in place.

## Prod

Checked for real: no prod stack is running, and
`docker-compose.prod.yml` isn't even startable on this host as-is
(`OPENSEARCH_ADMIN_PASSWORD` unset — a required secret, not configured
here). Matches the project owner's own stated expectation. Dev-stack
delivery is the deliverable for this cycle.

## Status

PASS. Pushed to `feat/nextgen-soc-cert-platform` (no PR, per standing
instruction).
