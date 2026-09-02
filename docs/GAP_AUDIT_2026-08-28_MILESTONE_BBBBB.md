# Gap Audit — Milestone BBBBB (2026-09-02)

**Scope:** the project owner's chosen follow-up to Milestone AAAAA:
"enhance the detection tab, to allow filtering in the UI, and we would
like to know why rules are triggered." Presented scenarios for both
filtering and "why triggered"; the owner's answer ("Go with best for you,
we would like to see rules triggered. In the future we would like orgs to
be able to add teire rules and activate/deactivate some.") confirmed the
recommended scope (minimal backend filter params + UI controls; "why
triggered" = both rule logic AND matched event content) and explicitly
deferred custom/user-managed Sigma rules to a future, out-of-scope phase.

Two real, unplanned bugs were found and fixed along the way, both from a
live user report mid-cycle ("the volatility analysis result is not
available") — folded into this same cycle rather than a separate
milestone since they were found, fixed, and verified in the same pass.

## The real issue / what changed

### 1. Detections filtering + "why triggered"

- `src/domain/detection.py`: `DetectionRuleMatch.query: str | None = None`
  — the real, compiled OpenSearch query DSL string SA evaluated to fire
  the rule. `None` for any `Detection` synced before this field existed
  (an honest absence — `Detection.rule_matches` is a frozen-once-created
  snapshot, roadmap invariant #6, so this is never retroactively
  backfilled).
- `src/application/detection_sync.py`: `_sync_one()` now captures
  `query=q.get("query")` from each real finding's `queries[]` entry.
- `src/adapter/repository/postgres_detection.py`: `_to_row`/`_from_row`
  updated for the new field (additive JSON key, no schema migration).
- `src/external/routes/detections.py`:
  - `DetectionRuleMatchOut.query` added; `_to_detection_out` maps it.
  - `list_detections` gained `severity`/`q` query params, additive
    in-memory filters over the org's own full detection stream (same
    idiom `triageState`/`caseId` already used) — `severity` matches
    `Detection.rule_severity` exactly (`SIGMA_SEVERITY_LEVELS`), `q` is a
    case-insensitive substring match against detector name or any
    matched rule's name/id.
  - New `GET /{detection_id}/matched-events` route: fetches the real
    timeline/stream documents behind a detection's own
    `matched_document_ids` via the already-real
    `AbstractTimelineIndex.get_documents_by_id` `_mget` primitive
    (`DetectionSyncService._resolve_risk_inputs` already uses the same
    primitive). Capped at 50 documents per request
    (`_MAX_MATCHED_EVENTS`), with an honest `truncatedFrom` signal rather
    than silent truncation. A missing/expired document id is simply
    absent from the response, never fabricated.
- Frontend: `Detection.ruleMatches[].query`, new `MatchedEvent` type,
  `getMatchedEvents()` API client function, severity dropdown + debounced
  free-text search on `DetectionsPage.tsx` (same debounce pattern
  `CaseMembersSection`'s search-as-you-type picker already uses),
  `DetectionDetailPage.tsx` now shows the real query string per matched
  rule (or an honest "not captured" message) and a new "Matched Events"
  section reusing `ArtifactViews.tsx`'s `GenericArtifactView` (wrapped as
  `{rows: [...]}`) rather than a new renderer.
- `ArtifactViews.tsx::formatCell` extended to `JSON.stringify` nested
  object/array cell values instead of the useless `"[object Object]"` —
  additive (existing Volatility rows are all primitives already), needed
  for matched events' nested ECS-shaped `source` content to render
  usefully in the generic table fallback.

### 2. Real user report: "the volatility analysis result is not available"

Investigated live against the real reported case
(`43097ab0-aae3-4968-915b-8f0229ac3865`, evidence `ch2.dmp`, 512 MiB,
`state=COMPLETE`). Full trail in `poc/volatility_worker_fallback_on_failure/README.md`.
Two real findings:

- **A genuine, real tool limitation for this specific sample**:
  volatility3's own automagic layer stacker cannot identify this image's
  Windows kernel/DTB at all (`WindowsIntelStacker hits: []`, `No suitable
  kernels found during pdbscan`) — both `windows.pstree` and
  `windows.psscan` fail identically with `Unsatisfied requirement
  plugins.*.kernel.layer_name`. Not something this cycle "fixes" (would
  need deeper volatility3-specific investigation into whether this is
  even a Windows image); documented as an honest, real outcome.
- **A real, fixable bug found investigating it**:
  `docker/volatility/kronos-volatility-worker.py`'s fallback-plugin logic
  was gated on `if not rows and args.fallback_plugin:` — reached only
  when the primary plugin exited **0** with an empty result. A non-zero
  primary exit returned `scan_error` immediately, **never attempting the
  fallback plugin at all**, even though a plugin-specific requirement
  failure doesn't guarantee every other plugin fails the same way (the
  entire reason the fallback exists, per this file's own `cridex.vmem`
  precedent). Fixed: a non-zero primary exit now falls through to the
  same fallback-attempt path an empty-rows result already took;
  `scan_error` is only emitted after the fallback has genuinely been
  tried too (or wasn't configured), with a strictly more informative
  combined error message.
- **The UX-layer consequence, also fixed**: `CaseDetailPage.tsx`'s
  `ArtifactsTab` showed the exact same generic "No forensic artifacts
  yet. Upload a memory dump..." empty state whether nothing was ever
  uploaded, a memory dump was still processing, or (this case) a memory
  dump genuinely finished processing with zero recoverable artifacts —
  actively misleading for the last case, and the direct cause of the
  report. Now distinguishes all three using the already-fetched evidence
  list (`MEMORY_DUMP_EXTENSIONS`, exported from `validateFileMagic.ts`
  rather than re-declared): still-processing shows a "still in progress"
  message; completed-with-nothing names the file(s) and points at the
  Audit tab for the real underlying error.

### 3. Unrelated, smaller fix landed at the start of this cycle

`frontend/src/utils/validateFileMagic.ts`'s client-side upload pre-check
never got a matching entry when Volatility/memory-dump support shipped
server-side — real `.vmem`/`.mem`/`.raw`/`.dmp`/`.lime` uploads were
rejected client-side ("Unsupported extension") before ever reaching the
backend's own (already-correct) `MagicByteValidator`. Fixed with the same
extension-only bypass shape `_MEMORY_DUMP_EXTENSIONS` already uses
server-side, checked *before* the MZ-header reject (raw physical memory
is arbitrary content and can coincidentally start with `0x4d 0x5a`
without being a Windows executable).

## Real, live verification (commands + actual captured output)

**Backend unit tests** (all real, not mocks of domain objects):
- `tests/unit/application/test_detection_sync.py`: 2 new tests
  (`test_stores_real_query_string_for_why_triggered_display`,
  `test_query_is_honestly_none_when_finding_predates_the_field`) — 22/22
  passed.
- `tests/unit/application/test_routes_detections.py`: 7 new tests across
  `TestListDetections` (query surfacing, pre-BBBBB null, severity filter,
  free-text filter x2) and new `TestGetMatchedEvents` (real documents,
  honest-absence, cross-org 404, nonexistent-id 404, truncation) — 43/43
  passed.
- Full backend suite: `~/venv/bin/python3 -m pytest -q --no-cov`:
  **2095 passed, 2 skipped**. `ruff check`/`mypy` clean on every changed
  file (two pre-existing, unrelated findings confirmed via `git diff` and
  left alone).

**Frontend unit tests**: `npx vitest run`: **116 passed** (16 files,
including 3 new memory-dump tests in `validateFileMagic.test.ts`).
`npx tsc -b` / `npx oxlint` clean on every changed file.

**Live PoC verification against the real dev stack**:
- Confirmed live, freshly (`curl` against `.opensearch-sap-network-findings-*`
  right now, not just trusting `poc/detection_finding_sync/`'s older
  captured output): real SA finding documents genuinely carry
  `queries[].query` with real compiled OpenSearch query DSL.
- `run_sync_org_findings_cycle()` invoked for real against the running
  `kronos-backend` container (`docker exec ... python -c "..."`) — ran
  clean against real Keycloak orgs and real OpenSearch findings, `{org:
  0, org: 0}` (idempotency held — no new real findings needed syncing at
  that moment).
- Real, authenticated Playwright script against the actual running
  backend confirmed a genuinely pre-existing real `Detection` row
  (`cc418d9d-...`, created by a prior real PoC) round-trips correctly:
  `ruleMatches[0].query` is honestly `null` (pre-BBBBB row), and
  `GET /{id}/matched-events` returns the real OpenSearch document behind
  it (`221aa1035977c68c5fc8027831ab078738bd38cc`, real
  `message: "10.0.0.7:55000 -> 10.0.0.1:443 (tcp)"`), confirmed the
  document still exists via a direct `curl` to real OpenSearch first.
- `frontend/e2e/fixtures/seed_detection.py --query "..." --severity high`
  run for real: seeded row confirmed in Postgres with the real query
  string and severity tag captured correctly.
- `npx playwright test e2e/detection-filtering.spec.ts
  e2e/detection-why-triggered.spec.ts`: **4/4 passed** against the real,
  rebuilt+redeployed dev-stack frontend (`docker compose -p docker -f
  docker-compose.dev.yml build nginx && up -d nginx`).
- `npx playwright test e2e/a11y.spec.ts -g "detections page|detection
  detail page"`: **2/2 passed**, no new WCAG violations from the new
  filter controls or the reused matched-events table.
- Real memory-dump worker fix: `docker exec docker-celery-worker-plaso-1
  python3 -c "...VolatilityLauncher().run(...)"` against the real,
  downloaded (via real `boto3`/MinIO) `ch2.dmp` file, before and after
  rebuilding+redeploying `celery-worker-plaso` — before: fallback never
  attempted; after: `"windows.pstree exited 1: ... (fallback windows.psscan
  also failed)"`, confirming the fallback genuinely ran.
- Real UI verification: a throwaway Playwright script logged in as the
  real dev-seeded `admin` account (case-lead isn't a member of this real,
  long-lived case — confirmed via a real `403` first) and confirmed the
  real reported case's Artifacts tab now shows "No process data could be
  recovered from the uploaded memory dump." / "ch2.dmp finished
  processing, but memory analysis found nothing usable..." instead of the
  generic empty state.
- `.github/workflows/security-integration-tests.yml` validated with
  `python3 -c "import yaml; yaml.safe_load(...)"` after adding the two
  new CI steps (with the real test-stack-profile OpenSearch password
  override, `KronOSCiTest#2026` — differs from the dev stack's own
  default the shared `_e2e_env.py` falls back to).

## Status

Both parts of the requested scope (filtering, why-triggered) are done and
live-verified end to end, plus the real, live-reported memory-dump bug
(worker-level and UX-level) is fixed and verified. Custom/user-managed
Sigma rule activation, per the owner's own "in the future" framing, is
explicitly **not** built this cycle.

## Recommendation for the next cycle

- `docs/HANDOFF_AND_ORCHESTRATION.md`'s Tier 1 list is fully closed (last
  item closed at Milestone ZZZZ) — Tier 2 remains blocked on host memory
  / no-GitHub-CI-execution / no k8s cluster (re-check `free -h` fresh
  before assuming still blocked), Tier 3 remains deliberately out of
  scope. No new Tier 1 work to report without inventing scope.
- If further volatility3 investigation into `ch2.dmp` is ever wanted (not
  requested), the next step would be trying `--offline`-mode symbol
  overrides or manually determining the image's real source OS/tool
  before assuming it's a Windows image volatility3 should recognize.
