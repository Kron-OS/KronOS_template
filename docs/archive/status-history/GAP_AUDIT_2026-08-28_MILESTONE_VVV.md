# Gap Audit — Milestone VVV (2026-08-30)

**Scope:** closes Milestone UUU's own recommendation #1 — extend HEAVY-tier
(`q.parse.plaso`) CI coverage beyond Plaso alone to the archive-container
(`ZipArchiveParser`) and EWF/E01 whole-image (`PlasoParser`'s dfVFS routing)
paths, the two remaining HEAVY-tier code paths with zero real browser E2E
coverage. Along the way, a real, previously-unknown, live-verified bug in
`POST /api/cases` was found and fixed — not a hypothetical, it directly
caused a test failure during this cycle's own verification.

---

## Fixed this cycle

### 1. New spec: `frontend/e2e/evidence-upload-heavy-parser-archive.spec.ts`

Two tests, reusing real fixtures already committed and already verified
backend-only (`tests/fixtures/samples/real/kape/`, see that directory's own
`NOTICE.md` and `poc/kape_ingestion_test/` — 631 real OpenSearch documents,
zero flagged parsing errors, from a prior cycle's backend-only Python-script
verification):

- `kape_triage.zip` — real container recursion through `ZipArchiveParser`
  (unconditionally HEAVY, even though every one of its 4 real inner members
  — EVTX, Prefetch, Chrome History, an IIS-style access log — is itself
  FAST-path). Reaches `Complete` in ~12-17s.
- `kape_triage.E01` — a real EWF/E01 disk image (FAT16, built with real
  `ewfacquirestream`); `PlasoParser`'s magic-byte routing hands the whole
  image to `log2timeline`/`psort`, which auto-detects "storage media image"
  via dfVFS and walks the FAT filesystem itself (414 real events in the
  prior backend-only run). Reaches `Complete` in ~17-22s.

Both were already fully verified at the backend level in a prior cycle; this
is the first time either has been driven through a real BROWSER upload
against `docker-compose.test.yml`'s own `celery-worker-plaso` (added in
Milestone UUU). No new fixtures needed — both files were already sitting in
the repo, already magic-byte-validated client- and server-side (confirmed
by reading `frontend/src/utils/validateFileMagic.ts` and
`src/application/validation.py`'s `_MAGIC_TABLE` before writing the spec,
not assumed).

Wired into `.github/workflows/security-integration-tests.yml` as a 9th E2E
step, `if: always()`, matching every other step's shape. `timeout-minutes`
left at `70` (Milestone UUU) — the new step's own real measured cost
(~35s) is well inside existing headroom.

### 2. Real bug found and fixed: `POST /api/cases` could block for 15+ seconds, contradicting its own code comment

While first running the new E01 test, case creation itself (not the
upload) timed out against `CasesPage.createCase()`'s own 15000ms wait for
the newly-created case to appear. Investigated via real backend logs rather
than assumed to be a flaky test:

- `src/external/routes/cases.py`'s `create_case` handler directly
  `await`ed both `dashboards_provisioner.ensure_case_index_pattern(...)`
  and `detector_provisioner.ensure_org_detectors(...)` in the request path
  — despite each call site's own comment explicitly saying "must not block
  case creation."
- `SecurityAnalyticsDetectorProvisioner.ensure_org_detectors` (
  `src/adapter/opensearch/detector_provisioner.py`) only swallows
  **errors** per log type (`except httpx.HTTPError`), not **slowness** —
  each log type's detector-create call shares one `httpx.AsyncClient(timeout=15)`.
- Real backend logs showed a genuine 15-second gap between the "windows"
  detector's rules-search response and the next log line
  (`detector_provisioning_failed`, `log_type: windows`, `error: ""` — an
  empty message is exactly what a bare `httpx.TimeoutException` stringifies
  to). The "windows" prepackaged Sigma rule set is far larger than
  cloudtrail/network's, and OpenSearch Security Analytics' real
  detector-create endpoint took long enough (under real, if modest, load —
  this was the org's second case, not its first) to exceed the hardcoded
  15s client timeout. cloudtrail/network's own detector-create calls
  succeeded in ~1.5-2s each in the same run.
- Net effect: the entire `POST /api/cases` HTTP response — not just
  detector provisioning — hung for the full duration, directly
  contradicting "must not block case creation." This is a real,
  reproducible degraded-UX bug for any real user creating a case while
  OpenSearch Security Analytics is doing first-time (or contended) work for
  their org, not a synthetic edge case — it happened on this cycle's own
  second real case-creation call, unprompted.

**Fixed**: both provisioner calls now run via FastAPI's `BackgroundTasks`
(`background_tasks.add_task(...)`) instead of being awaited inline —
actually fulfilling the "must not block case creation" contract the
comments already claimed, for the first time. Both provisioners are
self-contained (their own `httpx.AsyncClient` per call, no request-scoped
resource like a DB session used after the response), confirmed by reading
both classes before making this change — safe for `BackgroundTasks`
without needing a heavier mechanism (e.g. routing through Celery).

**Verified, not assumed**: rebuilt `kronos-backend` in the isolated stack,
re-ran the exact same E01 scenario that had just failed — passed, and case
creation across every spec in the same run became visibly near-instant
(previously up to ~18s for a case hitting the slow path). Confirmed via
backend logs that the "windows" detector for the test org did eventually
get created successfully (idempotent check-then-create, self-healing on a
later case's own background-task retry) — the underlying OpenSearch-side
slowness is real and unfixed (out of scope: it's a real Security Analytics
plugin characteristic, not a KronOS defect), but it no longer blocks any
user-facing request. `ruff`/`mypy` clean on the changed file; existing
`tests/unit/test_cases_routes.py` (37 tests, none touching these two
provisioners) still passes with no changes needed.

## Verified live

Full real-CI-order regression (all 8 `frontend-e2e-smoke` specs, plus the
2 new archive-spec tests — 10 tests total) run against one freshly-built,
isolated `kronos-test`-named stack, after the case-creation fix landed:
all 10 passed, ~3.6 minutes total. (A broader, non-representative run
against literally every `frontend/e2e/*.spec.ts` file also surfaced two
false alarms from running this profile's specs without the required
`+asyncpg` DSN scheme and against dev-stack-only `evidence-retry.spec.ts`
with no dev stack running — both self-inflicted invocation mistakes, not
real findings; re-run correctly, both resolved.)

## Documented, not fixed this cycle

1. `SecurityAnalyticsDetectorProvisioner`'s per-log-type 15s httpx timeout
   is still real and can still be hit (now harmlessly, in the background,
   with a retry on the next case creation for that org) — a longer timeout
   or a real backoff/retry-with-jitter inside the provisioner itself would
   be the more complete fix, not attempted this cycle since the
   user-facing blocking behavior (the actual bug) is what mattered most
   and is now closed.
2. `DashboardsIndexPatternProvisioner.ensure_case_index_pattern` shares the
   exact same "await'd despite a 'must not block' comment" shape and was
   fixed identically, but was not independently observed to actually stall
   for real during this cycle (Dashboards' own index-pattern API is
   much cheaper than Security Analytics' detector-create) — flagged so a
   future cycle doesn't assume it was reproduced when it wasn't.
3. VolatilityModule (`extract_artifacts()`, real memory-forensics output as
   `StructuredArtifact`) has no frontend read API or UI at all — confirmed
   by grepping every route in `src/external/routes/` and every frontend
   component for `artifact`/`StructuredArtifact`. This is intentional
   product direction, not a gap: `CLAUDE.md` §G.2 states the design
   decision explicitly ("capture and store safely now, design
   presentation/analysis later"). Documented here only so a future cycle
   doesn't mistake the missing UI for an oversight and rush to build it.
4. Carried unchanged from Milestone TTT/UUU: intake-stage retry has zero
   E2E coverage; no spec covers two simultaneous dependency failures or a
   degraded-not-hard-down dependency; `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`
   §3.6-§3.8; Milestone RRR's "no workflow has ever run on real GitHub
   Actions" finding remains true as of this cycle's check.

## Status

Both remaining HEAVY-tier code paths (`ZipArchiveParser` container
recursion, `PlasoParser`'s EWF/E01 routing) now have real browser E2E
coverage wired into CI, closing the coverage gap Milestone UUU's own
recommendation named. `q.parse.plaso` (all three parsers that route to it:
Plaso direct, archive/EWF, and — not yet covered — VolatilityModule) is no
longer a blind spot for the two most common real-world shapes (a single
forensic artifact, and a KAPE-style triage bundle). The case-creation
finding was not something this cycle went looking for — it surfaced
directly from real verification catching a real, reproducible discrepancy
between a code comment's stated contract and the code's actual behavior,
exactly the class of bug CLAUDE.md §F's verification-first discipline
exists to catch. Fixed, verified live, and confirmed to improve (not
regress) every other spec's own case-creation timing in the same run.

## Recommendation for the next cycle

1. VolatilityModule (`.vmem`/`.mem` memory-forensics ingestion) is the one
   HEAVY-tier parser still with zero CI coverage of any kind (E2E or
   otherwise, beyond `poc/volatility_memory_module/`) — but per §G.2's
   explicit product direction, there is no frontend surface to E2E-test
   yet (no read API, no UI). The next real increment here is a
   backend-only integration test (real upload → `celery-worker-plaso` →
   `ArtifactIngestService` → confirm a real `StructuredArtifact` row in
   Postgres), not a browser spec — matching what actually exists to test.
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain open.
4. Periodically re-check Milestone RRR's finding (no workflow has ever run
   against this branch).
5. If `DashboardsIndexPatternProvisioner`'s own background-tasked call is
   ever observed stalling for real (item 2 above), apply the same
   "increase timeout or add backoff" fix `SecurityAnalyticsDetectorProvisioner`
   itself still needs.
