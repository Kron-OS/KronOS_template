# Gap Audit — Milestone QQQ (2026-08-29)

**Scope:** Milestone PPP's own recommendation #1 (cheapest item) — a
real error/retry-path spec against `docker-compose.test.yml`, closing
the "only happy-path coverage exists" gap the last cycle's coverage-gap
review flagged. The literal suggestion ("reuse `DevStackFaultInjector`-
style fault injection targeted at `q.intake`/MinIO instead of
OpenSearch") turned out not to be directly implementable — investigating
it for real surfaced a genuine architectural difference between MinIO
and OpenSearch's failure shapes, and along the way, a real,
previously-undiscovered UI bug.

---

## Why the original suggestion needed rethinking

`evidence-retry.spec.ts`'s OpenSearch-outage pattern works because
**intake never touches OpenSearch at all** — stopping it *before* upload
always lands cleanly on a retryable parse-stage `ERROR`, no timing risk.
MinIO doesn't have that clean separation: `POST
/api/evidence/upload/request` calls `ensure_quarantine_bucket()` (a real
`head_bucket` call, `src/adapter/storage/s3.py`) as its *first*
synchronous step, before any presigned URL is even returned. Reading
`process_intake`'s own retry mechanics
(`src/external/celery_app.py`/`src/application/evidence_intake.py`)
confirmed a further complication: a genuine MinIO outage *during* intake
gets Celery's own automatic retry (`max_retries=3,
default_retry_delay=30`) with no client-visible `ERROR` state on most
attempts — reliably forcing evidence into a *client-visible, retryable*
intake-stage `ERROR` via black-box E2E would mean racing a narrow window
between upload-request success and celery-worker's own processing, with
no clean "always fails" story the way OpenSearch has.

Rather than build a flaky, race-dependent spec to match the original
suggestion literally, investigated what actually happens when MinIO is
down from the very start of an upload attempt instead — a related, real,
and **fully deterministic** scenario the existing 6 specs also never
cover (every prior spec assumes storage is healthy throughout).

## The bug found

Confirmed live: with MinIO stopped, the upload dialog shows a real
inline error ("Request failed with status code 500"), no evidence row is
ever created, no crash. Restarting MinIO and clicking "Upload" again on
the same still-open dialog (the real user action, not a fresh file
picker) **succeeded** — the evidence genuinely reached `Complete` in the
table — but the dialog's own per-file status text kept showing the OLD
"Request failed with status code 500" message forever, never switching
to "Done".

Root cause, found in `frontend/src/components/UploadDrawer.tsx`'s
`handleUpload()`: the success-path state update
(`{ ...f, progress: 100, done: true }`) spreads the previous per-file
state without clearing `error`, and the render logic checks
`f.error ? <error text> : f.done ? "Done" : ...` — `error` first, so a
stale truthy `error` from an earlier failed attempt permanently masked
`done: true` in the UI, even though the underlying upload had genuinely
succeeded. A real, previously-undiscovered, confirmed UI bug — not a
test artifact.

## The fix

`error: null` added to both the progress-update and success-path state
updates, plus an explicit `done: false` on the failure path for
symmetry, plus clearing every file's `error` the moment a new upload
attempt begins (`handleUpload()`'s own start, before the async work) so
the stale message doesn't even flash briefly before the new attempt's
first progress event. Verified live: rebuilt the frontend image, re-ran
the exact same stop-MinIO → fail → restart-MinIO → retry sequence —
retry now correctly shows "Done".

## What shipped

- `frontend/src/components/UploadDrawer.tsx`: the fix above.
- `frontend/e2e/ContainerFaultInjector.ts`: new shared base class for
  stop/restart/ensure-running mechanics, extracted from
  `DevStackFaultInjector` the moment a second fault injector needed the
  same shape — per this initiative's own Cycle 13 lesson (create the
  shared module at the *second* instance of a pattern, not after a third
  silently drifts). `DevStackFaultInjector` now extends it, with its
  existing public API (`stopOpenSearch()`, etc.) unchanged — verified no
  behavior change by re-running `evidence-retry.spec.ts` against the
  live dev stack (still passes, ~2.5 min, matching its own documented
  duration).
- `frontend/e2e/TestStackFaultInjector.ts`: new class, targets
  `kronos-test-minio-1` (the real container name
  `docker-compose.test.yml`'s own `name: kronos-test` produces when run
  without an explicit `-p`, exactly matching how the real CI job invokes
  it), asserting the Compose project label before acting (same guard as
  `DevStackFaultInjector`).
- `frontend/e2e/pages/CaseDetailPage.ts`: three new methods
  (`startUpload`, `waitForUploadRequestError`,
  `retryUploadAndWaitForDone`) — `uploadEvidence()`'s own success-only
  assumption doesn't fit a spec that needs to observe a failure
  *during* the upload dialog itself, unlike `evidence-retry.spec.ts`'s
  failure (which happens well after the dialog completes normally).
- `frontend/e2e/evidence-upload-storage-outage.spec.ts`: the new spec.
- `.github/workflows/security-integration-tests.yml`: wired in as a 6th
  `frontend-e2e-smoke` step.

## Verification (CLAUDE.md §F)

Real, live investigation before any code was written: confirmed the 500
error and the stale-error-text bug live, via a real Chromium browser
against a freshly-built isolated stack, *before* concluding what the fix
should be. After fixing:

1. New spec run alone against a freshly-built isolated stack (project
   `kronos-test`, no `-p` override — the file's own declared name,
   matching exactly what the real CI job produces, confirmed by
   inspecting the actual container names) — **passed**.
2. `evidence-retry.spec.ts` re-run against the live dev stack to confirm
   the `ContainerFaultInjector` refactor didn't change
   `DevStackFaultInjector`'s behavior — **passed** (2.5 min, matching its
   own documented expected duration).
3. Full mirror of the final, committed 6-step CI sequence (login,
   evidence-upload, detection-triage, detection-triage-race,
   cross-tenant-isolation, evidence-upload-storage-outage) run as 6
   separate `npx playwright test` invocations against one more
   freshly-built `kronos-test`-named isolated stack — **6 passed**.
4. Frontend unit test suite (`npm test`) — **104/104 passed**, confirming
   the `UploadDrawer.tsx` fix didn't regress anything already covered.

Isolated stacks torn down after each step (`down -v --remove-orphans` +
built-image cleanup); live dev stack (`docker ps`, project `docker`, 15
containers) confirmed untouched throughout every step.

## Status

`frontend-e2e-smoke` now runs all 6 `frontend/e2e/` specs — the entire
existing suite. Real error/retry-path coverage now exists for both the
parse stage (OpenSearch, dev-stack profile) and the upload-request stage
(MinIO, test-stack profile). A genuine, previously-shipped UI bug is
fixed and locked in by a permanent regression test.

## Recommendation for the next cycle

1. `evidence-retry.spec.ts` itself is still dev-stack-only — porting it
   to the test-stack profile (using the new `TestStackFaultInjector`
   pattern, needs its own target/timing investigation since OpenSearch's
   own container name/health-check shape differs) would complete
   error-path parity across both profiles.
2. Heavy-parser CI coverage (Milestone PPP's recommendation #2, still
   open) — add a `plaso-worker` service to `docker-compose.test.yml`
   mirroring dev, plus a heavy-format fixture sample.
3. Otherwise: `security-stack` also booting `kronos-backend`, RBAC
   access-denial specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8
   remain open per prior milestones' own still-standing recommendations.
   With the entire existing `frontend/e2e/` suite now CI-wired, this may
   also be a natural point for a fresh multi-scenario subagent
   assessment (per this initiative's own cycle instructions) once this
   cycle's work has had a chance to run for real on GitHub Actions.
