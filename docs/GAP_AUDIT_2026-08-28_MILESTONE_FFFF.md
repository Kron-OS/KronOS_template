# Gap Audit — Milestone FFFF (2026-08-31)

**Scope:** Milestone QQQ's own explicitly-declined item — a real, deterministic
E2E spec for a dependency failing **during the intake stage** (after `POST
/api/evidence/upload/finalize/{id}` but before `process_intake` completes),
closing the "intake-stage retry has zero E2E coverage" gap Milestone TTT's
coverage-gap review named again and every cycle since has carried forward.
QQQ investigated forcing MinIO down mid-intake specifically and explicitly
declined to build a flaky test for it. This cycle's job was to actually
solve that, or find a genuinely different real dependency/failure-point
combination that IS reliably forceable. It was solved — with a real,
previously-unknown backend bug found and fixed along the way, and one real,
honestly-scoped item left incomplete due to a directly measured host
resource constraint.

---

## Why MinIO still doesn't work, and what does instead

Re-confirmed QQQ's own finding by reading the current code, not just
trusting the old doc: `start_intake()` (`src/application/evidence_intake.py`,
called from the `finalize_upload` route) does a synchronous
`storage.object_exists()` HEAD check against MinIO *before* it ever enqueues
`kronos.process_intake`. Stopping MinIO before `finalize` still just fails
that synchronous call — there is no way to get a real, client-visible,
*retryable* evidence row into existence with MinIO down, so MinIO is a dead
end for this scenario, exactly as QQQ found.

Reading further (`process_intake`'s Celery task, `src/external/celery_app.py`,
and `EvidenceIntakeService.process_intake`/`_run_scan`,
`src/application/evidence_intake.py`, `src/application/scanning.py`)
surfaced a genuinely different real dependency with the right shape: the AV
scanner. `_run_scan()` calls `ClamAVScanner.scan_stream()` — a **separate**
real dependency from MinIO, invoked only from inside the Celery task, never
synchronously from `finalize_upload`. Stopping ClamAV *before* the upload
even starts (same recipe as `DevStackFaultInjector`'s existing OpenSearch
target) lets the real PUT and `finalize` both succeed normally — MinIO is
untouched — and `process_intake`'s own first real attempt then
deterministically fails reaching ClamAV: `asyncio.open_connection()`
against a stopped container raises `OSError` (connection refused) near
instantly, not a hung timeout, so there is no timing window to lose. This
was already proven **API-level** in a prior session
(`poc/evidence_intake_async/README.md`, "Transient error, real ClamAV
outage": 14/14 checks passed) — that PoC's own "Not yet done" section named
exactly what was still missing: *"A real browser click-through of the Retry
button succeeding."* That is this milestone.

## Fixed this cycle

1. **Real, previously-undiscovered gap: `docker-compose.test.yml`'s
   `celery-worker` never set `CLAMD_HOST`/`CLAMD_PORT` at all.** Unlike
   `kronos-backend` (which has had this since Milestone HHH),
   `celery-worker` is the service that actually calls `scan_stream()` — left
   unset, `Settings.clamd_host` defaults to `"localhost"` (unreachable
   inside the container), and `configure_clamav_from_settings()`'s
   dev/test-mode fallback silently downgrades to the permissive
   `NoOpScanner` for that worker's entire process lifetime. This means **no
   file uploaded through this profile has ever been genuinely AV-scanned**,
   independent of anything this milestone's own spec does — the same class
   of gap `poc/evidence_intake_async/README.md` already found and fixed for
   `docker-compose.dev.yml`/`.prod.yml`, just missed for this file. Fixed
   by mirroring `docker-compose.dev.yml`'s own already-correct values, plus
   `depends_on: clamav: { condition: service_healthy }` so the worker's
   one-shot startup probe can't race clamd's own virus-DB reload (measured
   ~15s in the original PoC). Also added `clamav` to
   `security-integration-tests.yml`'s "bring up base services" step for
   fail-fast clarity (Compose would already pull it in transitively via the
   new `depends_on`, but every other base service is named explicitly there
   too).

2. **Real, previously-undiscovered, reproduced-live frontend/backend race:
   a successful retry's SSE reconnect can permanently miss its own
   recovery.** Found while getting the FIRST live run of the new spec to
   pass (against the already-running dev stack, zero extra containers —
   see "Verification" below for why that stack was used). First attempt:
   the backend genuinely recovered (`process_intake` retried → `RECEIVED`
   → `dispatch_parse` → `parse_artefact_fast` → `finalize_evidence`, all
   within ~2.4s, confirmed in real `celery-worker` logs) but the UI stayed
   frozen on the stale `Error` state for the full 150s poll window — not a
   test bug (a fresh page load *did* show `Complete`, both the table row
   and drawer never got there live).

   Root-caused via the Playwright trace's own captured network timing plus
   `celery-worker`/`kronos-backend` logs, cross-referenced against
   `src/external/routes/sse.py`: `EvidenceDetailDrawer.tsx`'s retry
   mutation dispatches `kronos:sse-reconnect` (Milestone SSS's own fix for
   a *different*, already-closed variant of this bug) the instant the
   retry HTTP response lands, opening a **brand new** SSE connection with
   a fresh, empty `last_states` dict. `evidence_sse_stream`'s
   `event_generator()` unconditionally checked "stop once all evidence is
   terminal" on *every* iteration, including the very first one — and
   because `process_intake`'s own exception handling (unlike
   `execute_parse`'s `is_final_attempt`-gated version) lands evidence on a
   client-visible `ERROR` after every single failed attempt, not just the
   final one, there is a real window where a just-reconnected stream's
   first poll still observes the pre-retry `ERROR` (the retried Celery task
   genuinely had not landed its first state-changing write yet — observed
   live: the reconnect's own SSE `GET` and the retried task's `Task
   received` log landed within milliseconds of each other). The stream
   concluded "nothing left to watch," sent `done`, and closed — for good,
   since a `done` closure (unlike `onerror`) never starts the client's
   polling fallback and the one-shot ticket was already consumed. The
   evidence went on to genuinely complete a couple of seconds later with
   nothing left listening.

   **Fix** (`src/external/routes/sse.py`): a connection may never conclude
   "done" on its own first observation, full stop — it must see a state
   persist across at least one complete `_POLL_INTERVAL_SECONDS` cycle
   before treating it as stably terminal. This closes the exact race
   without weakening the real "stop once genuinely done" behavior for the
   overwhelmingly common case (a stream that was open and watching well
   before its subject ever went terminal). Verified: re-ran the exact same
   live scenario after the fix — passed clean (2.7 min). Also re-ran
   `evidence-retry.spec.ts` (the parse-stage sibling, same SSE machinery,
   much slower real recovery time so it was never exposed to this exact
   race) to confirm no regression — still passes (2.3 min, matching its own
   documented duration).

   Added a real, non-mocked regression test,
   `tests/unit/test_sse_routes.py::test_does_not_close_on_first_observation_even_if_already_terminal`
   — a small sequenced `EvidenceRepository` double returns `ERROR` then
   `COMPLETE` on successive polls (no real sleeping/threading needed) and
   asserts the stream emits *both* status events before `done`, proving it
   kept watching past the first, still-terminal observation. Also fixed a
   real, would-be-reintroduced regression in the *existing*
   `test_valid_ticket_consumed_once`: that test relied on the pre-fix
   behavior of closing on the first observation to avoid a real
   `asyncio.sleep()`; without patching `_POLL_INTERVAL_SECONDS` down for
   the test, this fix would have made it take a genuine 5 real seconds
   (`monkeypatch.setattr` added, matching CLAUDE.md B.6's <5s-suite
   budget). Full `tests/unit` suite: **1923 passed, 1 skipped (pre-existing),
   17.07s**, confirming no other regression.

3. **New E2E coverage, both profiles built:**
   - `frontend/e2e/DevStackClamAVFaultInjector.ts` +
     `frontend/e2e/evidence-intake-retry-dev-stack.spec.ts` — targets
     `docker-clamav-1` (real dev stack, zero extra containers). **Live-run,
     twice** (once pre-fix reproducing the bug above, once post-fix
     passing), plus a third time back-to-back with `login.spec.ts` +
     `evidence-upload.spec.ts` + `evidence-retry.spec.ts` to confirm no
     interference — all 4 passed in one 5.1-minute run. Deliberately **not**
     wired into `frontend-e2e-smoke`, mirroring `evidence-retry.spec.ts`'s
     own established precedent (that job only ever builds the isolated
     `docker-compose.test.yml` profile).
   - `frontend/e2e/TestStackClamAVFaultInjector.ts` +
     `frontend/e2e/evidence-intake-retry.spec.ts` — the CI-wired,
     test-stack-profile twin (targets `kronos-test-clamav-1`), same
     mechanism, plus an extra independent-GET assertion (fresh
     `GET /api/cases/{id}/evidence`, not trusted from the same page load,
     per `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.3) confirming
     `errorReason`/`retryAction` and the final server-persisted state.
     `CaseDetailPage.fetchEvidenceByFilename()` added to support this,
     reusing the existing `fetchJson()` helper. **See "Not completed this
     cycle" below — this file is code-complete and config-validated but has
     not had a full live isolated-stack run.**
   - `docker/docker-compose.test.local-verify.override.yml`: added
     `clamav: ports: !override []` — a real, reproduced port collision (this
     host's dev stack already holds `3310` unremapped) hit and fixed while
     attempting the isolated-stack verification below, the same class of
     gap this file's own header comment already warns about for
     Postgres/Keycloak.

## Not completed this cycle (honest account, not hidden)

`evidence-intake-retry.spec.ts` (the test-stack, CI-wired spec) has **not**
had a full live isolated-stack run — i.e., it has not itself been proven
against a real `kronos-test-clamav-1` inside a fully built `kronos-test`
stack with `celery-worker`/`kronos-backend`/`nginx` all built and running,
the way every prior fault-injection spec (QQQ, SSS) was before being wired
into CI. It is **not** wired into `security-integration-tests.yml` as a
result — CLAUDE.md §F's own bar ("actually run it and read the output" is
verification; "it follows the pattern" is not) is not met for this specific
config, even though the identical application code (`sse.py`,
`evidence_intake.py`, `scanning.py`, the frontend retry path) is proven via
the dev-stack twin above.

This was a deliberate stop, not an oversight. Attempting the standard
verification recipe (`docker/docker-compose.test.local-verify.override.yml`,
bringing up `postgres redis minio opensearch keycloak clamav`) hit a real,
directly measured resource wall on this host **before a single image build
even started**:

```
$ free -h   # immediately after the 6 base services (no builds) reported healthy
               total        used        free      shared  buff/cache   available
Mem:           7.1Gi       5.9Gi       946Mi        20Mi       653Mi       1.2Gi
Swap:          4.0Gi       4.0Gi        40Mi
```

Swap was fully exhausted with only `postgres`/`redis`/`minio`/`opensearch`/
`keycloak`/`clamav` running alongside the already-running dev stack — before
even attempting the `kronos-backend`/`celery-worker` image builds that
would come next (real, meaningful additional memory pressure of their own,
per every prior cycle's own account). Continuing risked either an ENOSPC/OOM
failure mid-build (wasted time, worse diagnostics) or, worse, an OOM-killer
picking a victim from the **already-running dev stack** the user explicitly
asked not to be disrupted. The isolated stack was torn down immediately
(`down -v --remove-orphans`); the dev stack was confirmed untouched
(`docker ps`, all 15 containers, unchanged) both before and after.

This is the same class of judgment call Milestone YYY already made
explicit ("verified against the live dev stack ... given genuinely tight
host memory headroom") — applied here to a case where the CI-representative
profile genuinely could not be safely stood up at all this cycle, not just
where it was more convenient to skip.

What partial verification the test-stack spec **does** have:
- `docker compose -f docker-compose.test.yml config -q` and the same with
  the local-verify override layered on top — both pass, confirming no YAML/
  schema regression.
- The real `postgres`/`redis`/`minio`/`opensearch`/`keycloak`/`clamav`
  services **do** boot to `healthy` under this exact, modified
  `docker-compose.test.yml` (captured in the same run that hit the memory
  wall above) — including `clamav` itself, the one service this milestone's
  fix specifically touches.
- `npx tsc --noEmit`, `oxlint`, and a full `npm run build` all pass clean
  for `evidence-intake-retry.spec.ts`/`TestStackClamAVFaultInjector.ts`.

What is genuinely unverified: whether `celery-worker`'s *build* picks up
the new `CLAMD_HOST`/`CLAMD_PORT` env vars correctly at runtime and
actually reaches `kronos-test-clamav-1` by DNS name inside that specific
container's network namespace, and whether the real browser spec passes
end to end through `nginx`/TLS in that profile. This is assessed as
low-risk (identical pattern to every other already-proven service-to-service
hostname resolution in this same file — `minio`, `opensearch`, `postgres`,
`redis` all resolve the same way for the same two containers today — and
the exact same application code is proven correct via the dev-stack twin),
but "low-risk by inference" is explicitly not the bar CLAUDE.md §F sets,
and this doc says so plainly rather than rounding it up to "done."

## Status

- Real, deterministic, non-flaky intake-stage retry coverage exists and is
  **live-verified**, closing the substance of the gap named since QQQ/TTT.
- A real, previously-unknown, reproduced-live bug (premature SSE stream
  closure racing an in-flight retry) is fixed, unit-tested, and verified
  not to regress the existing parse-stage sibling spec.
- A real, independently-valuable ClamAV-wiring bug in
  `docker-compose.test.yml` is fixed and partially verified (config +
  real container health), closing a silent-scanning gap that predates and
  is broader than this milestone's own spec.
- The CI-wired (test-stack) spec is code-complete, not yet CI-wired,
  pending a live isolated-stack dry run this cycle's own host resources
  could not safely support.

## Recommendation for the next cycle

1. Re-attempt `evidence-intake-retry.spec.ts`'s full isolated-stack dry run
   (`docker/docker-compose.test.local-verify.override.yml`, matching
   QQQ/SSS's own recipe exactly) once host memory headroom allows, then
   wire it into `frontend-e2e-smoke` as the 15th step — this is the single
   remaining item to fully close this gap per CLAUDE.md §F's own bar.
2. The SSE race fixed here was specifically found via *fast* recovery
   (intake-stage, ~2.4s total). Parse-stage retries have not been observed
   to hit this window in practice (OpenSearch indexing + Plaso/heavy-parser
   timing is typically much slower), but nothing in the fix or the domain
   model guarantees that — a heavy-parser retry-parse spec that happens to
   recover unusually fast could theoretically hit the same pre-fix race.
   Worth a quick, cheap confirmation the next time a heavy-parser retry
   spec is touched, not urgent enough to justify manufacturing a fast
   heavy-parser scenario just to test it.
3. Otherwise, the still-open items from Milestones TTT/QQQ/SSS
   (RBAC/CI-reliability follow-ups already tracked elsewhere,
   §3.6-§3.8 of the E2E plan) remain open per those cycles' own
   recommendations.
