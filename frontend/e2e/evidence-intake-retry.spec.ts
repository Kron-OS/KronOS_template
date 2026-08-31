import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { TestStackClamAVFaultInjector } from "./TestStackClamAVFaultInjector";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2), test-stack profile
 * only (docker-compose.test.yml, via TestStackClamAVFaultInjector).
 *
 * Milestone FFFF: closes the gap named since Milestone QQQ ("intake-stage
 * retry has zero E2E coverage") and explicitly declined there as too
 * racy to build against MinIO (MinIO sits in the upload's own first
 * SYNCHRONOUS step, `POST /api/evidence/upload/request` ->
 * `ensure_quarantine_bucket()`, so stopping it before upload fails the
 * request itself, before a real "client-visible retryable ERROR row"
 * ever exists to retry -- see evidence-upload-storage-outage.spec.ts).
 *
 * Real investigation (src/application/evidence_intake.py,
 * src/external/celery_app.py, src/application/scanning.py) found a
 * genuinely different, real dependency that IS deterministically
 * forceable the same way OpenSearch already is for the parse stage: the
 * AV scanner. `start_intake()` (the finalize route) only touches MinIO
 * synchronously (a HEAD `object_exists` check); it never touches ClamAV.
 * The real AV-scan call (`_run_scan` -> `ClamAVScanner.scan_stream()`)
 * only happens later, inside `kronos.process_intake` (Celery, off the
 * request thread). So: stop ClamAV BEFORE the upload even starts (same
 * recipe as `DevStackFaultInjector`'s OpenSearch target) -- MinIO stays
 * healthy throughout, the real PUT and finalize both succeed normally,
 * a real evidence row is created and enters intake -- and
 * `process_intake`'s own first real attempt deterministically fails
 * reaching ClamAV. Confirmed by reading `ClamAVScanner.scan_stream()`:
 * `asyncio.open_connection()` against a stopped container raises `OSError`
 * (connection refused) near-instantly, not a hung timeout -- no race
 * window to time, unlike MinIO's synchronous-first-step shape.
 *
 * This exact backend mechanism (stop docker-clamav-1, real upload, real
 * ERROR/`intake_failed:StorageError`, real `retry-intake` recovering to
 * COMPLETE) was already proven API-level against the real dev stack in
 * `poc/evidence_intake_async/run_poc.py` (14/14 checks passed,
 * `output.txt`) -- what that PoC's own "Not yet done" section explicitly
 * named as still missing is a real BROWSER click-through of the Retry
 * button succeeding for a retryable reason. This spec closes that.
 *
 * A real, previously-undiscovered gap was found and fixed getting this
 * far: docker-compose.test.yml's `celery-worker` (the service that
 * actually calls `scan_stream()`, NOT `kronos-backend`, which already had
 * this) never set `CLAMD_HOST`/`CLAMD_PORT` at all --
 * `configure_clamav_from_settings()`'s dev/test-mode fallback silently
 * downgrades to the permissive `NoOpScanner` when clamd is unreachable at
 * worker startup, so no file uploaded through this profile was ever
 * genuinely AV-scanned before this fix, regardless of what this spec
 * did. Fixed by mirroring docker-compose.dev.yml's own already-correct
 * values, plus a `depends_on: clamav: service_healthy` so the worker's
 * one-shot startup probe can't race clamd's own DB-load time (see
 * TestStackClamAVFaultInjector's own docstring for the measured ~15s
 * finding this guards against).
 *
 * Real, code-confirmed timing note (different from
 * evidence-parse-retry.spec.ts's OpenSearch case): `process_intake`'s own
 * exception handling (EvidenceIntakeService.process_intake, the
 * `except Exception` branch) is NOT gated on `is_final_attempt` the way
 * `execute_parse` is for the parse stage -- it lands evidence on a
 * client-visible ERROR after EVERY failed attempt, not just the final
 * one (confirmed by grepping celery_app.py: `parse_artefact_fast`/
 * `_heavy` both compute and pass `is_final_attempt` into
 * `execute_parse`/`start_parsing`; `process_intake` never computes or
 * passes any such flag into `EvidenceIntakeService.process_intake`).
 * That means ERROR appears within seconds of finalize here, not ~2
 * minutes -- but it also means Celery's own scheduled auto-retry
 * (`max_retries=3, default_retry_delay=30`, `src/external/celery_app.py`)
 * is STILL pending after that first ERROR is observed. Restarting ClamAV
 * and clicking Retry immediately would risk a real, code-confirmed race:
 * a concurrent auto-retry re-entering ERROR -> SCANNING at the same time
 * as this test's own manual retry-intake, where the loser's
 * `expected_state`-guarded `repo.update()` call would raise a conflict
 * that `process_intake`'s own broad `except Exception` handler would
 * misclassify as a fresh intake failure and stamp back over the winner's
 * legitimate in-flight SCANNING state. This is NOT a "hand-tuned sleep
 * racing a real network call" (the thing CLAUDE.md Section F warns
 * against) -- it is a generously-bounded wait for a fully-KNOWN, cited
 * Celery schedule (3 retries x 30s + per-attempt overhead, ~90-120s
 * worst case) to finish draining before this test does anything else,
 * the same category of wait evidence-parse-retry.spec.ts's own
 * `testInfo.setTimeout(420000)` already budgets for, just applied before
 * intervening instead of before the first observation.
 */
test("real Retry button recovers a transient INTAKE-stage error to COMPLETE (test-stack profile)", async ({
  casesPageAsCaseLead,
}, testInfo) => {
  testInfo.setTimeout(480000);
  const injector = new TestStackClamAVFaultInjector();
  const title = `E2E intake-retry spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-INTAKE-RETRY-${Date.now()}`);
  const caseId = detail.url.split("/cases/")[1];

  // Force a real, deterministic INTAKE-stage failure: ClamAV down before
  // upload even starts. MinIO is untouched (stays healthy), so the real
  // PUT and finalize both succeed -- only process_intake's own later
  // AV-scan step fails, deterministically, on its very first attempt.
  injector.stopClamAV();

  try {
    await detail.uploadEvidence(CLOUDTRAIL_SAMPLE);

    const failed = await detail.watchEvidenceStateLive("cloudtrail.json", 60000);
    expect(failed.terminal, `observed state sequence: ${failed.seenStates.join(" -> ")}`).toBe("Error");

    // Confirm, independently (fresh GET, not trusted from the same page
    // load), that this really is the retryable INTAKE-stage reason this
    // spec exists to exercise -- not a coincidental different failure.
    const errored = await detail.fetchEvidenceByFilename(caseId, "cloudtrail.json");
    expect(errored?.errorReason, "errorReason").toContain("intake_failed:");
    expect(errored?.retryAction, "retryAction").toBe("intake");

    // See this spec's own top-of-file docstring for why this wait is
    // real, bounded, and NOT a "hand-tuned sleep racing a network call":
    // it drains Celery's own already-scheduled auto-retry budget
    // (max_retries=3 @ default_retry_delay=30s) so the manual retry below
    // can never race a concurrent auto-retry re-entering SCANNING.
    await new Promise((resolve) => setTimeout(resolve, 130000));

    // Real recovery: bring the real dependency back, then drive the real
    // Retry button, then confirm the pipeline reaches COMPLETE live.
    await injector.restartClamAVAndWaitHealthy();

    await detail.openEvidenceDrawer("cloudtrail.json");
    await detail.clickRetry();

    const recovered = await detail.watchEvidenceStateLive("cloudtrail.json", 150000, "Error");
    expect(recovered.terminal, `observed state sequence after retry: ${recovered.seenStates.join(" -> ")}`).toBe(
      "Complete",
    );

    // Independent confirmation the recovery genuinely persisted
    // server-side, matching this plan's own §3.3 "not trusted from the
    // same page load" requirement.
    const final = await detail.fetchEvidenceByFilename(caseId, "cloudtrail.json");
    expect(final?.state, "final server-confirmed state").toBe("COMPLETE");
    expect(final?.retryAction, "retryAction after recovery").toBeNull();
  } finally {
    await injector.ensureRunning();
  }
});
