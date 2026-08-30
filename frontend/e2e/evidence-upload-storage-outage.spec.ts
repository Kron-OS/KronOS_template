import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { TestStackFaultInjector } from "./TestStackFaultInjector";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2), test-stack profile
 * only (docker-compose.test.yml, via TestStackFaultInjector -- NOT the
 * dev-stack-only DevStackFaultInjector evidence-retry.spec.ts uses).
 * Milestone QQQ: the coverage-gap review that led here originally
 * suggested exercising an INTAKE-stage retry the same way
 * evidence-retry.spec.ts exercises a PARSE-stage one (stop a dependency
 * before upload, expect a client-visible ERROR, restart, click Retry).
 * That doesn't actually work for MinIO the way it does for OpenSearch:
 * intake never touches OpenSearch, so stopping it before upload always
 * lands cleanly on a retryable ERROR with no timing risk -- but MinIO
 * sits in the upload's OWN first synchronous step
 * (`POST /api/evidence/upload/request` -> `ensure_quarantine_bucket()`,
 * src/adapter/storage/s3.py), so stopping it before upload fails the
 * REQUEST itself, synchronously, before any evidence row is even
 * created -- confirmed live, not raced. This spec covers that real,
 * different failure shape instead of forcing the racier one.
 *
 * Real bug found and fixed getting this far (src/components/UploadDrawer.tsx):
 * retrying the same file after MinIO recovered showed the OLD "Request
 * failed with status code 500" text forever in the dialog, even though
 * the retry itself succeeded and the evidence really did reach Complete
 * in the table behind it -- the success-path state update spread the
 * previous per-file state without clearing `error`, so the render's
 * `f.error ? <error> : f.done ? "Done" : ...` branch never reached
 * "Done". Fixed by clearing `error: null` on both progress and success.
 */
test("upload fails cleanly when storage is down, and a real retry recovers without a stale error", async ({
  casesPageAsCaseLead,
  page,
}) => {
  test.setTimeout(120000);
  const injector = new TestStackFaultInjector();
  const title = `E2E storage-outage spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-OUTAGE-${Date.now()}`);

  // Force a real, deterministic upload-request failure: MinIO down
  // before the request ever fires, not raced against celery-worker.
  injector.stopMinio();

  try {
    await detail.startUpload(CLOUDTRAIL_SAMPLE);
    const errorText = await detail.waitForUploadRequestError();
    expect(errorText).toContain("Request failed with status code 500");

    // No evidence row should exist yet -- the request never got far
    // enough to create one.
    await expect(page.locator(`tr:has-text('cloudtrail.json')`)).toHaveCount(0);

    // Real recovery: bring MinIO back, then retry the SAME already-open
    // dialog (the real user action after fixing what failed), then
    // confirm the dialog itself reaches "Done" -- not just that the
    // evidence eventually appears, which the pre-fix bug would have
    // passed too (the underlying upload always succeeded on retry; only
    // the dialog's own stale error text was wrong).
    await injector.restartMinioAndWaitHealthy();
    await detail.retryUploadAndWaitForDone();

    const recovered = await detail.watchEvidenceStateLive("cloudtrail.json", 60000);
    expect(recovered.terminal, `observed state sequence: ${recovered.seenStates.join(" -> ")}`).toBe("Complete");
  } finally {
    await injector.ensureRunning();
  }
});
