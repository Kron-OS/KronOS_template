import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { TestStackOpenSearchFaultInjector } from "./TestStackOpenSearchFaultInjector";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2), test-stack profile
 * only (docker-compose.test.yml, via TestStackOpenSearchFaultInjector --
 * NOT the dev-stack-only DevStackFaultInjector evidence-retry.spec.ts
 * uses). Milestone SSS: the test-stack analogue of that spec, closing
 * the parity gap Milestone QQQ's own recommendation named -- QQQ covered
 * the upload-REQUEST-stage failure shape (MinIO), this covers the
 * PARSE-stage failure shape (OpenSearch), completing real error/retry
 * coverage for both failure shapes on this profile, matching what
 * already existed for the dev stack.
 *
 * Identical structure to evidence-retry.spec.ts by design (same real
 * dependency-failure shape: intake never touches OpenSearch at all, only
 * parsing/indexing does, so stopping it BEFORE upload always lands
 * cleanly on a retryable parse-stage ERROR, no race window to time,
 * unlike MinIO's own upload-request-stage failure Milestone QQQ had to
 * design around differently) -- only the fault injector and the
 * celery-worker requirement (this profile needs it started explicitly,
 * unlike the dev stack where it's always running) differ.
 */
test("real Retry button recovers a transient parse-stage error to COMPLETE (test-stack profile)", async ({
  casesPageAsCaseLead,
}, testInfo) => {
  // Same real timing as evidence-retry.spec.ts: reaching a real ERROR
  // can take up to ~2 minutes (parse_artefact_fast's own max_retries=3
  // with a real 30s countdown between attempts,
  // src/external/celery_app.py), restarting OpenSearch can take up to
  // 90s to report healthy again.
  testInfo.setTimeout(420000);
  const injector = new TestStackOpenSearchFaultInjector();
  const title = `E2E test-stack retry spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-TS-RETRY-${Date.now()}`);

  // Force a real, transient parse-stage failure: intake doesn't touch
  // OpenSearch at all, only indexing does, so stopping it before upload
  // reliably lands evidence on ERROR/ingest_failed rather than racing a
  // timing window mid-flight.
  injector.stopOpenSearch();

  try {
    await detail.uploadEvidence(CLOUDTRAIL_SAMPLE);

    const failed = await detail.watchEvidenceStateLive("cloudtrail.json", 150000);
    expect(failed.terminal, `observed state sequence: ${failed.seenStates.join(" -> ")}`).toBe("Error");

    // Real recovery: bring the real dependency back, then drive the real
    // Retry button, then confirm the pipeline reaches COMPLETE live.
    await injector.restartOpenSearchAndWaitHealthy();

    await detail.openEvidenceDrawer("cloudtrail.json");
    await detail.clickRetry();

    const recovered = await detail.watchEvidenceStateLive("cloudtrail.json", 150000, "Error");
    expect(recovered.terminal, `observed state sequence after retry: ${recovered.seenStates.join(" -> ")}`).toBe(
      "Complete",
    );
  } finally {
    injector.ensureRunning();
  }
});
