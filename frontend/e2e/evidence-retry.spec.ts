import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { DevStackFaultInjector } from "./DevStackFaultInjector";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.2 / §5 item 3): closes a
 * named, real, previously-open gap. poc/evidence_parse_retry/README.md
 * already proved the real retry-parse route/pipeline works (13/13 checks,
 * including a real docker-opensearch-1 outage forcing ERROR/ingest_failed,
 * then real recovery to COMPLETE) but explicitly left "a real browser
 * click-through of the Retry button succeeding" unverified, after an
 * earlier Python-script attempt hit selector/routing trouble and wasn't
 * worth chasing further at the time. This is that attempt, on top of the
 * now-working Playwright TS foundation.
 */
test("real Retry button recovers a transient parse-stage error to COMPLETE", async ({ casesPageAsCaseLead }, testInfo) => {
  // Default 30s test timeout is too short for this spec's real work:
  // upload + wait for a real ERROR, restart a real OpenSearch container
  // (can take up to 90s to report healthy again), retry, wait for real
  // COMPLETE. Confirmed live (first run hit the default and was killed
  // mid-poll, not stuck). Second real finding: parse_artefact_fast
  // (src/external/celery_app.py) retries up to max_retries=3 with a real
  // 30s countdown between attempts before landing on ERROR -- confirmed
  // via real celery-worker logs ("Retry in 30s") -- so reaching ERROR
  // alone can genuinely take ~2 minutes, not the 60s watchEvidenceStateLive
  // defaults to.
  testInfo.setTimeout(420000);
  const injector = new DevStackFaultInjector();
  const title = `E2E retry spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-RETRY-${Date.now()}`);

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
