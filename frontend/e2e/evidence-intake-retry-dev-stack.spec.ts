import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { DevStackClamAVFaultInjector } from "./DevStackClamAVFaultInjector";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * Dev-stack twin of `evidence-intake-retry.spec.ts` -- see that file's own
 * top-of-file docstring for the full real investigation (Milestone FFFF:
 * why ClamAV, stopped BEFORE upload, deterministically forces a real,
 * retryable INTAKE-stage error, unlike MinIO). This is this cycle's
 * primary LIVE verification vehicle: this host's already-running dev
 * stack needed zero extra containers (a real, observed constraint this
 * session -- standing up an isolated `kronos-test` stack alongside it
 * drove free memory to under 1Gi with swap fully exhausted, confirmed via
 * `free -h`, before even starting the heavy `kronos-backend`/
 * `celery-worker` image builds -- see
 * docs/GAP_AUDIT_2026-08-28_MILESTONE_FFFF.md).
 *
 * Mirrors `evidence-retry.spec.ts`'s own precedent exactly: deliberately
 * NOT wired into `frontend-e2e-smoke` (that CI job only ever builds the
 * isolated `docker-compose.test.yml` profile) -- `evidence-intake-retry.spec.ts`
 * is the CI-wired test-stack twin.
 */
test("real Retry button recovers a transient INTAKE-stage error to COMPLETE (dev stack)", async ({
  casesPageAsCaseLead,
}, testInfo) => {
  testInfo.setTimeout(480000);
  const injector = new DevStackClamAVFaultInjector();
  const title = `E2E intake-retry dev-stack spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-INTAKE-RETRY-DEV-${Date.now()}`);
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

    const errored = await detail.fetchEvidenceByFilename(caseId, "cloudtrail.json");
    expect(errored?.errorReason, "errorReason").toContain("intake_failed:");
    expect(errored?.retryAction, "retryAction").toBe("intake");

    // See evidence-intake-retry.spec.ts's own docstring for why this wait
    // is real, bounded, and not a "hand-tuned sleep racing a network
    // call": it drains Celery's own already-scheduled auto-retry budget
    // (process_intake: max_retries=3 @ default_retry_delay=30s) so the
    // manual retry below can never race a concurrent auto-retry
    // re-entering SCANNING.
    await new Promise((resolve) => setTimeout(resolve, 130000));

    await injector.restartClamAVAndWaitHealthy();

    await detail.openEvidenceDrawer("cloudtrail.json");
    await detail.clickRetry();

    const recovered = await detail.watchEvidenceStateLive("cloudtrail.json", 150000, "Error");
    expect(recovered.terminal, `observed state sequence after retry: ${recovered.seenStates.join(" -> ")}`).toBe(
      "Complete",
    );

    const final = await detail.fetchEvidenceByFilename(caseId, "cloudtrail.json");
    expect(final?.state, "final server-confirmed state").toBe("COMPLETE");
    expect(final?.retryAction, "retryAction after recovery").toBeNull();
  } finally {
    await injector.ensureRunning();
  }
});
