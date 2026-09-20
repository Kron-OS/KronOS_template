import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";
import { DevStackFaultInjector } from "./DevStackFaultInjector";
import { DevStackClamAVFaultInjector } from "./DevStackClamAVFaultInjector";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/cloudtrail.json");

/**
 * Closes the named gap in STATUS.md's known-gaps section: every existing
 * fault-injection spec (evidence-retry.spec.ts, evidence-intake-retry-dev-stack.spec.ts,
 * evidence-upload-storage-outage.spec.ts, ...) targets exactly ONE real
 * dependency, fully down. This is the first with TWO real dependencies down
 * at once (ClamAV -- gates INTAKE/SCANNING -- and OpenSearch -- gates
 * PARSE/indexing), specifically to check the pipeline attributes the
 * failure to the correct stage rather than hanging, crashing, or reporting
 * a confusing/merged error when two independent failure domains are down
 * simultaneously, and that recovery correctly walks through each failure
 * domain in turn rather than skipping straight to COMPLETE the moment only
 * one of the two dependencies comes back.
 */
test("evidence upload survives ClamAV+OpenSearch both down, then recovers through each stage in turn", async ({
  casesPageAsCaseLead,
}, testInfo) => {
  // Three real stop/restart cycles across two dependencies, each with its
  // own real Celery auto-retry backoff to drain -- budget generously.
  testInfo.setTimeout(900000);
  const clamavInjector = new DevStackClamAVFaultInjector();
  const openSearchInjector = new DevStackFaultInjector();
  const title = `E2E dual-outage spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-DUAL-OUTAGE-${Date.now()}`);
  const caseId = detail.url.split("/cases/")[1];

  clamavInjector.stopClamAV();
  openSearchInjector.stopOpenSearch();

  try {
    // Both dependencies down: upload should still land deterministically on
    // the INTAKE-stage error, not hang and not get confused about which of
    // the two down dependencies is responsible -- ClamAV is the first real
    // gate (SCANNING happens before parsing ever touches OpenSearch).
    await detail.uploadEvidence(CLOUDTRAIL_SAMPLE);

    const firstFailure = await detail.watchEvidenceStateLive("cloudtrail.json", 60000);
    expect(firstFailure.terminal, `observed state sequence: ${firstFailure.seenStates.join(" -> ")}`).toBe("Error");

    const afterFirstFailure = await detail.fetchEvidenceByFilename(caseId, "cloudtrail.json");
    expect(afterFirstFailure?.errorReason, "errorReason after ClamAV+OpenSearch both down").toContain(
      "intake_failed:",
    );
    expect(afterFirstFailure?.retryAction, "retryAction after ClamAV+OpenSearch both down").toBe("intake");

    // Drain process_intake's own auto-retry budget (max_retries=3 @ 30s,
    // same real reasoning as evidence-intake-retry-dev-stack.spec.ts) so the
    // manual retry below can't race a concurrent auto-retry re-entering
    // SCANNING.
    await new Promise((resolve) => setTimeout(resolve, 130000));

    // Restore only ClamAV. OpenSearch is still down -- retrying should now
    // get PAST the intake gate for real, then fail again, this time at the
    // PARSE stage, rather than either succeeding (it can't -- OpenSearch is
    // still down) or reporting a stale/misattributed intake_failed reason.
    await clamavInjector.restartClamAVAndWaitHealthy();

    await detail.openEvidenceDrawer("cloudtrail.json");
    await detail.clickRetry();
    await detail.closeEvidenceDrawer();

    const secondFailure = await detail.watchEvidenceStateLive("cloudtrail.json", 150000, "Error");
    expect(
      secondFailure.terminal,
      `observed state sequence after ClamAV-only recovery: ${secondFailure.seenStates.join(" -> ")}`,
    ).toBe("Error");

    const afterSecondFailure = await detail.fetchEvidenceByFilename(caseId, "cloudtrail.json");
    expect(afterSecondFailure?.errorReason, "errorReason after ClamAV-only recovery").toBe("ingest_failed");
    expect(afterSecondFailure?.retryAction, "retryAction after ClamAV-only recovery").toBe("parse");

    // Drain parse_artefact_fast's own auto-retry budget (max_retries=3 @
    // 30s, same real reasoning as evidence-retry.spec.ts) before the final
    // manual retry.
    await new Promise((resolve) => setTimeout(resolve, 130000));

    // Now restore OpenSearch too -- both dependencies real again. Final
    // retry should reach real COMPLETE.
    await openSearchInjector.restartOpenSearchAndWaitHealthy();

    await detail.openEvidenceDrawer("cloudtrail.json");
    await detail.clickRetry();

    const recovered = await detail.watchEvidenceStateLive("cloudtrail.json", 150000, "Error");
    expect(
      recovered.terminal,
      `observed state sequence after full recovery: ${recovered.seenStates.join(" -> ")}`,
    ).toBe("Complete");

    const final = await detail.fetchEvidenceByFilename(caseId, "cloudtrail.json");
    expect(final?.state, "final server-confirmed state").toBe("COMPLETE");
    expect(final?.retryAction, "retryAction after full recovery").toBeNull();
  } finally {
    await clamavInjector.ensureRunning();
    await openSearchInjector.ensureRunning();
  }
});
