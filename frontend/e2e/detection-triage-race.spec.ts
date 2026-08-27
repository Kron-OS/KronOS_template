import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DetectionDetailPage } from "./pages/DetectionDetailPage";
import { DetectionSeeder } from "./DetectionSeeder";

/**
 * Real, reproduced bug (coverage-gap subagent assessment, 2026-08-28):
 * two analysts triaging the same Detection near-simultaneously raced a
 * real optimistic-concurrency check
 * (PostgresDetectionRepository.update(..., expected_state=...)) that
 * correctly detected the conflict but surfaced it as a generic 503
 * (indistinguishable from a real infra outage), and the frontend's loser
 * tab kept showing the stale pre-race state indefinitely (no refetch on
 * error). Both fixed in src/exceptions.py (ConcurrentModificationError),
 * src/external/routes/detections.py, src/external/fastapi_app.py, and
 * frontend/src/pages/DetectionDetailPage.tsx. This test drives two real
 * browser contexts (two independent real logins, same shared dev account
 * -- sequential logins to avoid the already-known Keycloak concurrent-
 * login collision, see playwright.config.ts's own comment; only the
 * actual triage click races) against the real backend.
 */
test("real concurrent triage race: one 200, one real 409 (not 503), loser's UI recovers", async ({ browser }) => {
  test.setTimeout(60000);
  const seeded = new DetectionSeeder().seed(`E2E Race Spec ${Date.now()}`);

  const contextA = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const contextB = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageA = await contextA.newPage();
  const pageB = await contextB.newPage();

  try {
    // Sequential real logins (concurrent logins as the same account are a
    // real, separately-confirmed Keycloak collision -- see
    // playwright.config.ts). Only the triage click itself races below.
    const loginA = await LoginPage.open(pageA);
    await loginA.waitUntilReady();
    await loginA.loginWithSso("case-lead", "DevCaseLead#2026");

    const loginB = await LoginPage.open(pageB);
    await loginB.waitUntilReady();
    await loginB.loginWithSso("case-lead", "DevCaseLead#2026");

    const detailA = await DetectionDetailPage.openById(pageA, seeded.detectionId);
    const detailB = await DetectionDetailPage.openById(pageB, seeded.detectionId);

    const statusCodes: number[] = [];
    const captureStatus = (resp: import("@playwright/test").Response) => {
      if (resp.url().includes(`/api/detections/${seeded.detectionId}/triage`)) {
        statusCodes.push(resp.status());
      }
    };
    pageA.on("response", captureStatus);
    pageB.on("response", captureStatus);

    // The actual race: both real triage POSTs fired as close to
    // simultaneously as Playwright allows.
    await Promise.all([detailA.clickTriageAction("Start Investigating"), detailB.clickTriageAction("Start Investigating")]);

    await expect.poll(() => statusCodes.length, { timeout: 15000 }).toBeGreaterThanOrEqual(2);

    const successes = statusCodes.filter((s) => s === 200);
    const conflicts = statusCodes.filter((s) => s === 409);
    const serverErrors = statusCodes.filter((s) => s >= 500);

    expect(serverErrors, `observed status codes: ${statusCodes.join(", ")}`).toHaveLength(0);
    expect(successes, `observed status codes: ${statusCodes.join(", ")}`).toHaveLength(1);
    expect(conflicts, `observed status codes: ${statusCodes.join(", ")}`).toHaveLength(1);

    // Both tabs' UIs must converge on the real current state -- including
    // the loser's, which previously stayed frozen on stale "New".
    await expect.poll(() => detailA.triageStateLabel(), { timeout: 10000 }).toBe("Investigating");
    await expect.poll(() => detailB.triageStateLabel(), { timeout: 10000 }).toBe("Investigating");
  } finally {
    await contextA.close();
    await contextB.close();
  }
});
