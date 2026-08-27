import { test, expect } from "./fixtures";
import { DetectionSeeder } from "./DetectionSeeder";
import { DetectionDetailPage } from "./pages/DetectionDetailPage";

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.3 / §5 item 4): real
 * NEW -> INVESTIGATING triage transition through the UI, confirmed both
 * live in the DOM (no reload) and independently via a fresh real API call
 * per the plan's own requirement ("not trusted from the same page load").
 * Detection is seeded fresh per run (frontend/e2e/fixtures/seed_detection.py).
 * Navigates directly to the real detection URL rather than through the
 * list (see DetectionDetailPage.openById's own comment for why).
 */
test("real triage transition NEW -> INVESTIGATING updates live and persists", async ({
  casesPageAsCaseLead: _casesPageAsCaseLead, // real login side effect only -- navigating directly by URL below
  page,
}) => {
  const ruleName = `E2E Triage Spec ${Date.now()}`;
  const seeded = new DetectionSeeder().seed(ruleName);

  const detail = await DetectionDetailPage.openById(page, seeded.detectionId);

  expect(await detail.triageStateLabel()).toBe("New");

  await detail.clickTriageAction("Start Investigating");

  await expect
    .poll(async () => detail.triageStateLabel(), { timeout: 10000 })
    .toBe("Investigating");

  const persisted = await detail.fetchRealTriageStateFromApi(seeded.detectionId);
  expect(persisted).toBe("INVESTIGATING");
});
