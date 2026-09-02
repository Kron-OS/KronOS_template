import { test, expect } from "./fixtures";
import { DetectionSeeder } from "./DetectionSeeder";
import { DetectionsPage } from "./pages/DetectionsPage";

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md SS3.3): Gap Audit Milestone
 * BBBBB's severity dropdown + free-text search on the real /detections
 * list. Both filters are real backend query params (severity/q,
 * src/external/routes/detections.py's list_detections), applied over the
 * ORG'S FULL detection history before pagination -- this repo's dev-stack
 * kronos-dev org has accumulated 1000+ real detections from prior PoC/E2E
 * runs, so a search that only checked the current page would be a much
 * weaker test than one that proves server-side filtering actually works
 * across that whole history. Seeds two detections with distinct, unique
 * rule names and distinct severities so both filters can be asserted
 * independently without colliding with any pre-existing real row.
 */
test("free-text search finds a seeded detection by rule name across the org's full history", async ({
  casesPageAsCaseLead: _casesPageAsCaseLead,
  page,
}) => {
  const uniqueToken = `E2EBBBBBSearch${Date.now()}`;
  const ruleName = `${uniqueToken} Suspicious RDP`;
  new DetectionSeeder().seed(ruleName);

  const list = await DetectionsPage.open(page);
  await list.searchByText(uniqueToken);

  await expect.poll(() => list.visibleRuleNames()).toEqual([ruleName]);
});

test("severity filter shows only detections at the selected real severity", async ({
  casesPageAsCaseLead: _casesPageAsCaseLead,
  page,
}) => {
  const uniqueToken = `E2EBBBBBSeverity${Date.now()}`;
  const criticalName = `${uniqueToken} Critical Rule`;
  const lowName = `${uniqueToken} Low Rule`;
  new DetectionSeeder().seedWithQueryAndSeverity(criticalName, { severity: "critical" });
  new DetectionSeeder().seedWithQueryAndSeverity(lowName, { severity: "low" });

  const list = await DetectionsPage.open(page);
  // Narrow to just these two seeded rows first via the free-text box (the
  // severity filter alone would still be correct against 1000+ real rows,
  // but asserting an exact-length array is far more legible scoped down
  // to what this test actually seeded).
  await list.searchByText(uniqueToken);
  await expect
    .poll(() => list.visibleRuleNames())
    .toEqual(expect.arrayContaining([criticalName, lowName]));

  // expect.poll (not a bare await+assert): switching the severity <select>
  // triggers a real, unwaited network refetch -- allInnerTexts() is a
  // one-shot DOM snapshot with no auto-retry, so reading it immediately
  // after selectOption() can race a brief loading-spinner render (real,
  // observed flake against this org's 1700+-row real detection history).
  await list.filterBySeverity("critical");
  await expect.poll(() => list.visibleRuleNames()).toEqual([criticalName]);

  await list.filterBySeverity("low");
  await expect.poll(() => list.visibleRuleNames()).toEqual([lowName]);
});
