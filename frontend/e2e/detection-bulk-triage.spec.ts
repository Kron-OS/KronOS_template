import { test, expect } from "./fixtures";
import { DetectionSeeder } from "./DetectionSeeder";
import { DetectionsPage } from "./pages/DetectionsPage";

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md SS3.3): Milestone IIIII's
 * default-NEW view + bulk triage action on the real /detections list.
 * Seeds real detections via the same PostgresDetectionRepository-backed
 * fixture DetectionSeeder already uses (frontend/e2e/fixtures/seed_detection.py),
 * then exercises the real multi-select checkboxes + POST
 * /api/detections/bulk-triage through the real browser UI -- not a direct
 * API call, since the analyst-facing selection UI is exactly what's new
 * this cycle.
 */
test("default view on load shows only NEW detections", async ({
  casesPageAsCaseLead: _casesPageAsCaseLead,
  page,
}) => {
  const uniqueToken = `E2EIIIIIDefault${Date.now()}`;
  const newName = `${uniqueToken} New Rule`;
  const investigatingName = `${uniqueToken} Investigating Rule`;
  new DetectionSeeder().seed(newName);
  new DetectionSeeder().seedAtTriageState(investigatingName, "INVESTIGATING");

  const list = await DetectionsPage.open(page);
  await list.searchByText(uniqueToken);

  // Default view is triageState=NEW only -- the INVESTIGATING row must not
  // appear until the analyst explicitly widens the filter.
  await expect.poll(() => list.visibleRuleNames()).toEqual([newName]);

  await list.selectTriageStatePill("All");
  await expect
    .poll(() => list.visibleRuleNames())
    .toEqual(expect.arrayContaining([newName, investigatingName]));
});

test("bulk-selecting multiple NEW detections and marking them Investigating transitions all of them", async ({
  casesPageAsCaseLead: _casesPageAsCaseLead,
  page,
}) => {
  const uniqueToken = `E2EIIIIIBulk${Date.now()}`;
  const firstName = `${uniqueToken} First`;
  const secondName = `${uniqueToken} Second`;
  new DetectionSeeder().seed(firstName);
  new DetectionSeeder().seed(secondName);

  const list = await DetectionsPage.open(page);
  await list.searchByText(uniqueToken);
  await expect
    .poll(() => list.visibleRuleNames())
    .toEqual(expect.arrayContaining([firstName, secondName]));

  await list.selectAllOnPage();
  await list.clickBulkAction("Mark Investigating");
  await expect(page.getByText("2 detections updated.")).toBeVisible();

  // The default view is filtered to triageState=NEW -- both rows correctly
  // fall out of it the instant they transition, exactly like any other
  // filtered list. Widen to "All" to confirm the real, persisted new state
  // (not just the success toast).
  await list.selectTriageStatePill("All");
  await expect.poll(() => list.triageStateForRow(firstName)).toBe("Investigating");
  await expect.poll(() => list.triageStateForRow(secondName)).toBe("Investigating");
});
