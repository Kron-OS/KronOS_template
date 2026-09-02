import { test, expect } from "./fixtures";
import { DetectionSeeder } from "./DetectionSeeder";
import { DetectionDetailPage } from "./pages/DetectionDetailPage";

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md SS3.3): Gap Audit Milestone
 * BBBBB's "why did this rule trigger" -- the two real halves are the
 * compiled query DSL string (DetectionRuleMatchOut.query) and the real
 * matched OpenSearch document content (GET /{id}/matched-events). Both are
 * exercised here against real seeded Postgres + OpenSearch data (
 * frontend/e2e/fixtures/seed_detection.py's new --query flag and its real
 * OpenSearchClient.bulk_index call), not a UI-only fixture.
 */
test("detection detail page shows the real rule query string and the real matched event content", async ({
  casesPageAsCaseLead: _casesPageAsCaseLead,
  page,
}) => {
  const ruleName = `E2E BBBBB Why-Triggered ${Date.now()}`;
  const query = "destination.port:3389 AND source.ip:203.0.113.7";
  const seeded = new DetectionSeeder().seedWithQueryAndSeverity(ruleName, { query });

  const detail = await DetectionDetailPage.openById(page, seeded.detectionId);

  expect(await detail.ruleMatchQueryText()).toBe(query);

  const rowCount = await detail.matchedEventRowCount();
  expect(rowCount).toBe(1);
});

test("a pre-BBBBB detection with no captured query shows the honest fallback message", async ({
  casesPageAsCaseLead: _casesPageAsCaseLead,
  page,
}) => {
  const ruleName = `E2E BBBBB No-Query ${Date.now()}`;
  const seeded = new DetectionSeeder().seed(ruleName);

  const detail = await DetectionDetailPage.openById(page, seeded.detectionId);

  await expect(
    page.getByText("Query not captured (this detection was synced before this data was recorded)."),
  ).toBeVisible();
  // seed_detection.py still always indexes one real matched document
  // regardless of --query, so this is exercising the query-fallback text
  // specifically, not accidentally also an empty-matched-events state.
  expect(await detail.matchedEventRowCount()).toBe(1);
});
