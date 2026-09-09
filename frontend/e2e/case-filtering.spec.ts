import { test, expect } from "./fixtures";

/**
 * Flow tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md SS3.3): Milestone IIIII's
 * real multi-parameter Cases filtering (q/status/classification/sort),
 * pushed into PostgresCaseRepository's own dynamic SQL WHERE/ORDER BY.
 * Creates two real cases via the actual UI (CasesPage.createCase already
 * proven by every other case-lifecycle spec) with distinct, unique titles
 * so the search filter can be asserted against the org's full real case
 * history (this dev org has accumulated hundreds of cases from prior
 * E2E/PoC runs) without colliding with any pre-existing row.
 */
test("free-text search finds a real case by title across the org's full history", async ({
  casesPageAsCaseLead,
  page,
}) => {
  const uniqueToken = `E2EIIIIISearch${Date.now()}`;
  const title = `${uniqueToken} Ransomware Incident`;
  await casesPageAsCaseLead.createCase(title, `REF-${uniqueToken}`);

  await page.goto("/cases");
  await page.getByLabel("Search cases").fill(uniqueToken);
  await page.waitForTimeout(500);

  await expect(page.getByText(title)).toBeVisible();
  const cardCount = await page.locator("a", { hasText: uniqueToken }).count();
  expect(cardCount).toBe(1);
});

test("status filter narrows the real cases list to archived cases only", async ({
  casesPageAsCaseLead,
  page,
}) => {
  const uniqueToken = `E2EIIIIIStatus${Date.now()}`;
  const title = `${uniqueToken} To Archive`;
  await casesPageAsCaseLead.createCase(title, `REF-${uniqueToken}`);
  const caseId = page.url().split("/cases/")[1];

  // Archive it via the same real, already-proven route
  // (attemptDeleteCase -> DELETE /api/cases/{id}, a soft archive --
  // DeleteCaseSection's own UI button already has dedicated coverage in
  // case-delete-archive-ui.spec.ts; this spec is about the filter, not
  // re-proving archival itself).
  const status = await casesPageAsCaseLead.attemptDeleteCase(caseId);
  expect(status).toBe(204);

  await page.goto("/cases");
  await page.getByLabel("Search cases").fill(uniqueToken);
  await page.waitForTimeout(500);
  await page.getByRole("button", { name: "Archived", exact: true }).click();

  await expect(page.getByText(title)).toBeVisible();
});
