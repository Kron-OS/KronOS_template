import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * Milestone RRRR: delete_case had been fully built, tested, and audited
 * (Milestone MMMM) with zero frontend UI ever reaching it -- every prior
 * spec exercised it via a raw, direct fetch (`CasesPage.attemptDeleteCase()`).
 * This spec drives the real UI instead: the new "Danger Zone" section in
 * the Settings tab (`DeleteCaseSection`, `frontend/src/pages/CaseDetailPage.tsx`),
 * including its two-step confirm flow (a bare click must NOT delete
 * anything -- only "Confirm Delete" does).
 */
test("a case-lead can archive their case through the real Settings UI, with a real two-step confirm", async ({
  page,
}) => {
  test.setTimeout(45000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  const cases = await login.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);

  const caseTitle = `E2E Delete-Archive-UI Case ${Date.now()}`;
  const detail = await cases.createCase(caseTitle, `E2E-DEL-UI-${Date.now()}`);
  const caseId = page.url().split("/cases/")[1];

  await detail.openSettingsTab();

  // The first click only reveals the confirm step -- must NOT have
  // deleted anything yet. A fresh, independent GET (not trusted from the
  // same page load) confirms the case is still genuinely open.
  await page.getByRole("button", { name: "Delete / Archive Case", exact: true }).click();
  await page.getByText("Are you sure?").waitFor({ timeout: 10000 });
  const beforeConfirm = await cases.fetchCaseById(caseId);
  expect(beforeConfirm.status).toBe("open");

  await page.getByRole("button", { name: "Confirm Delete", exact: true }).click();

  // Real navigation back to the cases list on success.
  await page.waitForURL("**/cases", { timeout: 15000 });

  // Milestone SSSS: the cases LIST view (CasesPage.tsx's CaseCard) also
  // shows a real "Archived" badge, not just the detail page -- this is
  // the very page the redirect above just landed on, so the badge must
  // already be visible without any extra navigation. Scoped to THIS
  // case's own card (by its unique title) -- the dev stack's /cases list
  // already has other archived cases from unrelated prior spec runs, so a
  // bare page-wide "Archived" text match wouldn't actually prove this
  // card's own badge rendered.
  const thisCaseCard = page.locator("a", { hasText: caseTitle });
  await thisCaseCard.getByText("Archived", { exact: true }).waitFor({ timeout: 10000 });

  // Fresh, independent GET confirms the archive genuinely persisted.
  const afterConfirm = await cases.fetchCaseById(caseId);
  expect(afterConfirm.status).toBe("archived");

  // Navigating back to the case directly shows the real "Archived" badge
  // and the Settings tab's own archived-state message, not the
  // delete button again.
  await page.goto(`/cases/${caseId}`);
  await page.getByText("Archived", { exact: true }).waitFor({ timeout: 10000 });
  await detail.openSettingsTab();
  await page.getByText("This case has been archived.").waitFor({ timeout: 10000 });
});
