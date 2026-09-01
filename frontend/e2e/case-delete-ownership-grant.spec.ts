import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), the positive counterpart
 * to `case-delete-ownership-denial.spec.ts` -- closes Milestone LLLL's own
 * recommendation: `delete_case` (`src/external/routes/cases.py`) had zero
 * E2E coverage on either branch before this pair. No second account is
 * needed here (unlike the denial spec): the static `case-lead` dev user
 * always owns whatever case it creates itself, so `assert_case_lead_or_admin`'s
 * ALLOW branch is exercised directly.
 *
 * `delete_case` is a soft archive, not a row deletion --
 * `case.with_status(CaseStatus.ARCHIVED)` -- confirmed by reading the
 * route before writing this: `CaseRepository.get_by_id` has no status
 * filter (`postgres_case.py`), so a subsequent `GET /api/cases/{id}`
 * still returns `200` with `status: "archived"`, which is exactly what
 * this spec asserts to prove the mutation genuinely persisted, not just
 * that the DELETE call itself returned the right code.
 */
test("a real case-lead who owns this case can delete/archive it", async ({ page }) => {
  test.setTimeout(45000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  const cases = await login.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);

  await cases.createCase(
    `E2E Case-Delete-Grant Case ${Date.now()}`,
    `E2E-DEL-GRANT-${Date.now()}`,
  );
  const caseId = page.url().split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${page.url()}`).toBeTruthy();

  const status = await cases.attemptDeleteCase(caseId);
  expect(
    status,
    "case-lead deleting/archiving a case it owns must be a real, successful mutation",
  ).toBe(204);

  // Fresh, independent GET (not trusted from the same page/session state
  // that issued the DELETE) confirms the archive genuinely persisted --
  // asserting on the real status transition, not just that the row is
  // still readable.
  const archived = await cases.fetchCaseById(caseId);
  expect(archived.id).toBe(caseId);
  expect(archived.status.toLowerCase()).toBe("archived");
});
