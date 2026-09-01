import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { SecondCaseLeadSeeder } from "./SecondCaseLeadSeeder";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), closing the one remaining
 * uncovered call site of `assert_case_lead_or_admin`
 * (`src/external/middleware/rbac.py`) named in Milestone LLLL's own
 * recommendation: `delete_case` (`src/external/routes/cases.py`) had zero
 * E2E coverage on either branch before this pair of specs. Mirrors
 * `case-lead-ownership-access-denial.spec.ts`'s (Milestone DDDD) exact
 * structure for the same boundary on a different route -- a genuinely
 * SECOND, real case-lead account (real `Role.CASE_LEAD`, so `requires_role`
 * lets it through) that does NOT own the case in question is what's
 * needed, same `SecondCaseLeadSeeder` this pairing already established.
 */
test("a real case-lead who does not own this case is denied deleting/archiving it", async ({
  browser,
}) => {
  test.setTimeout(45000);

  // The static case-lead dev user creates a real case it owns.
  const contextOwner = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageOwner = await contextOwner.newPage();
  const loginOwner = await LoginPage.open(pageOwner);
  await loginOwner.waitUntilReady();
  const casesOwner = await loginOwner.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
  await casesOwner.createCase(
    `E2E Case-Delete-Denial Case ${Date.now()}`,
    `E2E-DEL-DENY-${Date.now()}`,
  );
  const caseUrl = pageOwner.url();
  const caseId = caseUrl.split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${caseUrl}`).toBeTruthy();
  // Owner's context stays open -- needed below to independently confirm
  // the denied delete didn't land, since the second case-lead can't read
  // this case at all (assert_case_access, a separate boundary) and so
  // can't be used for that confirmation itself.

  // A real, freshly-seeded SECOND case-lead, same org, does not own it.
  const secondLead = new SecondCaseLeadSeeder().seed();

  const contextSecondLead = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageSecondLead = await contextSecondLead.newPage();
  try {
    const loginSecondLead = await LoginPage.open(pageSecondLead);
    await loginSecondLead.waitUntilReady();
    const casesSecondLead = await loginSecondLead.loginWithSso(secondLead.username, secondLead.password);

    const claims = await casesSecondLead.fetchDecodedAccessTokenClaims();
    const roles = (claims.roles as string[] | undefined) ?? [];
    expect(roles, "second case-lead's token must actually carry case-lead").toContain("case-lead");

    const status = await casesSecondLead.attemptDeleteCase(caseId);
    expect(
      status,
      "a case-lead who does not own this case must get a real 403 from assert_case_lead_or_admin",
    ).toBe(403);
  } finally {
    await contextSecondLead.close();
  }

  // Confirm the case genuinely was NOT archived -- the 403 isn't just a
  // response-code assertion, the mutation must not have landed either.
  // Checked from the OWNER's own session: the second case-lead can't read
  // this case at all (a real, separate 403 from assert_case_access, same
  // boundary case-membership-access-denial.spec.ts proves), so it can't
  // be used for this confirmation.
  const stillThere = await casesOwner.fetchCaseById(caseId);
  expect(stillThere.id).toBe(caseId);
  expect(stillThere.status.toLowerCase()).not.toBe("archived");
  await contextOwner.close();
});
