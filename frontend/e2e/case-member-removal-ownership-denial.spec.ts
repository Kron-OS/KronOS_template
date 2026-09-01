import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { SecondCaseLeadSeeder } from "./SecondCaseLeadSeeder";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), the denial counterpart to
 * `case-member-removal-revokes-access.spec.ts` -- Milestone OOOO's new
 * `remove_case_member` route shares `add_case_member`'s own
 * `assert_case_lead_or_admin` gating, so a case-lead who does not own the
 * case must be denied the removal the same way `case-lead-ownership-access-denial.spec.ts`
 * (Milestone DDDD) already proves for `add_case_member`. Mirrors that
 * spec's exact structure, same `SecondCaseLeadSeeder`.
 */
test("a real case-lead who does not own this case is denied removing a member from it", async ({
  browser,
}) => {
  test.setTimeout(45000);

  // The static case-lead dev user creates a real case it owns and adds a
  // real member to it (the analyst dev user's own real sub -- doesn't
  // strictly need to be a real id for THIS boundary, since
  // assert_case_lead_or_admin rejects before the target user id is ever
  // read, same reasoning case-lead-ownership-access-denial.spec.ts
  // already established for add_case_member -- kept realistic anyway for
  // a case that reads clearly).
  const contextOwner = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageOwner = await contextOwner.newPage();
  const loginOwner = await LoginPage.open(pageOwner);
  await loginOwner.waitUntilReady();
  const casesOwner = await loginOwner.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
  await casesOwner.createCase(
    `E2E Member-Removal-Denial Case ${Date.now()}`,
    `E2E-REMOVE-DENY-${Date.now()}`,
  );
  const caseUrl = pageOwner.url();
  const caseId = caseUrl.split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${caseUrl}`).toBeTruthy();

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

    // Real target user id doesn't matter -- assert_case_lead_or_admin
    // rejects before it's ever read (mirrors add_case_member's own
    // established reasoning for this exact boundary).
    const status = await casesSecondLead.attemptRemoveMember(caseId, "00000000-0000-0000-0000-000000000003");
    expect(
      status,
      "a case-lead who does not own this case must get a real 403 from assert_case_lead_or_admin",
    ).toBe(403);
  } finally {
    await contextSecondLead.close();
  }
});
