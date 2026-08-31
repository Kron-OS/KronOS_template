import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), the second half of the
 * access-control boundary Gap Audit Milestone BBBB's own recommendation
 * #1 named: `assert_case_access`'s ownership/membership qualifier
 * (src/external/middleware/rbac.py, AUTH-007) -- a real, DIFFERENT
 * security boundary from BBBB's own `rbac-access-denial.spec.ts`
 * (a pure role check, `requires_role`) and from
 * `cross-tenant-isolation.spec.ts` (a different ORG entirely, which
 * `case_repo.get_by_id(case_id, tenant.org_id)` already scopes to a real
 * 404 before `assert_case_access` is ever reached).
 *
 * This spec exercises the case where BOTH users are real, same-org
 * members (both real dev-seeded kronos-dev users, no throwaway org
 * seeding needed) -- the case genuinely exists for the second caller's
 * own org_id, so `case_repo.get_by_id` succeeds, and it is
 * `assert_case_access` itself that must reject: `analyst` is neither
 * this case's `owner_user_id` nor listed in `member_user_ids`. This is
 * therefore a real, distinct 403, not the 404 `cross-tenant-isolation.spec.ts`
 * already proves -- confirmed directly from `assert_case_access`'s own
 * source before writing this test, not assumed to just be "the same
 * check under a different name."
 */
test("a same-org user who is not a case's owner/member is denied access with a real 403, not a leak", async ({
  browser,
}) => {
  test.setTimeout(45000);

  // case-lead: real case owner (Case.owner_user_id is set to the creating
  // caller -- src/external/routes/cases.py's create_case).
  const contextOwner = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageOwner = await contextOwner.newPage();
  const loginOwner = await LoginPage.open(pageOwner);
  await loginOwner.waitUntilReady();
  const casesOwner = await loginOwner.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
  const caseTitle = `E2E Membership-Denied Case ${Date.now()}`;
  await casesOwner.createCase(caseTitle, `E2E-MEMBER-${Date.now()}`);
  const caseUrl = pageOwner.url();
  const caseId = caseUrl.split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${caseUrl}`).toBeTruthy();
  await contextOwner.close();

  // analyst: real, same-org, same-tenant user -- deliberately never added
  // as a member of the case above, so case_repo.get_by_id succeeds (same
  // org_id) but assert_case_access must still reject.
  const contextOther = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageOther = await contextOther.newPage();

  const caseResponseCodes: number[] = [];
  pageOther.on("response", (resp) => {
    if (resp.url().includes(`/api/cases/${caseId}`)) caseResponseCodes.push(resp.status());
  });

  try {
    const loginOther = await LoginPage.open(pageOther);
    await loginOther.waitUntilReady();
    await loginOther.loginWithSso(DEV_USERS.analyst.username, DEV_USERS.analyst.password);

    // Direct URL navigation -- the same "typed/bookmarked URL" shape
    // cross-tenant-isolation.spec.ts already proves is safe across orgs;
    // this proves it's also safe WITHIN the same org, for a real member
    // of the org who simply isn't entitled to this specific case.
    await pageOther.goto(`/cases/${caseId}`);
    await pageOther.waitForSelector("text=Failed to load case", { timeout: 15000 });

    await expect.poll(() => caseResponseCodes.length, { timeout: 10000 }).toBeGreaterThanOrEqual(1);
    expect(
      caseResponseCodes.every((code) => code === 403),
      `observed response codes for the case-lead-owned case: ${caseResponseCodes.join(", ")} ` +
        `(expected every response to be a real 403 from assert_case_access -- a 404 would mean ` +
        `the org-scoping check ran instead, a 200 would be a real access-control leak)`,
    ).toBe(true);

    const bodyText = await pageOther.locator("body").innerText();
    expect(bodyText).not.toContain(caseTitle);
  } finally {
    await contextOther.close();
  }
});
