import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { SecondCaseLeadSeeder } from "./SecondCaseLeadSeeder";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), closing Gap Audit
 * Milestone CCCC's own recommendation #2: `assert_case_lead_or_admin`
 * ("of case"/"own" qualifier, `src/external/middleware/rbac.py`) is a
 * THIRD, distinct RBAC boundary from both
 * `rbac-access-denial.spec.ts` (a pure `requires_role` check --
 * analyst lacks Role.CASE_LEAD entirely, rejected before any ownership
 * logic runs) and `case-membership-access-denial.spec.ts`
 * (`assert_case_access`, the weaker "owner OR member" check used for
 * read access). `assert_case_lead_or_admin` is used for the *stricter*
 * case-lead-gated mutations (add member, delete, legal hold, audit log)
 * and requires actual OWNERSHIP, not mere membership.
 *
 * The single static `case-lead` dev user (docker/keycloak/kronos-realm.json)
 * can't exercise this boundary alone -- whatever case it creates, it
 * owns. A genuinely SECOND, real case-lead account (real Role.CASE_LEAD,
 * so `requires_role` lets it through) that does NOT own the case in
 * question is what's actually needed -- `SecondCaseLeadSeeder` (new this
 * cycle) provisions exactly that in the same real `kronos-dev` org via
 * the Keycloak Admin API, the same proven pattern
 * `SecondOrgSeeder`/`seed_detection.py` already use.
 *
 * `POST /api/cases/{id}/members` has no frontend UI yet (confirmed by
 * reading `CasesPage.tsx` before writing this test) -- issued directly
 * via `CasesPage.attemptAddMember()` (real fetch with a real bearer
 * token), the same real API call a future UI would make.
 */
test("a real case-lead who does not own this case is denied a case-lead-gated mutation", async ({
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
    `E2E Case-Lead-Owned Case ${Date.now()}`,
    `E2E-OWNER-${Date.now()}`,
  );
  const caseUrl = pageOwner.url();
  const caseId = caseUrl.split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${caseUrl}`).toBeTruthy();
  await contextOwner.close();

  // A real, freshly-seeded SECOND case-lead, same org, does not own it.
  const secondLead = new SecondCaseLeadSeeder().seed();

  const contextSecondLead = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageSecondLead = await contextSecondLead.newPage();
  try {
    const loginSecondLead = await LoginPage.open(pageSecondLead);
    await loginSecondLead.waitUntilReady();
    const casesSecondLead = await loginSecondLead.loginWithSso(secondLead.username, secondLead.password);

    // Confirm the token actually carries case-lead (so a 403 below is
    // genuinely assert_case_lead_or_admin rejecting, not requires_role
    // rejecting for lack of the role at all -- would silently duplicate
    // rbac-access-denial.spec.ts's own coverage instead of testing the
    // new boundary).
    const claims = await casesSecondLead.fetchDecodedAccessTokenClaims();
    const roles = (claims.roles as string[] | undefined) ?? [];
    expect(roles, "second case-lead's token must actually carry case-lead").toContain("case-lead");

    // Real target user id doesn't matter -- assert_case_lead_or_admin
    // rejects before the request body's userId is ever read (confirmed
    // from src/external/routes/cases.py's own add_case_member: the
    // ownership check runs immediately after the case lookup, before
    // case_repo.update(case.with_member(body.userId))).
    const status = await casesSecondLead.attemptAddMember(caseId, "00000000-0000-0000-0000-000000000001");
    expect(
      status,
      "a case-lead who does not own this case must get a real 403 from assert_case_lead_or_admin",
    ).toBe(403);
  } finally {
    await contextSecondLead.close();
  }
});
