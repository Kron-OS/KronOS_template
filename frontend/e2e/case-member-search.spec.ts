import { test, expect, DEV_USERS } from "./fixtures";
import { LoginPage } from "./pages/LoginPage";
import { SecondCaseLeadSeeder } from "./SecondCaseLeadSeeder";

/**
 * Gap Audit Milestone ZZZZ: closes Tier 1 item 6 of
 * docs/HANDOFF_AND_ORCHESTRATION.md, per the project owner's explicit
 * choice (a new, case-scoped user-search endpoint, not a UI-only
 * workaround or widening admin.py's existing org-admin-only listing).
 * `GET /{case_id}/member-candidates` (src/external/routes/cases.py) is
 * exercised here two ways: through the real Settings UI (proves the
 * search itself surfaces real matches and hides already-added members,
 * complementing `case-members-ui.spec.ts`'s own add/remove-flow focus),
 * and directly via a real second case-lead account (proves the RBAC
 * boundary -- a case-lead who does not own the target case is denied,
 * mirroring `case-lead-ownership-access-denial.spec.ts`'s own proven
 * pattern for `add_case_member`).
 */
test("case member search returns real, matching org members and hides already-added ones", async ({
  casesPageAsCaseLead,
}) => {
  const detail = await casesPageAsCaseLead.createCase(
    `E2E ZZZZ search case ${Date.now()}`,
    `E2E-ZZZZ-${Date.now()}`,
  );
  await detail.openSettingsTab();

  const searchInput = detail.page.getByPlaceholder("Start typing a name or email...");

  // Real match against a real dev-seeded org member ("analyst").
  await searchInput.fill("analyst");
  const suggestion = detail.page.locator("li", { hasText: "analyst" });
  await expect(suggestion.getByRole("button", { name: "Add", exact: true })).toBeVisible({
    timeout: 10000,
  });

  // A query that matches no real org member.
  await searchInput.fill("");
  await searchInput.fill("no-such-person-zzzz");
  await expect(detail.page.getByText("No matching org members found.")).toBeVisible({
    timeout: 10000,
  });

  // Once added, the same search no longer offers that candidate again
  // (CaseMembersSection filters out existing members client-side).
  await searchInput.fill("");
  await searchInput.fill("analyst");
  await suggestion.getByRole("button", { name: "Add", exact: true }).click();
  await detail.page
    .locator("li", { hasText: /^analyst/ })
    .first()
    .waitFor({ timeout: 10000 });

  await searchInput.fill("");
  await searchInput.fill("analyst");
  await expect(detail.page.getByText("No matching org members found.")).toBeVisible({
    timeout: 10000,
  });
});

test("a real case-lead who does not own this case is denied the member-candidates search", async ({
  browser,
}) => {
  test.setTimeout(45000);

  const contextOwner = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageOwner = await contextOwner.newPage();
  const loginOwner = await LoginPage.open(pageOwner);
  await loginOwner.waitUntilReady();
  const casesOwner = await loginOwner.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
  await casesOwner.createCase(
    `E2E ZZZZ owner case ${Date.now()}`,
    `E2E-ZZZZ-OWNER-${Date.now()}`,
  );
  const caseId = pageOwner.url().split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${pageOwner.url()}`).toBeTruthy();
  await contextOwner.close();

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

    const status = await casesSecondLead.attemptListMemberCandidates(caseId, "anyone");
    expect(
      status,
      "a case-lead who does not own this case must get a real 403 from assert_case_lead_or_admin",
    ).toBe(403);
  } finally {
    await contextSecondLead.close();
  }
});
