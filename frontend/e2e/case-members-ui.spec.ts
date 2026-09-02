import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * Milestone RRRR: the backend's add_case_member/remove_case_member had
 * been fully built, tested, and audited (Milestones CCCC-QQQQ) with zero
 * frontend UI ever reaching them -- every prior spec exercised these
 * routes via a raw, direct fetch (`CasesPage.attemptAddMember()`/
 * `attemptRemoveMember()`). This spec drives the real UI instead: the
 * "Case Members" section in the Settings tab (`CaseMembersSection`,
 * `frontend/src/pages/CaseDetailPage.tsx`).
 *
 * The RBAC boundary itself (assert_case_lead_or_admin,
 * add_case_member's own userId-org validation) already has real,
 * dedicated coverage elsewhere -- this spec's own focus is the UI wiring:
 * does searching for a real org member and clicking Add actually call the
 * real API and render the result, and does clicking Remove actually call
 * the real DELETE and update the list.
 *
 * Gap Audit Milestone ZZZZ: `CaseMembersSection` no longer takes a raw
 * userId -- it's a real search-as-you-type picker backed by
 * `GET /{case_id}/member-candidates`. This spec now searches by the
 * analyst's real username ("analyst") rather than typing its id directly
 * -- the id is still independently confirmed afterward via the member
 * list row, which is unchanged.
 */
test("a case-lead can add and remove a case member through the real Settings UI", async ({
  browser,
}) => {
  test.setTimeout(45000);

  // analyst logs in first, purely to read its own real Keycloak user id --
  // add_case_member requires a real, in-org userId (Milestone QQQQ).
  const contextAnalystId = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageAnalystId = await contextAnalystId.newPage();
  const loginAnalystId = await LoginPage.open(pageAnalystId);
  await loginAnalystId.waitUntilReady();
  const casesAnalystId = await loginAnalystId.loginWithSso(DEV_USERS.analyst.username, DEV_USERS.analyst.password);
  const analystClaims = await casesAnalystId.fetchDecodedAccessTokenClaims();
  const analystUserId = analystClaims.sub as string | undefined;
  expect(analystUserId, "expected a real 'sub' claim on analyst's own access token").toBeTruthy();
  await contextAnalystId.close();

  const contextOwner = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  try {
    const pageOwner = await contextOwner.newPage();
    const login = await LoginPage.open(pageOwner);
    await login.waitUntilReady();
    const cases = await login.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);

    const detail = await cases.createCase(
      `E2E Members-UI Case ${Date.now()}`,
      `E2E-MEMBERS-UI-${Date.now()}`,
    );

    await detail.openSettingsTab();
    await detail.addMemberViaUI(DEV_USERS.analyst.username);
    await detail.waitForMemberRow(analystUserId as string);

    await detail.removeMemberViaUI(analystUserId as string);
    await detail.waitForMemberRowGone(analystUserId as string);
  } finally {
    await contextOwner.close();
  }
});
