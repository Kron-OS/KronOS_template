import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), closing Gap Audit
 * Milestone KKKK's own coverage-gap finding: membership was add-only
 * before this cycle -- `DELETE /api/cases/{id}/members/{user_id}`
 * (`remove_case_member`, `src/external/routes/cases.py`) did not exist at
 * all. New domain method `Case.without_member()` mirrors `with_member()`
 * exactly (immutable, same `updated_at` bump); the route mirrors
 * `add_case_member`'s own `assert_case_lead_or_admin` gating and
 * `CASE_UPDATED` audit event, `details={"action": "case.member_removed"}`.
 *
 * This spec proves the full real lifecycle in one pass, mirroring
 * `case-membership-access-grant.spec.ts`'s (Milestone EEEE) own structure
 * for the grant half, extended with the removal half that spec never
 * covered: a real grant genuinely opens access, and a real removal
 * genuinely revokes it -- not just that the DELETE call itself returns
 * the right status code.
 */
test("removing a case member genuinely revokes that member's real read access", async ({
  browser,
}) => {
  test.setTimeout(60000);

  // analyst logs in first, purely to read its own real Keycloak user id
  // (the JWT's `sub` claim) -- add_case_member/remove_case_member never
  // do a server-side lookup, so a real user id is required in the
  // request, not a placeholder (same reasoning Milestone EEEE established).
  const contextAnalystId = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageAnalystId = await contextAnalystId.newPage();
  const loginAnalystId = await LoginPage.open(pageAnalystId);
  await loginAnalystId.waitUntilReady();
  const casesAnalystId = await loginAnalystId.loginWithSso(DEV_USERS.analyst.username, DEV_USERS.analyst.password);
  const analystClaims = await casesAnalystId.fetchDecodedAccessTokenClaims();
  const analystUserId = analystClaims.sub as string | undefined;
  expect(analystUserId, "expected a real 'sub' claim on analyst's own access token").toBeTruthy();
  await contextAnalystId.close();

  // case-lead: real case owner, grants analyst real membership, then
  // REVOKES it -- both real, successful, case-lead-gated mutations.
  const contextOwner = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageOwner = await contextOwner.newPage();
  const loginOwner = await LoginPage.open(pageOwner);
  await loginOwner.waitUntilReady();
  const casesOwner = await loginOwner.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
  const caseTitle = `E2E Membership-Removal Case ${Date.now()}`;
  await casesOwner.createCase(caseTitle, `E2E-REMOVE-${Date.now()}`);
  const caseUrl = pageOwner.url();
  const caseId = caseUrl.split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${caseUrl}`).toBeTruthy();

  const grantStatus = await casesOwner.attemptAddMember(caseId, analystUserId as string);
  expect(grantStatus, "the initial grant must succeed").toBeGreaterThanOrEqual(200);
  expect(grantStatus).toBeLessThan(300);

  const removeStatus = await casesOwner.attemptRemoveMember(caseId, analystUserId as string);
  expect(
    removeStatus,
    "case-lead removing a member from a case it owns must be a real, successful revocation",
  ).toBe(200);
  await contextOwner.close();

  // analyst: fresh session, real login again -- proves the removal's
  // effect persisted server-side (Postgres case.member_user_ids), not
  // something only visible within the removing call's own session.
  const contextAnalyst = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageAnalyst = await contextAnalyst.newPage();
  try {
    const loginAnalyst = await LoginPage.open(pageAnalyst);
    await loginAnalyst.waitUntilReady();
    const casesAnalyst = await loginAnalyst.loginWithSso(DEV_USERS.analyst.username, DEV_USERS.analyst.password);

    // Direct URL navigation to the case -- same shape
    // case-membership-access-denial.spec.ts uses to prove a 403; the
    // removed member must now be denied the same way a member who was
    // never added would be.
    const caseResponseCodes: number[] = [];
    pageAnalyst.on("response", (resp) => {
      if (resp.url().includes(`/api/cases/${caseId}`) && !resp.url().includes(`/api/cases/${caseId}/`)) {
        caseResponseCodes.push(resp.status());
      }
    });

    await pageAnalyst.goto(`/cases/${caseId}`);
    await expect.poll(() => caseResponseCodes.length, { timeout: 10000 }).toBeGreaterThanOrEqual(1);
    expect(
      caseResponseCodes.every((code) => code === 403),
      `observed response codes for GET /api/cases/${caseId} after removal: ${caseResponseCodes.join(", ")} ` +
        `(expected every response to be a real 403 -- the removed member must be denied, not still granted)`,
    ).toBe(true);

    // Also confirm via a fresh, independent call. fetchJson()'s underlying
    // fetch() only rejects on a network error, not an HTTP error status --
    // a real 403's JSON error body still resolves normally (confirmed by
    // reading KronosPage.fetchJson() before writing this, matching the
    // same real lesson case-delete-ownership-denial.spec.ts's own fix
    // already established) -- so the correct assertion is the shape of
    // the resolved body, not that the call throws.
    const freshCase = await casesAnalyst.fetchCaseById(caseId);
    expect(freshCase.id, "a denied fetch's body must not be a real CaseOut").toBeUndefined();
  } finally {
    await contextAnalyst.close();
  }
});
