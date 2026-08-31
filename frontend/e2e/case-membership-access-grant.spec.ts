import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";

/**
 * RBAC tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md), the positive counterpart
 * deferred since Gap Audit Milestone CCCC and explicitly named as
 * Milestone DDDD's own recommendation #1: every RBAC spec so far
 * (`rbac-access-denial`, `case-membership-access-denial`,
 * `case-lead-ownership-access-denial`) proves a real DENIAL. None of them
 * prove that a real, successful `POST /api/cases/{id}/members` grant
 * actually turns into real read access for the newly-added member --
 * `assert_case_access`'s "owner OR member" ALLOW branch
 * (`src/external/middleware/rbac.py`) has never been exercised live.
 *
 * `add_case_member` (`src/external/routes/cases.py`) takes a real target
 * `userId` in its request body and calls `case.with_member(body.userId)`
 * directly -- no separate lookup happens server-side, so a real Keycloak
 * user id is required in the request, not a placeholder (the placeholder
 * UUID `case-lead-ownership-access-denial.spec.ts` uses only works there
 * because that spec's request is rejected by `assert_case_lead_or_admin`
 * before the body is ever read). `TenantContext.user_id` is parsed
 * directly from the JWT's own `sub` claim
 * (`src/external/middleware/keycloak_auth.py::_extract_tenant`,
 * `user_id = uuid.UUID(claims["sub"])`) -- confirmed by reading that
 * function before writing this test, not assumed. The real, static,
 * dev-seeded `analyst` account's own `sub` is therefore the correct real
 * id to add as a member: logging in as analyst once and decoding its own
 * fresh access token (`fetchDecodedAccessTokenClaims()`, already used by
 * `case-lead-ownership-access-denial.spec.ts` for the same "read a real
 * claim, don't assume" reasoning) yields it directly.
 */
test("a real member added via a successful grant genuinely gets real read access to the case", async ({
  browser,
}) => {
  test.setTimeout(45000);

  // analyst logs in first, purely to read its own real Keycloak user id
  // (the JWT's `sub` claim) off a real, freshly-issued access token --
  // this is the id add_case_member's body needs, not a placeholder.
  const contextAnalystId = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageAnalystId = await contextAnalystId.newPage();
  const loginAnalystId = await LoginPage.open(pageAnalystId);
  await loginAnalystId.waitUntilReady();
  const casesAnalystId = await loginAnalystId.loginWithSso(DEV_USERS.analyst.username, DEV_USERS.analyst.password);
  const analystClaims = await casesAnalystId.fetchDecodedAccessTokenClaims();
  const analystUserId = analystClaims.sub as string | undefined;
  expect(analystUserId, "expected a real 'sub' claim on analyst's own access token").toBeTruthy();
  await contextAnalystId.close();

  // case-lead: real case owner (Case.owner_user_id is set to the creating
  // caller -- src/external/routes/cases.py's create_case), then performs
  // a REAL, successful add-member grant using analyst's real user id.
  const contextOwner = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageOwner = await contextOwner.newPage();
  const loginOwner = await LoginPage.open(pageOwner);
  await loginOwner.waitUntilReady();
  const casesOwner = await loginOwner.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
  const caseTitle = `E2E Membership-Grant Case ${Date.now()}`;
  await casesOwner.createCase(caseTitle, `E2E-GRANT-${Date.now()}`);
  const caseUrl = pageOwner.url();
  const caseId = caseUrl.split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${caseUrl}`).toBeTruthy();

  const grantStatus = await casesOwner.attemptAddMember(caseId, analystUserId as string);
  expect(
    grantStatus,
    "case-lead adding analyst (a real userId, on a case it owns) must be a real, successful grant",
  ).toBeGreaterThanOrEqual(200);
  expect(grantStatus).toBeLessThan(300);
  await contextOwner.close();

  // analyst: fresh session, real login again -- proves the grant's effect
  // persisted server-side (Postgres case.member_user_ids), not something
  // only visible within the granting call's own session/page load.
  const contextAnalyst = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageAnalyst = await contextAnalyst.newPage();

  const caseResponseCodes: number[] = [];
  pageAnalyst.on("response", (resp) => {
    if (resp.url().includes(`/api/cases/${caseId}`) && !resp.url().includes(`/api/cases/${caseId}/`)) {
      caseResponseCodes.push(resp.status());
    }
  });

  try {
    const loginAnalyst = await LoginPage.open(pageAnalyst);
    await loginAnalyst.waitUntilReady();
    const casesAnalyst = await loginAnalyst.loginWithSso(DEV_USERS.analyst.username, DEV_USERS.analyst.password);

    // Direct URL navigation to the case owned by someone else -- the same
    // shape case-membership-access-denial.spec.ts uses to prove a 403;
    // here membership must make it succeed instead.
    await pageAnalyst.goto(`/cases/${caseId}`);
    await pageAnalyst.waitForSelector(`text=${caseTitle}`, { timeout: 15000 });

    await expect.poll(() => caseResponseCodes.length, { timeout: 10000 }).toBeGreaterThanOrEqual(1);
    expect(
      caseResponseCodes.every((code) => code === 200),
      `observed response codes for GET /api/cases/${caseId}: ${caseResponseCodes.join(", ")} ` +
        `(expected every response to be a real 200 -- membership must grant real read access, not just a UI render)`,
    ).toBe(true);

    // Not just a status code -- the real case data (title) is genuinely
    // visible in the DOM, proving the response body was the real CaseOut,
    // not an empty/error shell that happened to return 200.
    const bodyText = await pageAnalyst.locator("body").innerText();
    expect(bodyText).toContain(caseTitle);

    // Also confirm via a fresh, independent GET (not trusted from the
    // same page load that rendered the above -- docs/PLAYWRIGHT_E2E_TEST_PLAN.md
    // §3.3's own requirement), mirroring case-membership-access-denial's
    // sibling spec's own rigor for the negative case.
    const freshCase = await casesAnalyst.fetchCaseById(caseId);
    expect(freshCase.id).toBe(caseId);
    expect(freshCase.title).toBe(caseTitle);
  } finally {
    await contextAnalyst.close();
  }
});
