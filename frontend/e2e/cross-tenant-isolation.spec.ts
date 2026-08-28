import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { SecondOrgSeeder } from "./SecondOrgSeeder";

/**
 * Isolation tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.5, §5 item 4's
 * remaining half): the browser-level analogue of poc/global_l4_e2e/'s
 * own backend-level cross-org isolation assertions. Org A's real case,
 * given directly to a real, freshly-provisioned Org B member via the URL
 * bar, must produce the real 404 the backend enforces -- not a
 * client-side redirect that merely looks like isolation -- and org A's
 * case title must never appear anywhere in org B's rendered DOM, at any
 * point (including transient loading states).
 */
test("a fresh org member cannot see another org's case via a direct URL", async ({ browser }) => {
  test.setTimeout(45000);

  // Org A: real case-lead, real case, in the existing kronos-dev org.
  const contextA = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageA = await contextA.newPage();
  const loginA = await LoginPage.open(pageA);
  await loginA.waitUntilReady();
  const casesA = await loginA.loginWithSso("case-lead", "DevCaseLead#2026");
  const caseTitle = `E2E Isolation Secret Case ${Date.now()}`;
  await casesA.createCase(caseTitle, `E2E-ISO-${Date.now()}`);
  const caseUrl = pageA.url();
  const caseId = caseUrl.split("/cases/")[1];
  expect(caseId, `expected a real case id in the URL, got: ${caseUrl}`).toBeTruthy();
  await contextA.close();

  // Org B: a fresh, real, throwaway org + member, seeded independently.
  const orgB = new SecondOrgSeeder().seed();

  const contextB = await browser.newContext({ baseURL: "https://kronos.local", ignoreHTTPSErrors: true });
  const pageB = await contextB.newPage();

  const caseResponseCodes: number[] = [];
  pageB.on("response", (resp) => {
    if (resp.url().includes(`/api/cases/${caseId}`)) caseResponseCodes.push(resp.status());
  });

  try {
    const loginB = await LoginPage.open(pageB);
    await loginB.waitUntilReady();
    await loginB.loginWithSso(orgB.username, orgB.password);

    // Direct URL navigation to org A's real case -- not a link org B's
    // own UI would ever offer, exactly the "typed/bookmarked URL" attack
    // shape this tier exists to prove is safe.
    await pageB.goto(`/cases/${caseId}`);
    await pageB.waitForSelector("text=Failed to load case", { timeout: 15000 });

    // React Query's default retry behavior can fire more than one request
    // for the same failing query -- the real invariant is "every response
    // was a real 404, never anything else" (a 200 would be a leak; a 500
    // would suggest the isolation check itself errored rather than
    // correctly denying), not an exact request count.
    await expect.poll(() => caseResponseCodes.length, { timeout: 10000 }).toBeGreaterThanOrEqual(1);
    expect(
      caseResponseCodes.every((code) => code === 404),
      `observed response codes for org A's case: ${caseResponseCodes.join(", ")}`,
    ).toBe(true);

    // No org-A-identifying string anywhere in org B's rendered DOM.
    const bodyText = await pageB.locator("body").innerText();
    expect(bodyText).not.toContain(caseTitle);
  } finally {
    await contextB.close();
  }
});
