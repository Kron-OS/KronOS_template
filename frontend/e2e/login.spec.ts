import { test, expect } from "./fixtures";
import { LoginPage } from "./pages/LoginPage";

/**
 * Smoke tier (docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.1 / §5 item 1): proves
 * the whole real-browser toolchain end to end -- browser install, base
 * URL against real kronos.local, real PKCE login through Keycloak's real
 * hosted form, landing authenticated -- before any deeper spec is written.
 */
test("real PKCE login lands on an authenticated Cases dashboard", async ({ page }) => {
  const login = await LoginPage.open(page);
  await login.waitUntilReady();

  const before = page.url();
  expect(before).toContain("/login");

  const cases = await login.loginWithSso("case-lead", "DevCaseLead#2026");

  expect(cases.url).toContain("/cases");

  const header = await cases.headerText();
  expect(header.length).toBeGreaterThan(0);

  await cases.goToDetections();
  expect(page.url()).toContain("/detections");

  const claims = await cases.fetchDecodedAccessTokenClaims();
  expect(claims.preferred_username ?? claims.sub).toBeTruthy();
});
