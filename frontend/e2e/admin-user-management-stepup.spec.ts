import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { completeStepUpReauth } from "./stepup";
import { SecondCaseLeadSeeder } from "./SecondCaseLeadSeeder";

/**
 * Gap Audit Milestone WWWW: closes Tier 1 item 4 of
 * `docs/HANDOFF_AND_ORCHESTRATION.md`. `POST /api/admin/org/users/invite`
 * and `PATCH /api/admin/org/users/{id}/role` share the exact same
 * `_assert_aal2` step-up gating `PATCH /api/admin/org/quota` does
 * (`admin-quota-ui.spec.ts`, Milestone TTTT -- the first spec to drive a
 * real step-up flow at all), but neither had ever been exercised through
 * a real browser step-up before this. Reuses `completeStepUpReauth`
 * (extracted to `./stepup.ts` this same cycle) rather than duplicating
 * the window-aligned TOTP retry logic.
 *
 * Confirmed live, matching the quota spec's own finding: once a step-up
 * redirect completes, the session's token is aal2 for the REST of that
 * browser context -- a second aal2-gated action in the same session
 * succeeds directly, no further redirect. That matters for how each test
 * below is shaped: `test_invite_user_...` proves invite's OWN redirect
 * (a fresh aal1 session), then reuses the now-aal2 session to remove the
 * user it created (real cleanup, not a second step-up). `test_update_user_role_...`
 * needs a target user that exists BEFORE the step-up happens, without
 * itself elevating the session to aal2 first (which would hide whether
 * `update_user_role`'s own redirect trigger actually works) -- so it
 * seeds a throwaway user out-of-band via `SecondCaseLeadSeeder` (a real
 * Admin API call, not through this browser session at all) rather than
 * creating one through the invite UI first.
 */

test("inviteUser completes a real step-up redirect and creates the real user", async ({ page }) => {
  // Mirrors admin-quota-ui.spec.ts's own budget: a retried OTP submission
  // can wait up to ~30s for a fresh TOTP window.
  test.setTimeout(90000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/org");
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  const email = `e2e-wwww-invite-${Date.now()}@e2e.invalid`;
  const password = "E2EWwwwInvite#Strong2026";

  async function fillInviteForm(): Promise<void> {
    await page.getByRole("button", { name: "Create User", exact: true }).click();
    await page.waitForSelector("#invite-email", { timeout: 10000 });
    await page.fill("#invite-first-name", "E2E");
    await page.fill("#invite-last-name", "WwwwInvite");
    await page.fill("#invite-email", email);
    await page.fill("#invite-password", password);
    await page.selectOption("#invite-role", "analyst");
    await page.getByRole("button", { name: "Create User", exact: true }).last().click();
  }

  // First attempt: triggers the real step-up redirect. The mutation and
  // the modal's own local form state are abandoned by the page
  // navigation (same real behavior admin-quota-ui.spec.ts already found
  // for PATCH quota) -- no assertion on user creation yet.
  await fillInviteForm();
  await completeStepUpReauth(page);

  // Real navigation back to the app on success.
  await page.waitForURL("**/admin/org", { timeout: 15000 });
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  // Retry, now with a fresh aal2 token -- succeeds directly, no further
  // redirect.
  await fillInviteForm();
  const row = page.locator("tr", { hasText: email });
  await row.waitFor({ timeout: 15000 });
  await expect(row.locator("select")).toHaveValue("analyst");

  // Real cleanup via the UI's own Remove action -- the session is already
  // aal2 from the invite's step-up above, so this succeeds directly
  // without a second redirect (also real coverage of remove_user's own
  // `_assert_aal2` gate not silently blocking an already-elevated session).
  await row.getByRole("button", { name: "Remove", exact: true }).click();
  await page.getByRole("button", { name: "Remove", exact: true }).last().click();
  await expect(page.getByText(email, { exact: false })).toHaveCount(0);
});

test("updateUserRole completes a real step-up redirect and persists the new role", async ({ page }) => {
  test.setTimeout(90000);

  // Seeded out-of-band (real Admin API call, not through this browser
  // session) so the session below starts genuinely aal1 -- if it were
  // created via the invite UI first, that would already elevate the
  // session to aal2 and hide whether update_user_role's OWN redirect
  // trigger works.
  const seeded = new SecondCaseLeadSeeder().seed();

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/org");
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  const row = page.locator("tr", { hasText: seeded.username });
  await row.waitFor({ timeout: 15000 });
  await expect(row.locator("select")).toHaveValue("case-lead");

  // First attempt: triggers the real step-up redirect. Same abandoned-
  // mutation behavior as quota/invite above -- the <select> reverts to
  // the server's last-known value on remount, so no assertion yet.
  await row.locator("select").selectOption("analyst");
  await completeStepUpReauth(page);

  await page.waitForURL("**/admin/org", { timeout: 15000 });
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  // Retry, now aal2 -- succeeds directly.
  const rowAfterReturn = page.locator("tr", { hasText: seeded.username });
  await rowAfterReturn.waitFor({ timeout: 15000 });
  await rowAfterReturn.locator("select").selectOption("analyst");
  await expect(rowAfterReturn.locator("select")).toHaveValue("analyst", { timeout: 15000 });

  // Independent confirmation via a fresh page reload -- proves the role
  // change genuinely persisted server-side, not just optimistic client
  // state.
  await page.reload();
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });
  const rowAfterReload = page.locator("tr", { hasText: seeded.username });
  await expect(rowAfterReload.locator("select")).toHaveValue("analyst", { timeout: 15000 });
});
