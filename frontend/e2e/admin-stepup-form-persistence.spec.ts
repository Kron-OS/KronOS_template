import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { completeStepUpReauth } from "./stepup";
import { SecondCaseLeadSeeder } from "./SecondCaseLeadSeeder";

/**
 * Gap Audit Milestone YYYY: closes Tier 1 item 3 of
 * `docs/HANDOFF_AND_ORCHESTRATION.md`. Milestones TTTT/WWWW/XXXX all named
 * (but didn't fix) the same real UX rough edge: `apiClient`'s step-up
 * redirect abandons whatever the user had typed, forcing them to retype
 * it after returning. `frontend/src/lib/stepUpFormPersistence.ts` stashes
 * non-sensitive form values in `sessionStorage` right before the request
 * that might need step-up goes out, and each of the three affected forms
 * (`AdminPage.tsx`'s `QuotaSection`/`InviteModal`/`UserRow`) restores them
 * on mount -- but deliberately never auto-submits on the user's behalf.
 * These specs prove the RESTORATION actually happens across a real
 * redirect (not just the unit-tested storage round-trip,
 * `stepUpFormPersistence.test.ts`), and that the password field is
 * deliberately excluded and password is genuinely still required
 * afterward -- both real, live, browser-verified claims, not assumed
 * from reading the diff.
 */

test("quota form value survives a real step-up redirect", async ({ page }) => {
  test.setTimeout(90000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/org");
  await page.waitForSelector("text=Storage Quota", { timeout: 10000 });

  await page.fill("#quota-gb-input", "7");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await completeStepUpReauth(page);

  await page.waitForURL("**/admin/org", { timeout: 15000 });
  await page.waitForSelector("text=Storage Quota", { timeout: 10000 });

  // The real proof: the value is already there, restored from the stash
  // -- no retyping needed, unlike before Milestone YYYY.
  await expect(page.locator("#quota-gb-input")).toHaveValue("7");

  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByText("used of 7.00 GB", { exact: false }).waitFor({ timeout: 10000 });

  // Leave the shared dev-stack org in its original state.
  await page.getByRole("button", { name: "Clear (unlimited)", exact: true }).click();
  await page.getByText("(unlimited)", { exact: false }).waitFor({ timeout: 10000 });
});

test("invite-user form fields survive a real step-up redirect, password deliberately excluded", async ({
  page,
}) => {
  test.setTimeout(90000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/org");
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  const email = `e2e-yyyy-invite-${Date.now()}@e2e.invalid`;

  await page.getByRole("button", { name: "Create User", exact: true }).click();
  await page.waitForSelector("#invite-email", { timeout: 10000 });
  await page.fill("#invite-first-name", "E2E");
  await page.fill("#invite-last-name", "YyyyPersist");
  await page.fill("#invite-email", email);
  await page.fill("#invite-password", "WhateverGoesHere#2026");
  await page.selectOption("#invite-role", "case-lead");
  await page.getByRole("button", { name: "Create User", exact: true }).last().click();
  await completeStepUpReauth(page);

  await page.waitForURL("**/admin/org", { timeout: 15000 });
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  // Reopen the modal (it does not auto-open -- see stepUpFormPersistence's
  // own "never auto-submit" rule) and confirm the real restoration.
  await page.getByRole("button", { name: "Create User", exact: true }).click();
  await page.waitForSelector("#invite-email", { timeout: 10000 });
  await expect(page.locator("#invite-first-name")).toHaveValue("E2E");
  await expect(page.locator("#invite-last-name")).toHaveValue("YyyyPersist");
  await expect(page.locator("#invite-email")).toHaveValue(email);
  await expect(page.locator("#invite-role")).toHaveValue("case-lead");
  // The real, deliberate exclusion: password is NOT restored.
  await expect(page.locator("#invite-password")).toHaveValue("");

  await page.fill("#invite-password", "FreshlyTypedAgain#2026");
  await page.getByRole("button", { name: "Create User", exact: true }).last().click();

  const row = page.locator("tr", { hasText: email });
  await row.waitFor({ timeout: 15000 });
  await expect(row.locator("select")).toHaveValue("case-lead");

  // Cleanup: session is already aal2 from the step-up above.
  await row.getByRole("button", { name: "Remove", exact: true }).click();
  await page.getByRole("button", { name: "Remove", exact: true }).last().click();
  await expect(page.getByText(email, { exact: false })).toHaveCount(0);
});

test("a pending role change offers an explicit Apply banner after a real step-up redirect, never auto-applies", async ({
  page,
}) => {
  test.setTimeout(90000);

  const seeded = new SecondCaseLeadSeeder().seed();

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/org");
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  const row = page.locator("tr", { hasText: seeded.username });
  await row.waitFor({ timeout: 15000 });
  await expect(row.locator("select")).toHaveValue("case-lead");

  await row.locator("select").selectOption("analyst");
  await completeStepUpReauth(page);

  await page.waitForURL("**/admin/org", { timeout: 15000 });
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });

  const rowAfterReturn = page.locator("tr", { hasText: seeded.username });
  await rowAfterReturn.waitFor({ timeout: 15000 });

  // The real proof this never auto-applies: the select still shows the
  // OLD role, and a distinct "Pending: analyst" banner with an explicit
  // Apply button is what offers to finish the change.
  await expect(rowAfterReturn.locator("select")).toHaveValue("case-lead");
  await expect(rowAfterReturn.getByText("Pending: analyst", { exact: false })).toBeVisible({
    timeout: 10000,
  });

  await rowAfterReturn.getByRole("button", { name: "Apply", exact: true }).click();
  await expect(rowAfterReturn.locator("select")).toHaveValue("analyst", { timeout: 15000 });
  await expect(rowAfterReturn.getByText("Pending:", { exact: false })).toHaveCount(0);

  // Independent confirmation via a fresh reload.
  await page.reload();
  await page.waitForSelector("text=Organisation Admin", { timeout: 10000 });
  const rowAfterReload = page.locator("tr", { hasText: seeded.username });
  await expect(rowAfterReload.locator("select")).toHaveValue("analyst", { timeout: 15000 });
});
