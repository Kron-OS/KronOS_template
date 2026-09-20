import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { completeStepUpReauth } from "./stepup";

/**
 * `PushConnectorKeyPanel.tsx` (the same component the Suricata PUSH spec
 * exercises) also drives Wazuh and Zeek -- STATUS.md flagged these two as
 * "share the component, unit-tested, but no dedicated live-browser run".
 * This proves the shared panel actually works for the other two PUSH
 * connectors too, not just for the one previously exercised.
 */
for (const { displayName, sourceType } of [
  { displayName: "Wazuh", sourceType: "wazuh" },
  { displayName: "Zeek (conn.log)", sourceType: "zeek-json" },
]) {
  test(`${sourceType} PUSH connector: generate an API key and revoke it via the marketplace UI`, async ({
    page,
  }) => {
    test.setTimeout(90000);

    const login = await LoginPage.open(page);
    await login.waitUntilReady();
    await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

    await page.goto("/admin/connectors");
    await page.waitForSelector("text=Marketplace", { timeout: 10000 });

    const card = () =>
      page.getByRole("heading", { name: displayName, exact: true }).locator("xpath=ancestor::div[button]").first();
    await card().getByRole("button", { name: "Manage API key" }).click();

    await page.waitForSelector(`text=${displayName} — API Keys`, { timeout: 10000 });
    await expect(page.getByText("On your side, you'll need to:")).toBeVisible();

    const sourceId = `${sourceType}-e2e-${Date.now()}`;
    await page.fill("#new-source-id", sourceId);
    await page.getByRole("button", { name: "Generate key" }).click();
    await completeStepUpReauth(page);

    // Step-up redirects the whole page away and back; the panel is not
    // re-opened automatically -- reopen it and resubmit, matching the
    // documented "never auto-submit" rule (see the Suricata PUSH spec).
    await page.waitForURL("**/admin/connectors", { timeout: 15000 });
    await page.waitForSelector("text=Marketplace", { timeout: 10000 });
    await card().getByRole("button", { name: "Manage API key" }).click();
    await page.waitForSelector(`text=${displayName} — API Keys`, { timeout: 10000 });

    await page.fill("#new-source-id", sourceId);
    await page.getByRole("button", { name: "Generate key" }).click();

    await page.waitForSelector("text=Copy this key now", { timeout: 15000 });
    await expect(page.getByText("X-KronOS-Source-Key", { exact: true })).toBeVisible();
    const revealedKey = await page.locator("code").first().textContent();
    expect(revealedKey, "a real API key must be revealed").toBeTruthy();
    expect(revealedKey!.length).toBeGreaterThan(10);

    await page.getByRole("button", { name: "Dismiss" }).click();

    const row = page.getByText(sourceId, { exact: true }).locator("../..");
    await row.getByRole("button", { name: "Revoke" }).click();
    await page.getByRole("button", { name: "Revoke", exact: true }).last().click();

    const finalRow = page.getByText(sourceId, { exact: true }).locator("../..");
    await expect(finalRow.getByText("Revoked", { exact: false })).toBeVisible({ timeout: 10000 });

    await page.getByRole("button", { name: "Close" }).click();
  });
}
