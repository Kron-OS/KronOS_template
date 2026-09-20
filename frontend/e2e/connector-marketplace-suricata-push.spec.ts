import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { completeStepUpReauth } from "./stepup";

/**
 * Task 12 (connector marketplace E2E): proves the Suricata PUSH connector
 * can actually be configured end-to-end from `/admin/connectors` by a real
 * browser session -- not just that the underlying
 * `admin_integration_sources.py` routes work in isolation (already covered
 * by `tests/unit/test_admin_integration_source_routes.py`), but that the
 * marketplace UI (`PushConnectorKeyPanel.tsx`) actually drives them,
 * including the real step-up MFA redirect provisioning/revocation require.
 */

test("suricata-eve PUSH connector: generate an API key and revoke it via the marketplace UI", async ({
  page,
}) => {
  test.setTimeout(90000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/connectors");
  await page.waitForSelector("text=Marketplace", { timeout: 10000 });

  const suricataCard = () =>
    page
      .getByRole("heading", { name: "Suricata (eve.json)" })
      .locator("xpath=ancestor::div[button]")
      .first();
  await suricataCard().getByRole("button", { name: "Manage API key" }).click();

  await page.waitForSelector("text=Suricata (eve.json) — API Keys", { timeout: 10000 });
  // Real asset-setup guidance must be present for this connector.
  await expect(page.getByText("On your side, you'll need to:")).toBeVisible();

  const sourceId = `suricata-e2e-${Date.now()}`;
  await page.fill("#new-source-id", sourceId);
  await page.getByRole("button", { name: "Generate key" }).click();
  await completeStepUpReauth(page);

  // Step-up redirects the whole page away and back; the panel is not
  // re-opened automatically (matches the documented "never auto-submit"
  // rule for step-up-gated forms elsewhere in this suite) -- reopen it.
  await page.waitForURL("**/admin/connectors", { timeout: 15000 });
  await page.waitForSelector("text=Marketplace", { timeout: 10000 });
  await suricataCard().getByRole("button", { name: "Manage API key" }).click();
  await page.waitForSelector("text=Suricata (eve.json) — API Keys", { timeout: 10000 });

  await page.fill("#new-source-id", sourceId);
  await page.getByRole("button", { name: "Generate key" }).click();

  // The real proof: a plaintext key is revealed exactly once, with the
  // real header name the push ingestion route expects.
  await page.waitForSelector("text=Copy this key now", { timeout: 15000 });
  await expect(page.getByText("X-KronOS-Source-Key", { exact: true })).toBeVisible();
  const revealedKey = await page.locator("code").first().textContent();
  expect(revealedKey, "a real API key must be revealed").toBeTruthy();
  expect(revealedKey!.length).toBeGreaterThan(10);

  await page.getByRole("button", { name: "Dismiss" }).click();

  // Unlike the FIRST step-up-gated call in this test, the browser's aal2
  // session (established above) persists for the rest of this tab's
  // session -- a fresh ticket is minted per call, but no second Keycloak
  // redirect is required, matching how session-level MFA elevation
  // actually behaves (confirmed live: no #password prompt appears here).
  const row = page.getByText(sourceId, { exact: true }).locator("../..");
  await row.getByRole("button", { name: "Revoke" }).click();
  await page.getByRole("button", { name: "Revoke", exact: true }).last().click();

  const finalRow = page.getByText(sourceId, { exact: true }).locator("../..");
  await expect(finalRow.getByText("Revoked", { exact: false })).toBeVisible({ timeout: 10000 });

  await page.getByRole("button", { name: "Close" }).click();
});
