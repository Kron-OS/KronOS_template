import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { completeStepUpReauth } from "./stepup";

/**
 * Task 12 (connector marketplace E2E): proves the CEF-over-syslog egress
 * SINK connector can be configured, disabled/re-enabled, and removed
 * end-to-end from `/admin/connectors` by a real browser session -- the
 * per-org config path (`ConnectorConfigForm.tsx` -> `admin_connector_config.py`
 * -> Postgres `connector_configs` + Vault) that `evidence-upload.spec.ts`
 * and the Suricata PUSH spec don't exercise.
 */

test("cef-syslog SINK connector: configure, disable/enable, then remove via the marketplace UI", async ({
  page,
}) => {
  test.setTimeout(120000);

  const login = await LoginPage.open(page);
  await login.waitUntilReady();
  await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

  await page.goto("/admin/connectors");
  await page.waitForSelector("text=Marketplace", { timeout: 10000 });

  // Ancestor-with-a-direct-button-child is the actual card root -- a plain
  // `div` filter with `has: heading` also matches the outer grid container
  // (an ancestor of every card), which resolves ambiguously since multiple
  // connectors render an identically-labelled button.
  const cefCard = () =>
    page.getByRole("heading", { name: "CEF over Syslog" }).locator("xpath=ancestor::div[button]").first();
  await cefCard().getByRole("button", { name: /Configure|Edit configuration/ }).click();

  await page.waitForSelector("text=Configure CEF over Syslog", { timeout: 10000 });
  await expect(page.getByText("On your side, you'll need to:")).toBeVisible();

  const host = `siem-e2e-${Date.now()}.internal`;
  await page.fill("#param-cef_syslog_host", host);
  await page.fill("#param-cef_syslog_port", "514");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await completeStepUpReauth(page);

  // Same reopen-after-redirect idiom as the quota/invite step-up specs:
  // the mutation is ABANDONED by the redirect (`apiClient`'s interceptor
  // never auto-replays it -- see `stepUpFormPersistence.ts`'s own
  // docstring), so the form must be reopened, its stashed values confirmed
  // restored, and Save clicked again explicitly -- exactly like
  // `admin-stepup-form-persistence.spec.ts`'s quota test.
  await page.waitForURL("**/admin/connectors", { timeout: 15000 });
  await page.waitForSelector("text=Marketplace", { timeout: 10000 });
  await cefCard().getByRole("button", { name: /Configure|Edit configuration/ }).click();
  await page.waitForSelector("text=Configure CEF over Syslog", { timeout: 10000 });
  await expect(page.locator("#param-cef_syslog_host")).toHaveValue(host);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Enabled", { exact: true })).toBeVisible({ timeout: 10000 });

  // Reversible kill switch: disable, confirm reflected, then re-enable.
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible({ timeout: 10000 });
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText("Enabled", { exact: true })).toBeVisible({ timeout: 10000 });

  // Permanent removal: requires its own step-up ticket, distinct operation
  // from "set" (see admin_connector_config.py's `connector_config.delete`).
  // No second Keycloak redirect here either -- same aal2 session as above,
  // a fresh ticket is minted silently per call (see the Suricata PUSH
  // spec's identical observation for revoke).
  await page.getByRole("button", { name: "Remove" }).click();
  await page.getByRole("button", { name: "Remove", exact: true }).last().click();

  // Back to its unconfigured label -- the real proof the config + Vault
  // secret were actually deleted, not merely disabled.
  await expect(cefCard().getByRole("button", { name: "Configure", exact: true })).toBeVisible({
    timeout: 10000,
  });
});
