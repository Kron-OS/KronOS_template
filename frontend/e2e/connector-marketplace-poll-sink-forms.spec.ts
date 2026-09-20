import { test, expect } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { DEV_USERS } from "./fixtures";
import { completeStepUpReauth } from "./stepup";

/**
 * `ConnectorConfigForm.tsx` (the same component the CEF-syslog SINK spec
 * exercises) also drives Splunk HEC, Microsoft Sentinel (both SINK) and
 * Microsoft Defender (POLL) -- STATUS.md flagged these three as "share the
 * component, unit-tested, but no dedicated live-browser run". This is a
 * real config-storage round trip (Postgres + Vault via
 * `admin_connector_config.py`), not a live call to Splunk/Sentinel/Graph --
 * `set_connector_config` never dials out on save, it only validates and
 * persists (confirmed by reading src/external/routes/admin_connector_config.py),
 * so well-formed fake credentials are sufficient to prove the UI wiring.
 */
interface FormCase {
  displayName: string;
  suffix: string;
  fields: Record<string, string>;
  /** one non-secret field to assert persists correctly across the step-up reload */
  persistedField: string;
}

const CASES: FormCase[] = [
  {
    displayName: "Splunk HEC",
    suffix: "splunk",
    fields: {
      "param-splunk_hec_url": "https://splunk-e2e.internal:8088/services/collector/event",
      "param-splunk_hec_token": "e2e-fake-hec-token",
    },
    persistedField: "param-splunk_hec_url",
  },
  {
    displayName: "Microsoft Sentinel",
    suffix: "sentinel",
    fields: {
      "param-sentinel_dce_endpoint": "https://e2e-dce.eastus-1.ingest.monitor.azure.com",
      "param-sentinel_dcr_immutable_id": "dcr-e2e0000000000000000000000000000",
      "param-sentinel_stream_name": "Custom-KronOSDetections",
      "param-sentinel_tenant_id": "00000000-0000-0000-0000-0000000000e2",
      "param-sentinel_client_id": "00000000-0000-0000-0000-0000000000e3",
      "param-sentinel_client_secret": "e2e-fake-client-secret",
    },
    persistedField: "param-sentinel_dce_endpoint",
  },
  {
    displayName: "Microsoft Defender",
    suffix: "defender",
    fields: {
      "param-defender_tenant_id": "00000000-0000-0000-0000-0000000000e4",
      "param-defender_client_id": "00000000-0000-0000-0000-0000000000e5",
      "param-defender_client_secret": "e2e-fake-client-secret",
    },
    persistedField: "param-defender_tenant_id",
  },
];

for (const { displayName, suffix, fields, persistedField } of CASES) {
  test(`${suffix} connector: configure, disable/enable, then remove via the marketplace UI`, async ({
    page,
  }) => {
    test.setTimeout(120000);

    const login = await LoginPage.open(page);
    await login.waitUntilReady();
    await login.loginWithSso(DEV_USERS.admin.username, DEV_USERS.admin.password);

    await page.goto("/admin/connectors");
    await page.waitForSelector("text=Marketplace", { timeout: 10000 });

    const card = () =>
      page.getByRole("heading", { name: displayName, exact: true }).locator("xpath=ancestor::div[button]").first();
    await card().getByRole("button", { name: /Configure|Edit configuration/ }).click();

    await page.waitForSelector(`text=Configure ${displayName}`, { timeout: 10000 });
    await expect(page.getByText("On your side, you'll need to:")).toBeVisible();

    // Scoped to the open modal, not the page as a whole: the marketplace
    // card behind the modal renders its own independent "Enabled"/"Disabled"
    // badge (`ConnectorCatalogCard.tsx`) that reaches the same state a beat
    // after the modal's own header badge does, so an unscoped `page.getByText`
    // intermittently resolves to two elements (real, observed: a strict-mode
    // violation on this exact assertion during this spec's own first real run).
    const modal = () => page.locator("div.fixed.inset-0.z-50");

    for (const [id, value] of Object.entries(fields)) {
      await page.fill(`#${id}`, value);
    }
    await modal().getByRole("button", { name: "Save", exact: true }).click();
    await completeStepUpReauth(page);

    // Mutation is abandoned by the step-up redirect, same idiom as the
    // CEF-syslog SINK spec -- reopen, confirm stashed values restored, save again.
    await page.waitForURL("**/admin/connectors", { timeout: 15000 });
    await page.waitForSelector("text=Marketplace", { timeout: 10000 });
    await card().getByRole("button", { name: /Configure|Edit configuration/ }).click();
    await page.waitForSelector(`text=Configure ${displayName}`, { timeout: 10000 });
    await expect(page.locator(`#${persistedField}`)).toHaveValue(fields[persistedField]);
    await modal().getByRole("button", { name: "Save", exact: true }).click();
    await expect(modal().getByText("Enabled", { exact: true })).toBeVisible({ timeout: 10000 });

    // Reversible kill switch.
    await modal().getByRole("button", { name: "Disable" }).click();
    await expect(modal().getByText("Disabled", { exact: true })).toBeVisible({ timeout: 10000 });
    await modal().getByRole("button", { name: "Enable" }).click();
    await expect(modal().getByText("Enabled", { exact: true })).toBeVisible({ timeout: 10000 });

    // Permanent removal, its own step-up ticket -- confirm config + Vault
    // secret are actually gone (card reverts to its unconfigured label).
    await page.getByRole("button", { name: "Remove" }).click();
    await page.getByRole("button", { name: "Remove", exact: true }).last().click();

    await expect(card().getByRole("button", { name: "Configure", exact: true })).toBeVisible({
      timeout: 10000,
    });
  });
}
