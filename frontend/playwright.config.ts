import { defineConfig, devices } from "@playwright/test";

/**
 * KronOS real-browser E2E suite (docs/PLAYWRIGHT_E2E_TEST_PLAN.md).
 *
 * Points at a real, already-running KronOS stack -- this is not a mocked
 * harness. `ignoreHTTPSErrors` is required because kronos.local's step-ca
 * leaf cert is a short-lived (24h) internal-PKI cert, not a
 * publicly-trusted one (see plan doc §0.1) -- the same reason the
 * precedent Python PoCs (poc/keycloak_browser_login/, etc.) pass
 * `ignore_https_errors=True`.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "e2e-report" }]],
  use: {
    baseURL: process.env.KRONOS_E2E_BASE_URL ?? "https://kronos.local",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
