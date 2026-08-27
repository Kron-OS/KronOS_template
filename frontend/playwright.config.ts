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
  // Real, reproduced bug (not a flaky test): `fullyParallel: false` only
  // serializes tests *within* one spec file -- Playwright still runs
  // separate spec FILES concurrently across multiple workers by default.
  // Two specs each logging in as the same shared dev-seeded "case-lead"
  // Keycloak account at nearly the same instant caused a genuine, real
  // Keycloak authentication rejection ("Invalid username or password")
  // on the second login -- confirmed by re-running with `--workers=1`,
  // which passed both specs cleanly. Root cause not fully isolated
  // (concurrent identical logins racing the same account's session/PKCE
  // state, possibly interacting with bruteForceProtected in
  // docker/keycloak/kronos-realm.json), but forcing serial execution is
  // the correct fix regardless: this suite intentionally reuses one real
  // shared fixture account per docs/PLAYWRIGHT_E2E_TEST_PLAN.md §0.1,
  // not a fresh one per spec, so concurrent runs of it are never safe.
  // Revisit if/when specs are split across DEV_USERS.caseLead/analyst/admin
  // to allow real parallelism without this collision.
  workers: 1,
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
