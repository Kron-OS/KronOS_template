import { test as base } from "@playwright/test";
import { LoginPage } from "./pages/LoginPage";
import { CasesPage } from "./pages/CasesPage";

/**
 * Real dev-seeded Keycloak user (docker/keycloak/kronos-realm.json),
 * reused across every prior real-browser PoC in this repo
 * (poc/keycloak_browser_login/, poc/evidence_sse_realtime/, ...) rather
 * than re-derived. Not a secret worth protecting -- a dev-only fixture
 * account, never used in test/prod.
 */
export const DEV_USERS = {
  caseLead: { username: "case-lead", password: "DevCaseLead#2026" },
  analyst: { username: "analyst", password: "DevAnalyst#2026" },
  admin: { username: "admin", password: "DevAdmin#2026" },
} as const;

type Fixtures = {
  casesPageAsCaseLead: CasesPage;
};

export const test = base.extend<Fixtures>({
  // eslint-disable-next-line no-empty-pattern
  casesPageAsCaseLead: async ({ page }, use) => {
    const login = await LoginPage.open(page);
    await login.waitUntilReady();
    const cases = await login.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
    await use(cases);
  },
});

export { expect } from "@playwright/test";
