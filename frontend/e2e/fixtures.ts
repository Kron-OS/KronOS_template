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
  casesPageAsAnalyst: CasesPage;
};

export const test = base.extend<Fixtures>({
  // eslint-disable-next-line no-empty-pattern
  casesPageAsCaseLead: async ({ page }, use) => {
    const login = await LoginPage.open(page);
    await login.waitUntilReady();
    const cases = await login.loginWithSso(DEV_USERS.caseLead.username, DEV_USERS.caseLead.password);
    await use(cases);
  },
  // Gap Audit Milestone BBBB: first use of the real dev-seeded "analyst"
  // account (docker/keycloak/kronos-realm.json) -- it existed in
  // DEV_USERS since this file's own creation but had never actually been
  // logged in with by any spec until RBAC access-denial coverage needed a
  // real, deliberately LESS-privileged user (Role.ANALYST, lacking
  // Role.CASE_LEAD/Role.ORG_ADMIN) distinct from the case-lead fixture
  // every other spec in this suite uses.
  // eslint-disable-next-line no-empty-pattern
  casesPageAsAnalyst: async ({ page }, use) => {
    const login = await LoginPage.open(page);
    await login.waitUntilReady();
    const cases = await login.loginWithSso(DEV_USERS.analyst.username, DEV_USERS.analyst.password);
    await use(cases);
  },
});

export { expect } from "@playwright/test";
