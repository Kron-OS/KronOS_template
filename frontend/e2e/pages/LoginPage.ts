import type { Page } from "@playwright/test";
import { KronosPage } from "./KronosPage";
import { CasesPage } from "./CasesPage";

/**
 * Real Keycloak-hosted login flow -- selectors proven against a real
 * running Keycloak 26.2 by poc/keycloak_browser_login/run_poc.py
 * (#username/#password/#kc-login on Keycloak's own hosted form, "Sign in
 * with SSO" on KronOS's own LoginPage). Reused here rather than
 * re-derived.
 */
export class LoginPage extends KronosPage {
  static async open(page: Page): Promise<LoginPage> {
    await page.goto("/login");
    return new LoginPage(page);
  }

  async waitUntilReady(): Promise<void> {
    await this.page.waitForSelector("text=Sign in with SSO");
  }

  /** Drives the full real redirect chain: KronOS -> Keycloak -> KronOS. */
  async loginWithSso(username: string, password: string): Promise<CasesPage> {
    await this.page.click("text=Sign in with SSO");
    await this.page.waitForSelector("#username", { timeout: 15000 });
    await this.page.fill("#username", username);
    await this.page.fill("#password", password);
    await this.page.click("#kc-login");
    await this.page.waitForURL("**/cases**", { timeout: 20000 });
    const cases = new CasesPage(this.page);
    await cases.waitUntilReady();
    return cases;
  }
}
