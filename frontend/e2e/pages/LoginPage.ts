import type { Page } from "@playwright/test";
import { KronosPage } from "./KronosPage";
import { CasesPage } from "./CasesPage";
import { generateTotp } from "../totp";

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

  /**
   * Drives the full real redirect chain: KronOS -> Keycloak -> KronOS.
   *
   * Milestone JJJJ: `docker/keycloak/kronos-realm.json`'s `admin` user
   * (the only dev-seeded Role.ORG_ADMIN account, needed for
   * `a11y.spec.ts`'s `/admin/org` scan) ships with
   * `"requiredActions": ["CONFIGURE_TOTP"]` -- unlike `case-lead`/
   * `analyst`, its first-ever login on ANY freshly-provisioned realm (a
   * fresh CI stack every run, not just this one long-lived dev stack)
   * lands on Keycloak's own interactive "Mobile Authenticator Setup" page
   * instead of completing. Confirmed live (`poc/admin_totp_enrollment/`)
   * that this is a one-time, per-account thing -- once done, a plain
   * password login needs no further OTP step, matching case-lead's
   * already-relied-on behavior everywhere else in this suite -- so this
   * handles it transparently and only when Keycloak actually presents it,
   * rather than special-casing the `admin` username.
   */
  async loginWithSso(username: string, password: string): Promise<CasesPage> {
    await this.page.click("text=Sign in with SSO");
    await this.page.waitForSelector("#username", { timeout: 15000 });
    await this.page.fill("#username", username);
    await this.page.fill("#password", password);
    await this.page.click("#kc-login");
    await this.completeConfigureTotpIfPresented();
    await this.page.waitForURL("**/cases**", { timeout: 20000 });
    const cases = new CasesPage(this.page);
    await cases.waitUntilReady();
    return cases;
  }

  /**
   * Completes Keycloak's real CONFIGURE_TOTP required-action page if (and
   * only if) it's the page we actually landed on after submitting
   * credentials -- a no-op for every account that doesn't have this
   * required action pending. Selectors confirmed live against this repo's
   * real Keycloak 26.2 (`poc/admin_totp_enrollment/` and a throwaway probe
   * user, both real runs, not guessed): "Unable to scan?" switches the
   * default QR view to the manual view exposing the real base32 secret in
   * `#kc-totp-secret-key`; the visible `#totp` field plus the hidden
   * `#totpSecret`/`#mode` fields are what the real enrollment form posts.
   */
  private async completeConfigureTotpIfPresented(): Promise<void> {
    const unableToScan = this.page.locator("text=Unable to scan?");
    const outcome = await Promise.race([
      this.page.waitForURL("**/cases**", { timeout: 10000 }).then(() => "logged-in" as const),
      unableToScan.waitFor({ timeout: 10000 }).then(() => "totp-setup" as const),
    ]).catch(() => "timeout" as const);
    if (outcome !== "totp-setup") return;

    await unableToScan.click();
    const secretText = await this.page.locator("#kc-totp-secret-key").textContent({ timeout: 10000 });
    if (!secretText) throw new Error("LoginPage: CONFIGURE_TOTP manual view had no #kc-totp-secret-key text");
    const code = generateTotp(secretText.replace(/\s/g, ""));
    await this.page.fill("#totp", code);
    await this.page.fill("#userLabel", "kronos-e2e-suite");
    await this.page.click("#saveTOTPBtn");
  }
}
