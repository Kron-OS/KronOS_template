import { KronosPage } from "./KronosPage";
import { CaseDetailPage } from "./CaseDetailPage";

/** Real, authenticated `/cases` dashboard. */
export class CasesPage extends KronosPage {
  async waitUntilReady(): Promise<void> {
    await this.page.waitForSelector("text=New Case", { timeout: 10000 });
  }

  /** Real case creation via the UI -- selectors proven by poc/evidence_sse_realtime/. */
  async createCase(title: string, ref: string): Promise<CaseDetailPage> {
    await this.page.click("text=New Case");
    await this.page.waitForSelector("#case-title", { timeout: 10000 });
    await this.page.fill("#case-title", title);
    await this.page.fill("#case-ref", ref);
    await this.page.click("button:has-text('Create')");
    await this.page.waitForSelector(`text=${title}`, { timeout: 15000 });
    await this.page.click(`text=${title}`);
    const detail = new CaseDetailPage(this.page);
    await detail.waitUntilReady();
    return detail;
  }

  async headerText(): Promise<string> {
    return this.page.locator("header").innerText();
  }

  async goToDetections(): Promise<void> {
    await this.page.click("text=Detections");
    await this.page.waitForURL("**/detections", { timeout: 10000 });
  }

  /**
   * Real access-token claims, fetched the same way the app's own
   * bootstrap does (same-origin POST /auth/refresh, real HttpOnly cookie
   * attached by the browser) -- not read off a mocked store.
   */
  async fetchDecodedAccessTokenClaims(): Promise<Record<string, unknown>> {
    return this.page.evaluate(async () => {
      const res = await fetch("/auth/refresh", { method: "POST", credentials: "include" });
      const body = await res.json();
      const token: string = body.accessToken ?? body.access_token;
      const payloadB64 = token.split(".")[1];
      const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
      const json = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
      return JSON.parse(json);
    });
  }
}
