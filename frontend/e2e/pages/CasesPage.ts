import { KronosPage } from "./KronosPage";
import { CaseDetailPage } from "./CaseDetailPage";
import { DetectionsPage } from "./DetectionsPage";

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

  async goToDetections(): Promise<DetectionsPage> {
    await this.page.click("text=Detections");
    await this.page.waitForURL("**/detections", { timeout: 10000 });
    return new DetectionsPage(this.page);
  }

  /**
   * Real access-token claims, fetched the same way the app's own
   * bootstrap does (same-origin POST /auth/refresh, real HttpOnly cookie
   * attached by the browser) -- not read off a mocked store. Decoded in
   * Node (not another page.evaluate) since JWT payload decoding is pure
   * string manipulation once the real token is in hand.
   */
  async fetchDecodedAccessTokenClaims(): Promise<Record<string, unknown>> {
    const token = await this.getFreshAccessToken();
    const payloadB64 = token.split(".")[1];
    const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
    const json = Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
    return JSON.parse(json);
  }
}
