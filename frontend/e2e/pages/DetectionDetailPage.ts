import { KronosPage } from "./KronosPage";

/** Real, authenticated `/detections/{id}` detail view. */
export class DetectionDetailPage extends KronosPage {
  /**
   * Real, reproduced finding: `PostgresDetectionRepository.stream_by_org`
   * sorts ascending by `synced_at`, so a freshly-seeded detection lands on
   * the LAST page of `/detections` (default pageSize=50), not the first
   * -- this repo's accumulated PoC history has seeded far more than 50
   * real detections into the kronos-dev org over time. Direct navigation
   * to the real per-detection URL (the same route `DetectionRow`'s own
   * `<Link to="/detections/$detectionId">` uses) sidesteps pagination
   * entirely and is also a more realistic scenario (a bookmarked/linked
   * detection) than paging through a list this spec isn't testing anyway.
   */
  static async openById(page: import("@playwright/test").Page, detectionId: string): Promise<DetectionDetailPage> {
    await page.goto(`/detections/${detectionId}`);
    const detail = new DetectionDetailPage(page);
    await detail.waitUntilReady();
    return detail;
  }

  async waitUntilReady(): Promise<void> {
    await this.page.waitForURL("**/detections/**", { timeout: 15000 });
    await this.page.waitForSelector('span:has-text("New"), span:has-text("Investigating"), span:has-text("Positive")', {
      timeout: 10000,
    });
  }

  /** Real TriageStatePill label, read live from the DOM -- no reload. */
  async triageStateLabel(): Promise<string> {
    const pill = this.page.locator("span").filter({
      hasText: /^(New|Investigating|True Positive|False Positive)$/,
    });
    return (await pill.first().innerText()).trim();
  }

  /** Clicks the real triage action button (e.g. "Start Investigating"). */
  async clickTriageAction(label: string): Promise<void> {
    await this.page.click(`button:has-text('${label}')`);
  }

  /**
   * Independent confirmation via a fresh real API call -- not trusted
   * from the same page load that rendered the pill, per
   * docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.3's own requirement. Reuses the
   * same real /auth/refresh cookie-proxy CasesPage already uses to obtain
   * a real bearer token, since the app authenticates API calls with an
   * Authorization header, not cookies.
   */
  async fetchRealTriageStateFromApi(detectionId: string): Promise<string> {
    return this.page.evaluate(async (id) => {
      const tokenRes = await fetch("/auth/refresh", { method: "POST", credentials: "include" });
      const tokenBody = await tokenRes.json();
      const accessToken: string = tokenBody.accessToken ?? tokenBody.access_token;
      const res = await fetch(`/api/detections/${id}`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const body = await res.json();
      return body.triageState as string;
    }, detectionId);
  }
}
