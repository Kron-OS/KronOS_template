import { KronosPage } from "./KronosPage";
import { DetectionDetailPage } from "./DetectionDetailPage";

/** Real, authenticated `/detections` list view. */
export class DetectionsPage extends KronosPage {
  async waitUntilReady(): Promise<void> {
    await this.page.waitForURL("**/detections", { timeout: 10000 });
  }

  /** Opens a real detection row by its (assumed-unique) real rule name. */
  async openDetectionByRuleName(ruleName: string): Promise<DetectionDetailPage> {
    await this.page.locator(`a:has-text('${ruleName}')`).click();
    const detail = new DetectionDetailPage(this.page);
    await detail.waitUntilReady();
    return detail;
  }

  /** Navigates directly to /detections (no assumptions about how the user
   * got there beforehand, mirrors DetectionDetailPage.openById's reasoning
   * for a real bookmarked/direct-link scenario). */
  static async open(page: import("@playwright/test").Page): Promise<DetectionsPage> {
    await page.goto("/detections");
    const list = new DetectionsPage(page);
    await list.waitUntilReady();
    return list;
  }

  /** Gap Audit Milestone BBBBB: real free-text search box -- debounced
   * 300ms client-side before the real backend `q` filter request fires. */
  async searchByText(text: string): Promise<void> {
    await this.page.getByLabel("Search detections").fill(text);
    await this.page.waitForTimeout(500);
  }

  /** Gap Audit Milestone BBBBB: real severity <select>, backed by the
   * real backend `severity` filter (Detection.rule_severity exact match). */
  async filterBySeverity(severity: string): Promise<void> {
    await this.page.getByLabel("Filter by severity").selectOption(severity);
  }

  /** Real rule-name/detector-name text shown per row, in list order --
   * for asserting exactly which real rows a filter combination surfaced. */
  async visibleRuleNames(): Promise<string[]> {
    return this.page.locator("a[href^='/detections/'] p.font-medium").allInnerTexts();
  }
}
