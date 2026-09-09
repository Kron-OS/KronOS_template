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

  /** Milestone IIIII: severity is now a multi-select toggle-pill group
   * (was a single <select>, Gap Audit Milestone BBBBB). This helper
   * preserves the pre-IIIII exclusive-select semantics for callers written
   * against a single severity at a time: deselects every currently-active
   * severity pill, then selects only the target one. */
  async filterBySeverity(severity: string): Promise<void> {
    const group = this.page.getByTestId("severity-filters");
    const active = group.locator("button[aria-pressed='true']");
    while ((await active.count()) > 0) {
      await active.first().click();
    }
    await group.getByRole("button", { name: new RegExp(`^${severity}$`, "i") }).click();
  }

  /** Real rule-name/detector-name text shown per row, in list order --
   * for asserting exactly which real rows a filter combination surfaced. */
  async visibleRuleNames(): Promise<string[]> {
    return this.page.locator("a[href^='/detections/'] p.font-medium").allInnerTexts();
  }

  /** Milestone IIIII: clicks a triage-state toggle pill (New/Investigating/
   * True Positive/False Positive/All) in the real, multi-select filter row. */
  async selectTriageStatePill(label: string): Promise<void> {
    await this.page
      .getByTestId("triage-state-filters")
      .getByRole("button", { name: label, exact: true })
      .click();
    await this.page.waitForTimeout(300);
  }

  /** Milestone IIIII: the real "select all on this page" checkbox above
   * the row list, backing bulk-triage row selection. */
  async selectAllOnPage(): Promise<void> {
    await this.page.getByLabel("Select all detections on this page").check();
  }

  /** Milestone IIIII: clicks a real bulk-action toolbar button (e.g. "Mark
   * Investigating") -- only rendered once at least one row is selected,
   * and only for target states reachable from the current selection's own
   * real triage states (DetectionTriageState._VALID_TRANSITIONS). */
  async clickBulkAction(label: string): Promise<void> {
    await this.page.getByRole("button", { name: label, exact: true }).click();
  }

  /** Real, persisted TriageStatePill label for the row matching *ruleName*
   * -- confirms the bulk action's effect round-tripped through the real
   * backend, not just an optimistic client-side update. */
  async triageStateForRow(ruleName: string): Promise<string> {
    const row = this.page.getByTestId("detection-row").filter({ hasText: ruleName });
    return row.getByTestId("triage-state-pill").innerText();
  }
}
