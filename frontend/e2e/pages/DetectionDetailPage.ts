import { KronosPage } from "./KronosPage";

const TRIAGE_STATES = ["New", "Investigating", "True Positive", "False Positive"] as const;

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
   * Polls the real TriageStatePill's own live text WITHOUT reloading --
   * generalization of CaseDetailPage.watchEvidenceStateLive's seedState
   * guard (KronosPage.pollLiveText's own docstring explains why: a
   * re-watch after an action that starts from a KNOWN current value must
   * not treat that stale value as a fresh reading). Pass `seedValue` when
   * re-watching after a prior watch already observed a value (e.g. after
   * clicking a triage action) so only a genuine change counts.
   */
  async watchTriageStateLive(
    seedValue: string | null = null,
    timeoutMs = 10000,
  ): Promise<{ seenValues: string[]; terminal: string | null }> {
    const pill = this.page.locator("span").filter({
      hasText: /^(New|Investigating|True Positive|False Positive)$/,
    });
    return this.pollLiveText(pill.first(), {
      knownValues: TRIAGE_STATES,
      terminalValues: TRIAGE_STATES,
      seedValue,
      timeoutMs,
    });
  }

  /**
   * Independent confirmation via a fresh real API call -- not trusted
   * from the same page load that rendered the pill, per
   * docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.3's own requirement.
   */
  async fetchRealTriageStateFromApi(detectionId: string): Promise<string> {
    return (await this.fetchJson<{ triageState: string }>(`/api/detections/${detectionId}`)).triageState;
  }
}
