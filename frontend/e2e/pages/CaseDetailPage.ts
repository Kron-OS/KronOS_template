import { KronosPage } from "./KronosPage";

const TERMINAL_STATES = ["Complete", "Error"] as const;
const KNOWN_STATES = ["Uploading", "Scanning", "Hashing", "Received", "Parsing", ...TERMINAL_STATES] as const;

/** Real, authenticated `/cases/{id}` detail view. */
export class CaseDetailPage extends KronosPage {
  async waitUntilReady(): Promise<void> {
    await this.page.waitForURL("**/cases/**", { timeout: 15000 });
  }

  /**
   * Real upload via the real UploadDrawer flow -- selectors proven by
   * poc/evidence_sse_realtime/browser_verify.py. The drawer does NOT
   * auto-close on finalize; this closes it explicitly once the file
   * reaches "Done" so callers land back on the evidence table.
   */
  async uploadEvidence(filePath: string): Promise<void> {
    await this.page.click("text=Upload Evidence");
    await this.page.waitForSelector("#evidence-file-input", { timeout: 10000 });
    await this.page.setInputFiles("#evidence-file-input", filePath);
    await this.page.getByRole("button", { name: "Upload", exact: true }).click();
    await this.page.waitForSelector("text=Done", { timeout: 30000 });
    await this.page.click('button[aria-label="Close"]');
    await this.page.waitForSelector("#evidence-file-input", { state: "detached", timeout: 10000 });
  }

  /**
   * Polls the real evidence row's own text WITHOUT reloading the page --
   * this is what actually proves the live SSE push path works, not just
   * that the terminal state is eventually correct after a fresh GET.
   * Delegates to KronosPage.pollLiveText -- see that method's own
   * docstring for the real, reproduced bug its `seedValue` guard fixes
   * (re-watching a row already sitting on a terminal state from a PRIOR
   * watch, e.g. after clicking Retry on an ERROR row, otherwise reads
   * that stale text on the first poll and returns immediately).
   */
  async watchEvidenceStateLive(
    fileName: string,
    timeoutMs = 60000,
    seedState: string | null = null,
  ): Promise<{ seenStates: string[]; terminal: string | null }> {
    const row = this.page.locator(`tr:has-text('${fileName}')`);
    const { seenValues, terminal } = await this.pollLiveText(row, {
      knownValues: KNOWN_STATES,
      terminalValues: TERMINAL_STATES,
      seedValue: seedState,
      timeoutMs,
    });
    return { seenStates: seenValues, terminal };
  }

  /**
   * Selects a file and clicks Upload, but does NOT assume success --
   * unlike `uploadEvidence()`, whose failure mode (Milestone LLL's
   * OpenSearch-outage spec) happens well after the upload dialog itself
   * completes normally. `POST /api/evidence/upload/request` can fail
   * synchronously, within this same click (Milestone QQQ: a real,
   * deterministic 500 when MinIO is down, confirmed live -- no evidence
   * row is ever created), so callers needing to observe that failure use
   * this instead of `uploadEvidence()`.
   */
  async startUpload(filePath: string): Promise<void> {
    await this.page.click("text=Upload Evidence");
    await this.page.waitForSelector("#evidence-file-input", { timeout: 10000 });
    await this.page.setInputFiles("#evidence-file-input", filePath);
    await this.page.getByRole("button", { name: "Upload", exact: true }).click();
  }

  /** Waits for the still-open upload dialog's own inline per-file error text. */
  async waitForUploadRequestError(timeoutMs = 15000): Promise<string> {
    const el = this.page.locator("text=/Request failed with status code \\d+/");
    await el.waitFor({ timeout: timeoutMs });
    return el.innerText();
  }

  /**
   * Clicks Upload again on the SAME still-open dialog (the file is
   * already selected from `startUpload()`) -- the real retry path a user
   * takes after fixing whatever made the first attempt fail, not a fresh
   * file selection. Closes the dialog once it reaches "Done", same as
   * `uploadEvidence()`.
   */
  async retryUploadAndWaitForDone(): Promise<void> {
    await this.page.getByRole("button", { name: "Upload", exact: true }).click();
    await this.page.waitForSelector("text=Done", { timeout: 30000 });
    await this.page.click('button[aria-label="Close"]');
    await this.page.waitForSelector("#evidence-file-input", { state: "detached", timeout: 10000 });
  }

  /** Opens EvidenceDetailDrawer by clicking the real evidence row (CaseDetailPage.tsx's own onClick). */
  async openEvidenceDrawer(fileName: string): Promise<void> {
    await this.page.locator(`tr:has-text('${fileName}')`).click();
    await this.page.waitForSelector("text=Retry", { timeout: 10000 });
  }

  /** Clicks the real Retry button (retryAction-gated -- only rendered for a retryable ERROR). */
  async clickRetry(): Promise<void> {
    await this.page.click("button:has-text('Retry')");
  }

  /**
   * Fresh, independent `GET /api/cases/{id}/evidence`, filtered to the
   * named file -- mirrors `CasesPage.fetchCaseById()`'s own "not trusted
   * from the same page load" pattern (docs/PLAYWRIGHT_E2E_TEST_PLAN.md
   * §3.3). Used to confirm `errorReason`/`retryAction` server-side rather
   * than only trusting the rendered `StatusPill` text.
   */
  async fetchEvidenceByFilename(
    caseId: string,
    fileName: string,
  ): Promise<{ state: string; errorReason: string | null; retryAction: string | null } | undefined> {
    const page = await this.fetchJson<{
      items: { filename: string; state: string; errorReason: string | null; retryAction: string | null }[];
    }>(`/api/cases/${caseId}/evidence`);
    return page.items.find((item) => item.filename === fileName);
  }
}
