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
   * Returns the ordered sequence of distinct states observed, and whether
   * a terminal state was reached before `timeoutMs`.
   *
   * `seedState`: real, reproduced bug this parameter fixes -- re-watching
   * a row that's already sitting on a terminal state from a PRIOR watch
   * (e.g. re-watching after clicking Retry on an ERROR row) otherwise
   * reads that stale terminal text on the very first poll and returns
   * immediately, before the backend has done any real work. Seeding
   * `last` with the already-known state means only a genuine, new
   * transition away from it counts.
   */
  async watchEvidenceStateLive(
    fileName: string,
    timeoutMs = 60000,
    seedState: string | null = null,
  ): Promise<{ seenStates: string[]; terminal: string | null }> {
    const row = this.page.locator(`tr:has-text('${fileName}')`);
    await row.waitFor({ timeout: 15000 });

    const seenStates: string[] = [];
    let last: string | null = seedState;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const text = await row.innerText();
      for (const candidate of KNOWN_STATES) {
        if (text.includes(candidate) && candidate !== last) {
          seenStates.push(candidate);
          last = candidate;
        }
      }
      if (last && last !== seedState && (TERMINAL_STATES as readonly string[]).includes(last)) break;
      await this.page.waitForTimeout(500);
    }

    return { seenStates, terminal: last === seedState ? null : last };
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
}
