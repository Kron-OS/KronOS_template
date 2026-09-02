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
   * Real, independent `GET /{case_id}/evidence`, fresh bearer token --
   * for a caller (e.g. an Artifacts-seeding spec) that needs a REAL
   * evidence_id belonging to a REAL evidence row it just uploaded through
   * the UI above, not a fabricated one -- mirrors CasesPage.fetchCaseById's
   * own "never trust the same page load" reasoning.
   */
  async fetchFirstEvidenceId(caseId: string): Promise<string> {
    const result = await this.fetchJson<{ items: { id: string }[] }>(
      `/api/cases/${caseId}/evidence`,
    );
    const id = result.items[0]?.id;
    if (!id) throw new Error(`No evidence found for case ${caseId}`);
    return id;
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

  /** Clicks the real "Timeline" tab button (renders TimelineTab -> the Dashboards iframe embed). */
  async openTimelineTab(): Promise<void> {
    await this.page.getByRole("button", { name: "Timeline", exact: true }).click();
  }

  async openArtifactsTab(): Promise<void> {
    await this.page.getByRole("button", { name: "Artifacts", exact: true }).click();
  }

  /**
   * The real, live OpenSearch Dashboards iframe (`title="Timeline
   * Analysis"`, `TimelineTab` in `frontend/src/pages/CaseDetailPage.tsx`).
   * `frameLocator()` (not a plain `Locator`) is required to assert on
   * content INSIDE the iframe's own document, not just its `src`
   * attribute -- see `dashboards-embed.spec.ts` for why that distinction
   * is the entire point of this spec (the `_a`/`_g`/`_q` RISON state
   * lives in the URL fragment; only a real page load inside the frame,
   * driven by data-explorer's own client-side router, proves it actually
   * applied -- `poc/dashboards_embed/autoload_verification/README.md`
   * found a top-level-query-string version of this same URL gets
   * silently discarded by that same router).
   */
  getDashboardsFrame() {
    return this.page.frameLocator('iframe[title="Timeline Analysis"]');
  }

  /** Real `src` of the Dashboards iframe -- asserted on before trusting anything rendered inside it. */
  async getDashboardsIframeSrc(): Promise<string | null> {
    return this.page.locator('iframe[title="Timeline Analysis"]').getAttribute("src");
  }

  /** Clicks the real "Audit Log" tab button (renders AuditLogTab -> GET /api/cases/{id}/audit). */
  async openAuditLogTab(): Promise<void> {
    await this.page.getByRole("button", { name: "Audit Log", exact: true }).click();
  }

  /**
   * Waits for a real audit-log table row whose Event column shows the
   * given `AuditEventType` value (e.g. `"case.created"`, `"case.updated"`)
   * -- confirms `list_case_audit_events` returned real, specific content
   * for this case, not just a 200 with an empty page.
   */
  async waitForAuditEventRow(eventType: string, timeoutMs = 10000): Promise<void> {
    await this.page.locator(`td:has-text("${eventType}")`).first().waitFor({ timeout: timeoutMs });
  }

  /** Real "N total events" footer text rendered under the Audit Log table. */
  async getAuditLogTotalText(): Promise<string> {
    return this.page.locator("text=/\\d+ total events/").innerText();
  }

  /** Clicks the real "Settings" tab button (renders SettingsTab -- Milestone RRRR's new member/delete UI). */
  async openSettingsTab(): Promise<void> {
    await this.page.getByRole("button", { name: "Settings", exact: true }).click();
  }

  /** Real UI flow: fills the Members section's userId input and clicks Add (CaseMembersSection). */
  /**
   * Gap Audit Milestone ZZZZ: CaseMembersSection's "Add" flow is now a
   * real search-as-you-type picker (GET /{case_id}/member-candidates),
   * not a raw userId text field -- *searchTerm* should match the target
   * user's real username or email substring, not their id.
   */
  async addMemberViaUI(searchTerm: string): Promise<void> {
    await this.page.getByPlaceholder("Start typing a name or email...").fill(searchTerm);
    const suggestion = this.page.locator("li", { hasText: searchTerm });
    await suggestion.getByRole("button", { name: "Add", exact: true }).click();
  }

  /** Waits for *userId* to appear as a real member row in the Members list. */
  async waitForMemberRow(userId: string, timeoutMs = 10000): Promise<void> {
    await this.page.locator(`li:has-text("${userId}")`).waitFor({ timeout: timeoutMs });
  }

  /** Clicks the real per-row "Remove" button for *userId* (CaseMembersSection). */
  async removeMemberViaUI(userId: string): Promise<void> {
    await this.page
      .locator(`li:has-text("${userId}")`)
      .getByRole("button", { name: "Remove", exact: true })
      .click();
  }

  /** Waits for *userId*'s member row to be gone (real removal reflected in the UI). */
  async waitForMemberRowGone(userId: string, timeoutMs = 10000): Promise<void> {
    await this.page.locator(`li:has-text("${userId}")`).waitFor({ state: "detached", timeout: timeoutMs });
  }

  /** Real UI flow: clicks "Delete / Archive Case" then "Confirm Delete" (DeleteCaseSection). */
  async deleteCaseViaUI(): Promise<void> {
    await this.page.getByRole("button", { name: "Delete / Archive Case", exact: true }).click();
    await this.page.getByRole("button", { name: "Confirm Delete", exact: true }).click();
  }
}
