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

  /**
   * Same real UI flow as createCase(), but does NOT assume success --
   * for a caller (e.g. an RBAC-denial spec) expecting the real backend to
   * reject the request. Real 403s land inside CreateCaseModal's own
   * mutation.isError branch (frontend/src/pages/CasesPage.tsx), rendered
   * via ErrorBanner with the still-open modal, not a redirect -- so this
   * waits for that banner rather than a new case row.
   */
  async attemptCreateCase(title: string, ref: string): Promise<void> {
    await this.page.click("text=New Case");
    await this.page.waitForSelector("#case-title", { timeout: 10000 });
    await this.page.fill("#case-title", title);
    await this.page.fill("#case-ref", ref);
    await this.page.click("button:has-text('Create')");
  }

  /** The real inline error banner CreateCaseModal renders on a failed mutation. */
  async waitForCreateCaseError(timeoutMs = 15000): Promise<string> {
    const el = this.page.locator("text=/Failed to create case/");
    await el.waitFor({ timeout: timeoutMs });
    return el.innerText();
  }

  /**
   * Real `POST /api/cases/{id}/members` call, issued directly (no
   * frontend UI drives this action yet) -- for `assert_case_lead_or_admin`
   * RBAC coverage. Returns the real HTTP status; callers assert on it
   * rather than the response body, since a real 403 body isn't the
   * `CaseOut` shape a success response would be.
   */
  async attemptAddMember(caseId: string, userId: string): Promise<number> {
    return this.postJsonWithStatus(`/api/cases/${caseId}/members`, { userId });
  }

  /**
   * Real `GET /{case_id}/member-candidates` call (Gap Audit Milestone
   * ZZZZ), issued directly -- for `assert_case_lead_or_admin` RBAC
   * coverage of the new case-member search endpoint, same reasoning as
   * `attemptAddMember`.
   */
  async attemptListMemberCandidates(caseId: string, q: string): Promise<number> {
    return this.getWithStatus(`/api/cases/${caseId}/member-candidates?q=${encodeURIComponent(q)}`);
  }

  /**
   * Real `DELETE /api/cases/{id}` call, issued directly (no frontend UI
   * drives this action yet, same reasoning as `attemptAddMember`) -- for
   * `assert_case_lead_or_admin` RBAC coverage of the delete/archive route.
   * Returns the real HTTP status; a success is a real `204 No Content`
   * (`DeleteCase`'s own `status_code=status.HTTP_204_NO_CONTENT`), not a
   * `CaseOut` body.
   */
  async attemptDeleteCase(caseId: string): Promise<number> {
    return this.deleteWithStatus(`/api/cases/${caseId}`);
  }

  /**
   * Real `DELETE /api/cases/{id}/members/{userId}` call (Milestone OOOO,
   * `remove_case_member` -- the mirror image `add_case_member` never had),
   * issued directly, same reasoning as `attemptAddMember`/`attemptDeleteCase`.
   * Returns the real HTTP status; a success is a real `200` with a
   * `CaseOut` body (idempotent -- removing a non-member also returns 200,
   * confirmed by reading the route before writing this).
   */
  async attemptRemoveMember(caseId: string, userId: string): Promise<number> {
    return this.deleteWithStatus(`/api/cases/${caseId}/members/${userId}`);
  }

  /**
   * Fresh, independent `GET /api/cases/{id}` (docs/PLAYWRIGHT_E2E_TEST_PLAN.md
   * §3.3's own "not trusted from the same page load" requirement) --
   * for a caller confirming a real membership grant's effect persisted
   * server-side, not just that the page that rendered it looked right.
   */
  async fetchCaseById(caseId: string): Promise<{ id: string; title: string; status: string }> {
    return this.fetchJson<{ id: string; title: string; status: string }>(`/api/cases/${caseId}`);
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
