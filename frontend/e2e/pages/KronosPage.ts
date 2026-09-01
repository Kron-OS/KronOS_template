import type { Locator, Page } from "@playwright/test";

/**
 * Abstract base for KronOS page objects. Concrete pages implement
 * `waitUntilReady()` with a real, page-specific readiness signal -- never
 * a bare `networkidle`, which this app's real SSE/polling traffic makes
 * an unreliable proxy for "the page actually rendered its real data."
 *
 * Maintainability pass (2026-08-28, docs/GAP_AUDIT_2026-08-28_MILESTONE_EEE.md
 * finding #3): `getFreshAccessToken()`/`fetchJson()` and `pollLiveText()`
 * were previously copy-pasted (near-verbatim) into CasesPage/
 * DetectionDetailPage and reactively bolted onto CaseDetailPage
 * respectively -- extracted here before the next ~15 specs the plan calls
 * for compound the duplication.
 */
export abstract class KronosPage {
  constructor(protected readonly page: Page) {}

  abstract waitUntilReady(): Promise<void>;

  get url(): string {
    return this.page.url();
  }

  /**
   * Real, fresh bearer token via the app's own same-origin
   * POST /auth/refresh cookie proxy (real HttpOnly cookie attached by the
   * browser) -- the app authenticates API calls with an Authorization
   * header, not cookies, so any direct `fetch()` from within the page
   * needs this first.
   */
  protected async getFreshAccessToken(): Promise<string> {
    return this.page.evaluate(async () => {
      const res = await fetch("/auth/refresh", { method: "POST", credentials: "include" });
      const body = await res.json();
      return (body.accessToken ?? body.access_token) as string;
    });
  }

  /**
   * Fresh, independent `GET <path>` using a freshly-fetched bearer token
   * -- not trusted from the same page load that rendered whatever this is
   * being used to confirm, per docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.3's
   * own requirement ("not trusted from the same page load").
   */
  protected async fetchJson<T>(path: string): Promise<T> {
    return this.page.evaluate(
      async ({ path: p, token }) => {
        const res = await fetch(p, { headers: { Authorization: `Bearer ${token}` } });
        return res.json() as Promise<T>;
      },
      { path, token: await this.getFreshAccessToken() },
    );
  }

  /**
   * Fresh, independent `POST <path>` using a freshly-fetched bearer
   * token, returning the real HTTP status code -- for RBAC-denial specs
   * that need to assert on the exact status (403 vs 404 vs 200), not
   * just parse a success body. No frontend UI drives some of the actions
   * this exercises (e.g. add-case-member has no page yet), so this is
   * the real API call a future UI would make, issued directly.
   */
  protected async postJsonWithStatus(path: string, body: unknown): Promise<number> {
    return this.page.evaluate(
      async ({ path: p, token, b }) => {
        const res = await fetch(p, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify(b),
        });
        return res.status;
      },
      { path, token: await this.getFreshAccessToken(), b: body },
    );
  }

  /**
   * Fresh, independent `DELETE <path>` using a freshly-fetched bearer
   * token, returning the real HTTP status code -- same reasoning as
   * `postJsonWithStatus`, for RBAC-denial/grant specs exercising a route
   * with no frontend UI yet (e.g. case delete/archive has no button).
   */
  protected async deleteWithStatus(path: string): Promise<number> {
    return this.page.evaluate(
      async ({ path: p, token }) => {
        const res = await fetch(p, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        });
        return res.status;
      },
      { path, token: await this.getFreshAccessToken() },
    );
  }

  /**
   * Polls `locator`'s own live text WITHOUT reloading the page -- what
   * actually proves a live push path (SSE, etc.) works, not just that a
   * value is eventually correct after a fresh GET. Generalizes the
   * seed/terminal-state guard `CaseDetailPage.watchEvidenceStateLive`
   * needed after a real, reproduced bug (re-watching a row already
   * sitting on a terminal state from a PRIOR watch read that stale text
   * on the very first poll and returned immediately, before the backend
   * had done any new work) -- any caller re-watching a value that might
   * already be showing its own previous terminal reading needs this same
   * guard, not just evidence rows.
   */
  protected async pollLiveText(
    locator: Locator,
    options: {
      knownValues: readonly string[];
      terminalValues: readonly string[];
      seedValue?: string | null;
      timeoutMs?: number;
    },
  ): Promise<{ seenValues: string[]; terminal: string | null }> {
    const { knownValues, terminalValues, seedValue = null, timeoutMs = 60000 } = options;
    await locator.waitFor({ timeout: 15000 });

    const seenValues: string[] = [];
    let last: string | null = seedValue;
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      const text = await locator.innerText();
      for (const candidate of knownValues) {
        if (text.includes(candidate) && candidate !== last) {
          seenValues.push(candidate);
          last = candidate;
        }
      }
      if (last && last !== seedValue && terminalValues.includes(last)) break;
      await this.page.waitForTimeout(500);
    }

    return { seenValues, terminal: last === seedValue ? null : last };
  }
}
