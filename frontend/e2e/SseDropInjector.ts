import https from "node:https";
import type { Page, Route } from "@playwright/test";

const TERMINAL_STATE_RE = /"state":\s*"(COMPLETE|ERROR)"/;
const ANY_STATE_RE = /"state":\s*"(\w+)"/;

/**
 * Forces a real, deterministic SSE connection drop mid-stream --
 * docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.7's "SSE connection drop mid-upload"
 * scenario.
 *
 * Investigated two other approaches live against the real dev stack before
 * landing on this one (see the Milestone IIII gap-audit doc for the full
 * account, captured console output included):
 *
 * 1. `browserContext.setOffline(true)` on an already-open EventSource --
 *    confirmed it does NOT error the connection within any deterministic
 *    window (8+ real seconds observed, zero `error`/`close` events). This
 *    matches Chromium's actual offline-emulation behavior: it blocks NEW
 *    connections, not bytes already flowing on an established one.
 * 2. Waiting for the real 60s one-shot ticket to expire naturally -- the
 *    test plan doc itself already flags this as too slow for a
 *    deterministic test.
 *
 * What DOES work, confirmed live: `page.route()` can only ever decide
 * continue/abort/fulfill ONCE, at the moment a request is first observed
 * -- it cannot reach into a connection already in flight. So this class
 * intercepts the SSE GET at that one decision point and, instead of
 * `route.continue()`, acts as a real authenticated proxy: a genuine
 * `https.get()` against the real backend (through the real nginx/TLS
 * front door, using the exact one-shot ticket `useEvidenceSSE.ts` itself
 * minted), forwarding real bytes until real evidence-state data confirms
 * the pipeline is genuinely mid-flight (a non-terminal state), then
 * severs the real backend connection and `route.fulfill()`s the browser
 * with exactly what was genuinely received -- a real, complete-looking
 * HTTP response that simply stops. Per the WHATWG EventSource spec, the
 * browser's own EventSource treats an unexpected close as connection loss
 * (fires `error`) exactly like a real network drop would -- confirmed
 * live (`readyState` transitions to `CONNECTING` before the app's own
 * `onerror` handler closes it for good and starts the polling fallback).
 */
export class SseDropInjector {
  private dropped = false;
  private lastBody = "";
  private lastObservedNonTerminalState: string | null = null;

  constructor(
    private readonly urlPattern: string,
    private readonly maxWaitMs = 30000,
  ) {}

  /** Registers the route handler. Call BEFORE the page navigates to where useEvidenceSSE.ts connects. */
  async arm(page: Page): Promise<void> {
    await page.route(this.urlPattern, async (route) => {
      if (this.dropped) {
        await route.continue();
        return;
      }
      this.dropped = true;
      await this.proxyThenCut(route);
    });
  }

  private proxyThenCut(route: Route): Promise<void> {
    const url = route.request().url();
    const chunks: Buffer[] = [];

    return new Promise<void>((resolveOuter) => {
      const finish = (res?: { destroy: () => void }) => {
        res?.destroy();
        resolveOuter();
      };
      const deadline = setTimeout(() => finish(), this.maxWaitMs);

      const req = https.get(
        url,
        { rejectUnauthorized: false, headers: { Accept: "text/event-stream" } },
        (res) => {
          res.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
            const text = Buffer.concat(chunks).toString("utf-8");
            const anyState = text.match(ANY_STATE_RE);
            if (anyState && !TERMINAL_STATE_RE.test(text)) {
              // Real, genuine non-terminal evidence state observed from the
              // real backend -- this is the moment to sever the connection,
              // matching the scenario's own "still in a non-terminal state"
              // requirement, not an arbitrary blind timer.
              this.lastObservedNonTerminalState = anyState[1];
              clearTimeout(deadline);
              finish(res);
            } else if (TERMINAL_STATE_RE.test(text)) {
              // The real pipeline already reached a terminal state before a
              // non-terminal one was ever observed -- too fast for this
              // technique to prove a genuine mid-upload drop this run. Cut
              // anyway so the request doesn't hang; the caller's own
              // droppedWhileNonTerminal check fails loudly rather than
              // silently passing.
              clearTimeout(deadline);
              finish(res);
            }
          });
          res.on("close", () => {
            clearTimeout(deadline);
            resolveOuter();
          });
          res.on("error", () => {
            clearTimeout(deadline);
            resolveOuter();
          });
        },
      );
      req.on("error", () => {
        clearTimeout(deadline);
        resolveOuter();
      });
    }).then(() => {
      const body = Buffer.concat(chunks).toString("utf-8");
      this.lastBody = body;
      return route.fulfill({
        status: 200,
        headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" },
        body,
      });
    });
  }

  /** True once the one deliberate drop has actually happened. */
  get hasDropped(): boolean {
    return this.dropped;
  }

  /** The real non-terminal state observed from the real backend right before the cut, if any. */
  get droppedWhileNonTerminal(): string | null {
    return this.lastObservedNonTerminalState;
  }

  /** The real bytes forwarded from the real backend before the cut (for debugging/assertions). */
  get capturedBody(): string {
    return this.lastBody;
  }
}
