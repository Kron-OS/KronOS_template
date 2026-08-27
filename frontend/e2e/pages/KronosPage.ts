import type { Page } from "@playwright/test";

/**
 * Abstract base for KronOS page objects. Concrete pages implement
 * `waitUntilReady()` with a real, page-specific readiness signal -- never
 * a bare `networkidle`, which this app's real SSE/polling traffic makes
 * an unreliable proxy for "the page actually rendered its real data."
 */
export abstract class KronosPage {
  constructor(protected readonly page: Page) {}

  abstract waitUntilReady(): Promise<void>;

  get url(): string {
    return this.page.url();
  }
}
