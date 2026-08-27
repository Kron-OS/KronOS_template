import { execSync } from "node:child_process";

/**
 * Deliberately breaks a real dependency of the real dev stack to force a
 * real, retryable pipeline error -- the same technique
 * poc/evidence_parse_retry/README.md already proved live ("stopped
 * docker-opensearch-1 mid-flight after intake genuinely completed --
 * evidence lands on ERROR/ingest_failed ... retryAction='parse'"), reused
 * here to close that PoC's own named-open item: a real browser
 * click-through of the Retry button succeeding, which that Python-script
 * attempt hit selector/routing trouble driving and left unverified.
 *
 * Container name is fixed (`docker-opensearch-1`, this repo's own
 * `docker-compose.dev.yml` project naming) -- this class exists to make
 * the stop/restart pair impossible to leave mismatched, not to be a
 * generic Docker wrapper.
 */
export class DevStackFaultInjector {
  private static readonly CONTAINER = "docker-opensearch-1";

  stopOpenSearch(): void {
    execSync(`docker stop ${DevStackFaultInjector.CONTAINER}`, { stdio: "pipe" });
  }

  /** Restarts and blocks until the real container reports `healthy` again. */
  async restartOpenSearchAndWaitHealthy(timeoutMs = 90000): Promise<void> {
    execSync(`docker start ${DevStackFaultInjector.CONTAINER}`, { stdio: "pipe" });
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const status = execSync(
        `docker inspect -f '{{.State.Health.Status}}' ${DevStackFaultInjector.CONTAINER}`,
        { stdio: "pipe" },
      )
        .toString()
        .trim();
      if (status === "healthy") return;
      await new Promise((r) => setTimeout(r, 2000));
    }
    throw new Error(`${DevStackFaultInjector.CONTAINER} did not report healthy within ${timeoutMs}ms`);
  }

  /** Best-effort cleanup for a test that failed before its own restart step ran. */
  ensureRunning(): void {
    const status = execSync(`docker inspect -f '{{.State.Status}}' ${DevStackFaultInjector.CONTAINER}`, {
      stdio: "pipe",
    })
      .toString()
      .trim();
    if (status !== "running") {
      execSync(`docker start ${DevStackFaultInjector.CONTAINER}`, { stdio: "pipe" });
    }
  }
}
