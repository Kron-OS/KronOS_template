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
 * generic Docker wrapper. **Only ever point this at the real dev stack.**
 * `docker-compose.test.yml`/`.prod.yml` each have their own distinct
 * Compose `name:` (Milestone EEE fixed a real project-name collision
 * between them) -- a container literally named `docker-opensearch-1`
 * only exists under the dev stack's project. `_assertDevStackProject()`
 * below still checks the label at call time rather than trusting the
 * name alone, so that reusing this class against a differently-launched
 * stack fails loudly instead of silently touching a container this
 * caller doesn't own (CLAUDE.md: never touch containers you didn't
 * create) -- a real, previously-unguarded risk flagged by Milestone KKK's
 * own coverage-gap review, not yet triggered only because no CI job wires
 * this class in against anything but the dev stack today.
 */
export class DevStackFaultInjector {
  private static readonly CONTAINER = "docker-opensearch-1";
  private static readonly EXPECTED_PROJECT = "docker";

  private static assertDevStackProject(): void {
    let project: string;
    try {
      project = execSync(
        `docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' ${DevStackFaultInjector.CONTAINER}`,
        { stdio: "pipe" },
      )
        .toString()
        .trim();
    } catch {
      throw new Error(
        `DevStackFaultInjector: container '${DevStackFaultInjector.CONTAINER}' not found -- ` +
          `refusing to guess. This class only targets the real dev stack.`,
      );
    }
    if (project !== DevStackFaultInjector.EXPECTED_PROJECT) {
      throw new Error(
        `DevStackFaultInjector: '${DevStackFaultInjector.CONTAINER}' belongs to Compose project ` +
          `'${project}', expected '${DevStackFaultInjector.EXPECTED_PROJECT}' (the real dev stack). ` +
          `Refusing to stop/start a container this class doesn't own -- if this fired, something ` +
          `other than the dev stack currently holds this container name.`,
      );
    }
  }

  stopOpenSearch(): void {
    DevStackFaultInjector.assertDevStackProject();
    execSync(`docker stop ${DevStackFaultInjector.CONTAINER}`, { stdio: "pipe" });
  }

  /** Restarts and blocks until the real container reports `healthy` again. */
  async restartOpenSearchAndWaitHealthy(timeoutMs = 90000): Promise<void> {
    DevStackFaultInjector.assertDevStackProject();
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
    DevStackFaultInjector.assertDevStackProject();
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
