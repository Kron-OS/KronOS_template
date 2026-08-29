import { execSync } from "node:child_process";

/**
 * Shared stop/restart/ensure-running mechanics for deliberately breaking a
 * real dependency of a real, already-running Compose stack to force a
 * real, retryable pipeline error. Extracted (Milestone QQQ) the moment a
 * second fault injector (`TestStackFaultInjector`, targeting the test
 * profile's MinIO) needed the exact same shape `DevStackFaultInjector`
 * already had -- per this initiative's own Cycle 13 lesson, a shared
 * module is worth creating as soon as a SECOND instance of a pattern
 * appears, not after a third one silently drifts (exactly what happened
 * with the KRONOS_E2E_KEYCLOAK_URL override across two fixture scripts,
 * Milestones NNN/OOO/PPP).
 *
 * Every subclass MUST fix its own `container`/`expectedProject` at
 * construction and never accept them from a caller -- this class exists
 * to make the stop/restart pair for one specific, known-safe target
 * impossible to leave mismatched, not to be a generic "stop any
 * container" wrapper. `assertExpectedProject()` checks the real
 * `com.docker.compose.project` label at call time rather than trusting
 * the container name alone, so reusing a subclass against a
 * differently-launched stack fails loudly instead of silently touching a
 * container this caller doesn't own (CLAUDE.md: never touch containers
 * you didn't create).
 */
export abstract class ContainerFaultInjector {
  protected constructor(
    private readonly container: string,
    private readonly expectedProject: string,
  ) {}

  private assertExpectedProject(): void {
    let project: string;
    try {
      project = execSync(
        `docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' ${this.container}`,
        { stdio: "pipe" },
      )
        .toString()
        .trim();
    } catch {
      throw new Error(
        `${this.constructor.name}: container '${this.container}' not found -- refusing to guess.`,
      );
    }
    if (project !== this.expectedProject) {
      throw new Error(
        `${this.constructor.name}: '${this.container}' belongs to Compose project '${project}', ` +
          `expected '${this.expectedProject}'. Refusing to stop/start a container this class ` +
          `doesn't own -- if this fired, something other than the intended stack currently holds ` +
          `this container name.`,
      );
    }
  }

  protected stop(): void {
    this.assertExpectedProject();
    execSync(`docker stop ${this.container}`, { stdio: "pipe" });
  }

  /** Restarts and blocks until the real container reports `healthy` again. */
  protected async restartAndWaitHealthy(timeoutMs = 90000): Promise<void> {
    this.assertExpectedProject();
    execSync(`docker start ${this.container}`, { stdio: "pipe" });
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const status = execSync(`docker inspect -f '{{.State.Health.Status}}' ${this.container}`, {
        stdio: "pipe",
      })
        .toString()
        .trim();
      if (status === "healthy") return;
      await new Promise((r) => setTimeout(r, 2000));
    }
    throw new Error(`${this.container} did not report healthy within ${timeoutMs}ms`);
  }

  /** Best-effort cleanup for a test that failed before its own restart step ran. */
  ensureRunning(): void {
    this.assertExpectedProject();
    const status = execSync(`docker inspect -f '{{.State.Status}}' ${this.container}`, {
      stdio: "pipe",
    })
      .toString()
      .trim();
    if (status !== "running") {
      execSync(`docker start ${this.container}`, { stdio: "pipe" });
    }
  }
}
