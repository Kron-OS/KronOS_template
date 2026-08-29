import { ContainerFaultInjector } from "./ContainerFaultInjector";

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
 * `docker-compose.dev.yml` project naming) -- **only ever point this at
 * the real dev stack.** `docker-compose.test.yml`/`.prod.yml` each have
 * their own distinct Compose `name:` (Milestone EEE fixed a real
 * project-name collision between them) -- a container literally named
 * `docker-opensearch-1` only exists under the dev stack's project.
 * `ContainerFaultInjector`'s own project-label assertion still checks
 * this at call time rather than trusting the name alone (Milestone LLL).
 * Stop/restart mechanics shared with `TestStackFaultInjector` via
 * `ContainerFaultInjector` (Milestone QQQ) -- only the target
 * container/project and the OpenSearch-specific method names live here.
 */
export class DevStackFaultInjector extends ContainerFaultInjector {
  constructor() {
    super("docker-opensearch-1", "docker");
  }

  stopOpenSearch(): void {
    this.stop();
  }

  /** Restarts and blocks until the real container reports `healthy` again. */
  restartOpenSearchAndWaitHealthy(timeoutMs = 90000): Promise<void> {
    return this.restartAndWaitHealthy(timeoutMs);
  }
}
