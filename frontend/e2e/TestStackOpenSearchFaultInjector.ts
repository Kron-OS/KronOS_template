import { ContainerFaultInjector } from "./ContainerFaultInjector";

/**
 * Deliberately breaks docker-compose.test.yml's real OpenSearch to force
 * a real, retryable PARSE-stage evidence error (Milestone SSS) -- the
 * test-stack analogue of `DevStackFaultInjector`'s own OpenSearch target,
 * kept as a separate class from `TestStackFaultInjector` (MinIO) rather
 * than widening that class or `ContainerFaultInjector` itself to handle
 * multiple named targets per instance: `ContainerFaultInjector` is
 * deliberately single-target or design (matches `DevStackFaultInjector`'s
 * own shape exactly), and the test-stack profile now has two genuinely
 * different real dependencies worth faulting independently. This is NOT
 * the "duplicated pattern" Milestone PPP's own lesson warns against --
 * that was about un-shared, copy-pasted CORE stop/restart logic (fixed by
 * `ContainerFaultInjector`); this is the normal, intended shape of
 * multiple thin subclasses sharing that same base.
 *
 * Method names deliberately match `DevStackFaultInjector`'s own
 * (`stopOpenSearch`/`restartOpenSearchAndWaitHealthy`) -- same
 * dependency, same failure shape (intake never touches OpenSearch at
 * all, only parsing/indexing does, so stopping it before upload always
 * lands cleanly on a retryable parse-stage ERROR, no timing risk, same
 * as the dev-stack case `evidence-retry.spec.ts` already proved).
 *
 * Container name is fixed (`kronos-test-opensearch-1`,
 * docker-compose.test.yml's own `name: kronos-test`) -- **only ever
 * point this at the real, isolated test-stack profile.**
 */
export class TestStackOpenSearchFaultInjector extends ContainerFaultInjector {
  constructor() {
    super("kronos-test-opensearch-1", "kronos-test");
  }

  stopOpenSearch(): void {
    this.stop();
  }

  /** Restarts and blocks until the real container reports `healthy` again. */
  restartOpenSearchAndWaitHealthy(timeoutMs = 90000): Promise<void> {
    return this.restartAndWaitHealthy(timeoutMs);
  }
}
