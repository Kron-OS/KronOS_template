import { ContainerFaultInjector } from "./ContainerFaultInjector";

/**
 * Dev-stack analogue of `TestStackClamAVFaultInjector` -- see that class's
 * own docstring for the full real investigation (Milestone FFFF) behind
 * why ClamAV, stopped BEFORE upload, is a genuinely deterministic way to
 * force a real, retryable INTAKE-stage error (as opposed to MinIO, which
 * Milestone QQQ found sits in the upload's own first synchronous step).
 *
 * Built alongside the test-stack version, not instead of it, for the same
 * reason `DevStackFaultInjector`/`TestStackOpenSearchFaultInjector` both
 * exist for the parse-stage OpenSearch case: this host's already-running
 * dev stack (`docker-clamav-1`, already correctly wired with
 * `CLAMD_HOST`/`CLAMD_PORT` per `poc/evidence_intake_async/README.md`'s
 * own finding #1) gives a real, zero-extra-container way to verify the
 * exact same mechanism live, without the memory cost of standing up a
 * whole isolated `kronos-test` stack (real, observed constraint this
 * session -- see docs/GAP_AUDIT_2026-08-28_MILESTONE_FFFF.md for the
 * actual swap-exhaustion numbers that made this the deciding factor for
 * this cycle's own primary live verification).
 *
 * Mirrors `evidence-retry.spec.ts`'s own precedent: this spec is
 * deliberately NOT wired into `frontend-e2e-smoke` (that CI job only ever
 * builds the isolated `docker-compose.test.yml` profile, matching every
 * other fault-injection spec already wired there) -- see
 * `evidence-intake-retry.spec.ts` for the CI-wired test-stack twin.
 *
 * Container name is fixed (`docker-clamav-1`, this repo's own
 * `docker-compose.dev.yml` project naming) -- **only ever point this at
 * the real dev stack.**
 */
export class DevStackClamAVFaultInjector extends ContainerFaultInjector {
  constructor() {
    super("docker-clamav-1", "docker");
  }

  stopClamAV(): void {
    this.stop();
  }

  /** See TestStackClamAVFaultInjector's identical comment on the longer default timeout. */
  restartClamAVAndWaitHealthy(timeoutMs = 120000): Promise<void> {
    return this.restartAndWaitHealthy(timeoutMs);
  }
}
