import { ContainerFaultInjector } from "./ContainerFaultInjector";

/**
 * Deliberately breaks docker-compose.test.yml's real ClamAV to force a
 * real, deterministic, RETRYABLE INTAKE-stage evidence error (Milestone
 * FFFF) -- the gap named since Milestone QQQ ("intake-stage retry has zero
 * E2E coverage") and explicitly declined there as too racy to build safely.
 *
 * Investigating the real code (src/application/evidence_intake.py,
 * src/external/celery_app.py) found the same "stop it before upload"
 * determinism `DevStackFaultInjector`'s OpenSearch target already relies
 * on, just at a different pipeline stage: intake's own AV-scan step
 * (`_run_scan`, ClamAVScanner.scan_stream) is a SEPARATE real dependency
 * from MinIO, invoked only from inside `kronos.process_intake` (Celery),
 * never synchronously from the client-facing `POST
 * /api/evidence/upload/finalize/{id}` route -- unlike MinIO (Milestone
 * QQQ's own finding), which start_intake() DOES touch synchronously
 * (`object_exists`, a HEAD check) before ever enqueuing that task. That
 * means: stop ClamAV before the upload even starts (same recipe as
 * OpenSearch), let the real PUT to MinIO succeed and finalize succeed too
 * (MinIO is untouched, still healthy), and `process_intake`'s own first
 * real attempt deterministically fails reaching ClamAV -- no race, no
 * timing window to lose, confirmed by reading
 * `ClamAVScanner.scan_stream()` (src/application/scanning.py):
 * `asyncio.open_connection()` against a stopped container raises `OSError`
 * near-instantly (connection refused, not a hung timeout), wrapped as a
 * `StorageError` that is NOT a `ValidationError` -- so it is NOT
 * terminal (`is_retryable_error_reason("intake_failed:StorageError")` is
 * `True`, confirmed from `domain/evidence.py`'s own reason lists) and
 * routes the frontend's Retry button to `retryIntake()`, not
 * `retryParse()` (`is_parse_stage_error_reason()` returns `False` for this
 * reason -- `_retry_action_for()`, src/external/routes/evidence.py).
 *
 * This exact mechanism (stop docker-clamav-1, real upload, real
 * ERROR/intake_failed:StorageError, real retry-intake recovering to
 * COMPLETE) was already proven backend-only, API-level, against the real
 * dev stack in `poc/evidence_intake_async/run_poc.py` (14/14 checks
 * passed) -- what was still missing, named explicitly in that PoC's own
 * "Not yet done" section, is a real BROWSER click-through of the Retry
 * button succeeding for a retryable reason. This class/spec closes that.
 *
 * Real, previously-undiscovered gap found investigating this (fixed
 * alongside this class, docker-compose.test.yml's own celery-worker
 * service): that service never set CLAMD_HOST/CLAMD_PORT at all, so
 * `configure_clamav_from_settings()`'s dev/test-mode fallback silently
 * downgraded the ONLY worker that actually calls `scan_stream()` to the
 * permissive `NoOpScanner` for its entire process lifetime -- meaning
 * this exact failure could never have been forced (or ANY file real
 * AV-scanned) against this profile before that fix, no matter how this
 * class stopped the container. Mirrors `docker-compose.dev.yml`'s own
 * celery-worker CLAMD_HOST/CLAMD_PORT values, matching the same class of
 * gap `poc/evidence_intake_async/README.md` already found and fixed for
 * `docker-compose.dev.yml`/`.prod.yml` (that PoC's own finding #1 did not
 * cover this file).
 *
 * Container name is fixed (`kronos-test-clamav-1`,
 * docker-compose.test.yml's own `name: kronos-test`) -- **only ever point
 * this at the real, isolated test-stack profile.**
 */
export class TestStackClamAVFaultInjector extends ContainerFaultInjector {
  constructor() {
    super("kronos-test-clamav-1", "kronos-test");
  }

  stopClamAV(): void {
    this.stop();
  }

  /**
   * Restarts and blocks until the real container reports `healthy` again.
   * Longer default timeout than the other test-stack injectors: clamd
   * reloads its full virus database on every restart --
   * `poc/evidence_intake_async/run_poc.py`'s own real, timestamped finding
   * was ~15s for this on a warm host, and this profile's `clamav` service
   * (unlike docker-compose.dev.yml's) has no persistent volume for the
   * database, so a cold pull could take meaningfully longer.
   */
  restartClamAVAndWaitHealthy(timeoutMs = 120000): Promise<void> {
    return this.restartAndWaitHealthy(timeoutMs);
  }
}
