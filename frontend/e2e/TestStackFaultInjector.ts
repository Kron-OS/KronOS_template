import { ContainerFaultInjector } from "./ContainerFaultInjector";

/**
 * Deliberately breaks docker-compose.test.yml's real MinIO to force a
 * real, deterministic evidence-upload-request failure (Milestone QQQ).
 *
 * Unlike DevStackFaultInjector's OpenSearch target (stopped BEFORE
 * upload, since intake never touches OpenSearch at all -- only parsing/
 * indexing does, so the failure lands cleanly mid-pipeline as a
 * retryable parse-stage ERROR), MinIO sits in the critical path of the
 * upload's OWN first step: `POST /api/evidence/upload/request` calls
 * `ensure_quarantine_bucket()` (a real `head_bucket` call,
 * src/adapter/storage/s3.py) before ever returning a presigned URL. With
 * MinIO down, that request fails immediately with a real 500 --
 * confirmed live, no evidence row is ever created, no race window to
 * time. This is a genuinely different, real failure shape from the
 * OpenSearch case, not a copy-pasted variant of it -- verified live that
 * a real UploadDrawer bug existed here too (Milestone QQQ found and
 * fixed a stale-error-state bug: retrying the same file after MinIO
 * recovered showed the OLD "Request failed with status code 500" text
 * forever, even though the retry itself succeeded and the evidence
 * really did reach Complete -- src/components/UploadDrawer.tsx never
 * cleared `error` on a successful retry).
 *
 * Container name is fixed (`kronos-test-minio-1`,
 * docker-compose.test.yml's own `name: kronos-test`) -- **only ever
 * point this at the real, isolated test-stack profile.** Stop/restart
 * mechanics shared with `DevStackFaultInjector` via
 * `ContainerFaultInjector` (Milestone QQQ) -- only the target
 * container/project and the MinIO-specific method names live here.
 */
export class TestStackFaultInjector extends ContainerFaultInjector {
  constructor() {
    super("kronos-test-minio-1", "kronos-test");
  }

  stopMinio(): void {
    this.stop();
  }

  /** Restarts and blocks until the real container reports `healthy` again. */
  restartMinioAndWaitHealthy(timeoutMs = 90000): Promise<void> {
    return this.restartAndWaitHealthy(timeoutMs);
  }
}
