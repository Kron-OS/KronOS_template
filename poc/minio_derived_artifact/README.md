# PoC: derived-artifact storage against real, live MinIO

**Version pinned**: `minio/minio:latest` (the actual running image tag in
`docker/docker-compose.dev.yml`), `boto3==1.43.56` (already installed in
`docker-kronos-backend-1`). Run for real inside that live container against
the real, already-running `docker-minio-1` service (port 9000, dev-stack
credentials from `docker-compose.dev.yml`).

## What this verifies (Milestone EEEEE, plan Stage 3.6 item 5)

That the planned `S3DerivedArtifactStorage` design -- a **separate**,
**non-WORM** bucket for derived/regenerable content (dumped files, future
registry exports), distinct from the WORM evidence bucket -- is real and
correct, not assumed:

1. A bucket created **without** `ObjectLockEnabledForBucket=True` genuinely
   has no Object Lock, confirmed via a real `get_object_lock_configuration`
   call (not inferred from `create_bucket` succeeding).
2. Put/get round-trips real bytes exactly (size + SHA-256 both match).
3. Delete on this bucket **succeeds** -- the functional contrast that
   justifies keeping derived artifacts out of the evidence bucket, where
   `poc/minio_object_lock_verification/` already confirmed Object Lock
   COMPLIANCE mode blocks deletion for the retention period.

A distinct `kronos-poc-derived-artifacts` bucket name was used (per
CLAUDE.md's PoC-naming convention) and fully cleaned up (objects + bucket
deleted) at the end of the run -- no real org's quarantine/evidence bucket
was touched.

## Real, captured results (`output.txt`)

```json
{
  "pre_cleanup": "nothing to clean (NoSuchBucket)",
  "bucket_created": "kronos-poc-derived-artifacts",
  "object_lock_configuration_error": "ObjectLockConfigurationNotFoundError",
  "put_object": {
    "key": "poc-org/case-1234/evidence-5678/artifact-9/dumpfiles/example.dat",
    "size_bytes": 35000,
    "sha256": "5f8981163f74d103a86b4bc86c0419efda1f6b620f7a6512cdb0e387b2829394"
  },
  "get_object": {
    "size_bytes": 35000,
    "sha256": "5f8981163f74d103a86b4bc86c0419efda1f6b620f7a6512cdb0e387b2829394",
    "matches_original_bytes": true
  },
  "delete_confirmed": true,
  "post_cleanup": "PoC bucket removed"
}
```

- `object_lock_configuration_error: "ObjectLockConfigurationNotFoundError"`
  is the SAME real error code `poc/minio_object_lock_verification/` uses to
  distinguish "Object Lock genuinely never enabled" from "enabled but
  retention rule missing" -- here it's the *expected, correct* outcome
  (confirms no WORM), not a bug being investigated.
- `matches_original_bytes: true` -- real 35,000-byte payload round-tripped
  through MinIO byte-for-byte, SHA-256 identical on both sides.
- `delete_confirmed: true` -- `delete_object` followed by a real
  `head_object` returning 404, confirming deletion genuinely took effect
  (would be blocked with `AccessDenied` on the WORM evidence bucket during
  its retention window).

## Design confirmation

`S3DerivedArtifactStorage` (`src/adapter/storage/s3_derived_artifact.py`,
to be built) can safely reuse `S3EvidenceStorage`'s real,
already-proven boto3 patterns (`_ensure_bucket`-style lazy creation,
`_s3_stream` chunked download) but must call `create_bucket` **without**
`ObjectLockEnabledForBucket` and **without** the retention-rule follow-up
call -- confirmed live, not assumed, that this genuinely produces a
non-WORM bucket where derived artifacts can be deleted/regenerated freely.
Object key convention `{org_alias}/{case_id}/{evidence_id}/{artifact_id}/{filename}`
(one path segment deeper than the evidence key convention, to allow
multiple derived artifacts per source evidence item) is confirmed
mechanically compatible with real MinIO key naming (slashes in keys work
as expected, no bucket/prefix collision with the real per-org quarantine/
evidence buckets since the bucket name itself is distinct:
`kronos-derived-{org_alias}` vs. `kronos-evidence-{org_alias}` /
`kronos-quarantine-{org_alias}-quarantine`).

## Status

**PASS.** All five PoCs for Milestone EEEEE's plan Stage 3.6 (multiplugin
worker, JsonRenderer reuse, dumpfiles extraction, registry printkey
drill-down, derived-artifact MinIO storage) are now complete with real
captured evidence. Proceeding to `src/` implementation: `DerivedArtifactStorage`
ABC + `S3DerivedArtifactStorage`, on-demand Celery task + routes, audit
events, worker `windows.dumpfiles`/registry extension.
