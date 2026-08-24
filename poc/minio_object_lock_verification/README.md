# PoC: MinIO Object Lock retention-configuration verification

**Gap Audit Milestone WW.** Verifies, against the real, running
`docker-minio-1` container, the real response shapes needed to fix
`S3EvidenceStorage._ensure_bucket()`/`S3SealedBatchStorage._ensure_bucket()`'s
silent Object Lock retention gap (see
`docs/GAP_AUDIT_2026-08-24_MILESTONE_VV.md` §4 for the original finding).

## Versions pinned

- MinIO: `RELEASE.2025-09-07T16-13-09Z` (the real, running `docker-minio-1`
  container's version — `docker exec docker-minio-1 minio --version`;
  `docker-compose.dev.yml`/`docker-compose.prod.yml` both pin
  `minio/minio:latest`, so this is the version actually deployed today,
  not assumed).
- `boto3`/`botocore`: `1.43.46` (`python3 -c "import boto3; print(boto3.__version__)"`
  in this repo's own venv; `pyproject.toml` pins `boto3>=1.34`).

## What this proves

`run_poc.py` creates three real, throwaway buckets against the live
MinIO S3 API (`http://localhost:9000`, the `kronos_minio` dev credentials
already used by the real dev stack) and calls `get_object_lock_configuration`
against each, to determine — empirically, not assumed — the real response
shape for each of the three bucket states `_ensure_bucket()` needs to
distinguish:

1. **(a) Partial failure** — `create_bucket(ObjectLockEnabledForBucket=True)`
   succeeded but `put_object_lock_configuration` was never called (the
   real state a crash or a transient failure between those two separate
   API calls leaves behind). Real result:
   `get_object_lock_configuration` **succeeds** (HTTP 200) with
   `{"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}` — no
   `"Rule"` key. **Recoverable**: re-calling
   `put_object_lock_configuration` on it succeeds and adds the missing
   rule (verified in the same run).

2. **(b) Object Lock never enabled at all** (a bucket created without
   `ObjectLockEnabledForBucket`). Real result: `get_object_lock_configuration`
   **raises** `ClientError` — HTTP 404,
   `Code="ObjectLockConfigurationNotFoundError"`. **Unrecoverable**:
   confirmed empirically (not assumed from S3 API docs) that retroactively
   calling `put_object_lock_configuration` on it fails with
   `Code="InvalidBucketState"`, `Message="Object Lock configuration cannot
   be enabled on existing buckets"`.

3. **(c) Healthy baseline** — both calls completed normally. Real result:
   `get_object_lock_configuration` succeeds with both `"ObjectLockEnabled"`
   and `"Rule"` present — the shape every existing test in this repo
   already assumed was the only possible one.

`output.txt` also includes a second verification pass run directly
against the real, **fixed** `S3EvidenceStorage`/`S3SealedBatchStorage`
classes themselves (not just raw boto3 calls) — three cases per class,
against real MinIO: a pre-existing partial-failure bucket gets its
retention rule retroactively applied by a real call to the fixed
`_ensure_bucket()`; a pre-existing never-enabled bucket makes the fixed
`_ensure_bucket()` raise `StorageError` instead of silently proceeding;
and the quarantine-bucket path (`object_lock=False`) is confirmed
unaffected by the new check (no regression on the non-WORM path).

## How to run

```bash
source /home/reca/venv/bin/activate
python3 poc/minio_object_lock_verification/run_poc.py
```

Requires `docker-minio-1` running (already part of this dev stack) and
reachable at `http://localhost:9000` with the dev credentials
(`kronos_minio` / `kronos_minio_dev_password`, matching
`docker-compose.dev.yml`'s own defaults). Creates and deletes only its own
`kronos-poc-objlock-*`/`kronos-poc-wwfix-*` throwaway buckets — never
touches any real evidence/sealed-batch bucket.
