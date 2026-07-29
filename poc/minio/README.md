# PoC: S3EvidenceStorage against real MinIO

See `CLAUDE.md` Section F for the workflow this follows.

## Pinned versions

- MinIO server: `minio/minio:latest` per `docker/docker-compose.dev.yml`
  (repo pins `latest` on purpose — not "fixed" here). Actual image pulled
  and run: `RELEASE.2025-09-07T16-13-09Z` (real version resolved at pull
  time, captured in `output.txt` container logs during the run).
- Client libs (`pyproject.toml`): `boto3>=1.34` (installed: 1.43.46),
  `aiobotocore>=2.13` (installed: 3.8.0). `requests` used only as the real
  HTTP client for the presigned-URL PUT (not a repo dependency, PoC-only).

## Container

```
docker run -d --name kronos-poc-minio-server \
  -p 19100:9000 -p 19101:9001 \
  -e MINIO_ROOT_USER=kronosadmin -e MINIO_ROOT_PASSWORD=kronossecret123 \
  minio/minio:latest server /data --console-address ":9001"
```

Torn down after the run (`docker rm -f kronos-poc-minio-server`) — nothing
left running.

## What this actually does

Uses the **real** `S3EvidenceStorage` class (`src/adapter/storage/s3.py`)
for every operation under test — no reimplementation of its logic. A raw
`boto3` client is used *only* for out-of-band verification (checking what
MinIO actually did after each `S3EvidenceStorage` call — e.g.
`get_object_lock_configuration`, `get_object_retention`,
`get_bucket_versioning`, `list_object_versions`), never to exercise the
class's own behavior. `tests/fixtures/factories.py`'s `make_evidence()` is
reused for the domain object, per CLAUDE.md B.5 (no hand-rolled domain
mocks).

Run (`docker` container from above must be running):

```
~/venv/bin/python3 poc/minio/run_poc.py
```

Full captured output of the last real run: `output.txt` (exit code 0, every
assertion passed).

## Note on how this PoC pass started

The task brief initially pointed at a CLAUDE.md Section F and `poc/`
examples that did not exist in this worktree — the worktree had been
created from `main`, and Section F only exists on
`fix/evidence-upload-camelcase`. Before writing a single line into `src/`,
this was caught, the coordinator confirmed, and the worktree was reset to
`origin/fix/evidence-upload-camelcase` (`git reset --hard`, no uncommitted
`src/` changes existed yet to lose). The `src/adapter/storage/s3.py` on
`main` (read only during the initial, mistaken exploration, never edited)
had several real gaps — no `set_legal_hold`, no per-object retention
applied on promote, `stream_object`/`object_exists` always resolving to the
quarantine bucket. **None of that applies to this branch** — its
`s3.py` already has `BucketKind`-aware bucket resolution, `set_legal_hold`,
and applies a bucket-level `COMPLIANCE` `DefaultRetention` rule via
`put_object_lock_configuration`. Recorded here only so a reviewer doesn't
wonder why the initial framing mentioned bugs that turned out not to exist
on this branch.

## Results — no bugs found in `src/`, verified working

Every check ran against the real container and every assertion passed
(see `output.txt` step-by-step). Highlights:

1. **`ensure_quarantine_bucket`/lazy quarantine creation** (via
   `request_presigned_upload`): real bucket created, confirmed **no**
   Object Lock config (`get_object_lock_configuration` →
   `ObjectLockConfigurationNotFoundError`, expected).
2. **`ensure_evidence_bucket`/lazy evidence-bucket creation** (via
   `promote_to_evidence_bucket`): real bucket created with
   `ObjectLockConfiguration = {'ObjectLockEnabled': 'Enabled', 'Rule':
   {'DefaultRetention': {'Mode': 'COMPLIANCE', 'Days': 1}}}` — confirmed via
   `get_object_lock_configuration`, not assumed from the code not throwing.
3. **Presigned PUT**: a real `requests.put()` to the generated URL
   returned `200`; bytes landed and were later read back byte-for-byte
   identical via `stream_object`.
4. **`promote_to_evidence_bucket`** (real `copy_object`): the **key
   open question** for this pass — does MinIO's `CopyObject` actually
   inherit the bucket's default Object Lock retention, given the
   implementation never passes `ObjectLockMode`/`ObjectLockRetainUntilDate`
   explicitly on the copy? Verified via real `get_object_retention`:
   `{'Mode': 'COMPLIANCE', 'RetainUntilDate': datetime(2026, 7, 22, ...)}`.
   **Yes — MinIO applies the bucket's default retention rule to objects
   landed via `CopyObject`, not just `PutObject`.** This was not documented
   anywhere obvious and was worth actually running rather than assuming.
5. **`object_exists`/`stream_object` with `bucket="evidence"`** (the
   contract `parsing_orchestration.py` relies on when reading
   `evidence.minio_evidence_key` post-promotion): both correctly resolve to
   the evidence bucket and return the right bytes.
6. **`delete_from_quarantine`**: real quarantine object confirmed gone
   afterward (`head_object` → 404).
7. **The compliance-mode WORM guarantee — the highest-value check**:
   - MinIO auto-enables bucket **versioning** when a bucket is created with
     `ObjectLockEnabledForBucket=True` (confirmed via
     `get_bucket_versioning` → `Enabled`) — this matches AWS S3 semantics
     and is required for Object Lock to mean anything.
   - An **unqualified** `delete_object` (no `VersionId`) on the promoted
     object does **not** destroy the locked version — it only adds a
     delete-marker; the retained version survives
     (`list_object_versions` still lists it). This is correct S3
     versioned-bucket behavior, not a bug — flagged here because it
     initially looked like a bug until the version history was inspected.
   - **The real test — deleting the exact locked `VersionId` before its
     `RetainUntilDate`** was rejected by real MinIO:
     ```
     delete_object(VersionId=<locked>) REJECTED by real MinIO:
     InvalidRequest: Object is WORM protected and cannot be overwritten
     ```
     This is the platform's core legal-admissibility guarantee, and it
     genuinely holds against a real server, not just "the code didn't
     throw."
   - The locked version's bytes were re-fetched via `VersionId` afterward
     and are still byte-for-byte identical to the original upload.
8. **`set_legal_hold`**: `put_object_legal_hold(Status="ON")` really sets
   the hold (confirmed via `get_object_legal_hold` → `{'Status': 'ON'}`),
   and with the hold on, deleting that exact version is independently
   rejected with the same `InvalidRequest: Object is WORM protected...`
   error. Clearing the hold (`Status="OFF"`) is confirmed the same way.
9. **`bucket_for`**: resolves to the correct fully-qualified evidence
   bucket name, matching what chain-of-custody audit entries need
   (`evidence_intake.py`'s `_bucket_for_audit`).

## Gaps / things this PoC does not cover

- Did not test retention-mode `GOVERNANCE` (only `COMPLIANCE`, which is
  what `_ensure_bucket` actually configures) or retention **extension**
  after the fact (`put_object_retention` with a later date) — not exercised
  by any code path in `src/`.
- Did not wait out the real retention period (`RetainUntilDate`) to confirm
  deletion becomes possible again after expiry — used `retention_days=1`
  for the PoC but didn't wait 24h; this is standard S3 Object Lock
  semantics and not something this repo's code controls, so treated as
  out of scope for a same-session PoC.
- Did not test MinIO's IAM/policy layer (bucket policies, MinIO admin
  users) — `S3EvidenceStorage` authenticates with root credentials only,
  matching how the dev compose file runs it.
- `presign_endpoint_url` (dual-endpoint signing for browser-vs-internal
  DNS) was not separately exercised — this PoC used the same endpoint for
  both `_client` and `_presign_client` since it runs entirely on
  `localhost`.

## Fixes made to `src/`

**None.** Every operation under test behaved exactly as the docstrings and
`Project_Specifications.md` claim, verified against a real MinIO server,
not inferred from the code. This is a "verified working" pass, not a
"bugs found" pass — see `poc/plaso/README.md` and
`poc/plaso_opensearch/README.md` for contrast (those found and fixed real
bugs); this component pair simply didn't have any to find.
