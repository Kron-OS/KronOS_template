# Gap Audit — Milestone WW (2026-08-24)

Continuation of the JJ-VV gap-audit chain. This milestone was scoped
narrowly to one item: a PoC-verified fix for the significant finding
documented in `docs/GAP_AUDIT_2026-08-24_MILESTONE_VV.md` §4, which was
deliberately left unfixed there pending real MinIO verification.

---

## `S3EvidenceStorage`/`S3SealedBatchStorage`: silent Object Lock retention gap — FIXED, PoC-verified

**Recap of the finding (Milestone VV).** `_ensure_bucket()` in both
classes returned immediately on a successful `head_bucket` (bucket
already exists), silently assuming an already-existing bucket was already
correctly WORM-protected. `create_bucket(ObjectLockEnabledForBucket=True)`
and `put_object_lock_configuration(...)` are two separate API calls with
no transaction between them — a crash between them, or a transient
failure of the second call alone, left a bucket with object-lock enabled
at the bucket level but no default retention rule, and every later call
saw `head_bucket` succeed and stopped looking. This directly undermines
CLAUDE.md's own "Key Decision: MinIO Object Lock Compliance for evidence
WORM enforcement," and is more severe in `S3EvidenceStorage` (the primary
evidence bucket) than the sealed-batch sibling.

**Real PoC, before any `src/` change** (`poc/minio_object_lock_verification/`,
MinIO `RELEASE.2025-09-07T16-13-09Z`, `boto3`/`botocore` `1.43.46` — the
exact versions this repo runs, pinned via `docker exec docker-minio-1
minio --version` and the venv's own installed packages, not assumed),
against the real, live `docker-minio-1` container:

| Bucket state | `get_object_lock_configuration` result |
|---|---|
| Object-lock enabled, retention rule never applied (the real partial-failure state) | **Succeeds** (200) with `{"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}` — no `"Rule"` key. Confirmed **recoverable**: re-calling `put_object_lock_configuration` succeeds. |
| Object-lock never enabled at all | **Raises** `ClientError` (404, `Code="ObjectLockConfigurationNotFoundError"`). Confirmed **unrecoverable**: retroactively enabling fails with `Code="InvalidBucketState"`. |
| Healthy (both steps completed) | Both `"ObjectLockEnabled"` and `"Rule"` present. |

**Fix.** Added `_ensure_retention_rule()` to both classes: on `head_bucket`
success, call `get_object_lock_configuration` and branch on the real
shapes above — re-apply the missing rule if recoverable, raise
`StorageError` if not, no-op if healthy. Applied identically to
`S3EvidenceStorage`'s `BucketAlreadyOwnedByYou` concurrent-creation-race
branch, which made the same "the winner already finished" assumption
about the race loser. The quarantine-bucket path (`object_lock=False`) is
untouched — it was never expected to be WORM-protected.

**Verified the real, fixed production code directly against real MinIO**
(not just mocked unit tests) before writing any test: constructed the
real `S3EvidenceStorage`/`S3SealedBatchStorage` classes, manually created
both a partial-failure bucket and a never-enabled bucket via raw boto3
calls, then called the classes' own real (fixed) `_ensure_bucket()` and
confirmed: the partial-failure bucket's retention rule is retroactively
applied; the never-enabled bucket makes the real call raise
`StorageError`; the quarantine path is unaffected. All captured in
`poc/minio_object_lock_verification/output.txt`.

**Tests.** Updated the one existing test whose assumption the fix changed
(`test_ensure_evidence_bucket_tolerates_concurrent_creation_race` — now
explicitly mocks `get_object_lock_configuration` rather than relying on
its absence) and added 8 new tests across `test_s3_storage_bugs.py`/
`test_sealed_batch_storage.py` covering the recoverable/unrecoverable/
healthy/quarantine-untouched cases for both classes. Verified via `git
stash` that the 4 core new tests fail against the pre-fix source.

**Verification.** Full suite: **2048 passed, 2 skipped** (2039 → 2048,
+9 net new tests). Coverage 90.36% (gate 80%). `ruff`/`black` clean.
`mypy` repo-wide: 29 errors, identical to the pre-existing baseline
(confirmed the one error inside `sealed_batch_storage.py` itself is
pre-existing and unrelated, via `git stash`), zero new. Committed as
`9ac9894`. Confirmed no stray PoC test buckets left behind on the real
MinIO instance after cleanup.

---

## Recommendation for the next wake-up cycle

This closes out the significant finding from Milestone VV. Reasonable
next candidates, continuing the JJ-WW chain's own established method:

1. `frontend/src/pages/`/`components/` files not yet read in the JJ-WW
   chain (`ConnectorStatusPage.tsx`/`DetectionsPage.tsx`/`CasesPage.tsx`/
   `DetectionDetailPage.tsx`/`Layout.tsx`/`ErrorBoundary.tsx` were all
   covered in Milestone UU — check for anything remaining, e.g.
   `EvidenceDetailDrawer.tsx`, `ErrorCatalogue.tsx`, `StatusPill.tsx`,
   `RiskScorePill.tsx`, `TriageStatePill.tsx`, `ConnectorStatusPill.tsx`,
   `ConfirmDialog.tsx`, `Spinner.tsx`, `LoginPage.tsx` if not already
   independently reviewed).
2. `src/adapter/opensearch/rule_catalog.py`/`correlation_client.py`/
   `correlation_rule_provisioner.py` — the OpenSearch adapter files not
   named in the JJ-OO chain's own original candidate list.
3. `src/adapter/queue/celery_queue.py`/`event_dedup.py`/`stream_ingest.py`/
   `task_queue.py` were reviewed in Milestone QQ; `src/external/
   collector_app.py`/`run_dual_listener.py`/`mtls_protocol.py` have not
   had a dedicated pass.

Also still open from prior milestones, unchanged:
1. The lower-value optional SIEM/EDR secrets
   (`splunk_hec_token`/`sentinel_client_secret`/`defender_client_secret`)
   confirmed to degrade safely with `secrets_dir` but not yet moved off
   plaintext `environment:` in `docker-compose.prod.yml`.
2. Keycloak's own `KC_DB_PASSWORD`/`KC_ADMIN_PASSWORD` — no native
   file-secret convention exists in Keycloak 26.x itself.
3. The Postgres sync-replica ops-policy decision
   (`docs/POSTGRES_MINIO_HA_RESEARCH.md` §1.6) remains open for the
   project owner.
4. (UX-focused, not this audit chain's charter) `AdminPage.tsx`'s
   `UserRow` role-change/remove-user mutations have no `onError` handling.
