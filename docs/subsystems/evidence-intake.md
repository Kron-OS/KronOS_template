# Evidence Intake Subsystem

Covers phases: `UPLOADING → SCANNING → HASHING → RECEIVED`.

## Upload Protocol

- **Primary:** S3 multipart upload via presigned URLs (client uploads directly to MinIO).
- **Fallback:** tus.io / `tusd` for environments where multipart is blocked by proxies.
- The `POST /cases/{id}/evidence` route only mints URLs — it does not receive the file body.
- NGINX `client_max_body_size` cap applies only to the tiny metadata payload, not the 1 GB file.

## Bucket Flow

```
MinIO: quarantine bucket (versioning on, no Object Lock, SSE-KMS ON)
   ↓ AV scan clean
MinIO: evidence bucket (versioning on, Compliance Object Lock, SSE-KMS ON)
```

## File Validation

1. Extension check — blocklist: `.exe .dll .scr .bat .cmd .ps1 .js .vbs .jar`
2. libmagic MIME check
3. Magic-byte allowlist (see `MagicByteValidator` in implementation guidelines §3.3)
4. File size ≤ 1 GB (configurable from `Settings`)

## Scanning (ClamAV)

- ClamAV runs as a **long-lived sidecar** (cold start once; signatures kept hot).
- Triggered by MinIO bucket notification `s3:ObjectCreated:CompleteMultipartUpload` on quarantine.
- Signatures refreshed by `freshclam` every 6 hours.
- Infected → `status=ERROR`, `error_reason="av_infected"`, quarantine object retained.

## Hashing Protocol

1. Client computes rolling SHA-256 during multipart upload.
2. Client sends `sha256` on `POST /evidence/{id}/complete`.
3. Celery task `verify_evidence_hash` re-reads the quarantine object, recomputes SHA-256 server-side.
4. Mismatch → `status=ERROR`, `error_reason="upload_hash_mismatch"`.
5. Match → promote to evidence bucket with Object Lock header, write RFC 3161 TSA token.

SHA-256 is stored as `BYTEA(32)` — not hex. The S3 multipart ETag is never the forensic fingerprint.

## RFC 3161 Timestamp

On the `evidence.hash.verified` transition:
1. POST the SHA-256 digest to the self-hosted Sigstore TSA.
2. Receive a TimeStampToken (TST).
3. Store TST in `evidence.rfc3161_token` (BYTEA).
4. Write `audit_log` action `evidence.tsa.anchored`.

## Evidence FSM

```
UPLOADING → SCANNING → HASHING → RECEIVED → PARSING → INGESTING → COMPLETE
                    ↘          ↘          ↘          ↘
                    ERROR ←←←←←←←←←←←←←←←←←←←←←←←←←←
```

`ERROR` is non-terminal — org-admin can retry from SCANNING (re-scan) or PARSING (re-parse).
`UPLOADING` rows older than 24 h are aborted by a Celery beat job.

## Retention and Legal Hold

- Default retention: 365 days (from `org.retention_days`).
- Object Lock retain-until is set at promotion time.
- Daily `evidence_retention_purge` job: only deletes after Object Lock expires AND `legal_hold = false`.
- Soft-delete: sets `status='PURGED'`, keeps SHA-256 and audit history forever.
- Legal Hold: `PUT /evidence/{id}/legal-hold` — `org-admin` or `case-lead` only, requires `aal2`.
