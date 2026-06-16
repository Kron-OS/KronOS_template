# Part 2 Review — Evidence Intake and Chain of Custody

- **Date:** 2026-06-16
- **Spec section reviewed:** `Project_Specifications.md` §2
- **Tracking issues:** #2 (category), #11 (today's review)
- **Branch:** `claude/zen-cerf-575yj7`

---

## 1. What the spec currently says

The spec proposes:

1. Users upload raw (uncompressed) evidence files **up to ~1 GB** into a case.
2. An **allowlist** of forensic file types (EVTX, .pf, registry hives, CSV logs, …); executables blocked; optional magic-byte check.
3. Files are streamed to **object storage**, a **SHA-256** is computed and stored as the digital fingerprint, plus metadata (uploader, timestamp, case).
4. Original files are **WORM by policy** — the app never modifies them.
5. **Chain-of-custody log** entries on upload, parse, ingest, access (who / when / action / IP).
6. **Status field** per evidence: `UPLOADING` / `RECEIVED` / `PARSING` / `INGESTING` / `COMPLETE` / `ERROR`.
7. **Retention policy** (default 365 days), automated purge, deletions logged.
8. TLS 1.3 for transit, possible AV scan, future parser sandboxing with gVisor, tamper resistance via checksums / signatures.

---

## 2. Work already done in the repo

| Artifact                                | Status                                                                  |
| --------------------------------------- | ----------------------------------------------------------------------- |
| `Project_Specifications.md` §2          | Narrative description only — no API surface, no schema, no FSM diagram  |
| Object-storage configuration            | None                                                                    |
| Upload service / tus server / API       | None                                                                    |
| Hashing / AV / type-detection code      | None                                                                    |
| Audit-log table / chain-of-custody code | Schema sketched in §1 review (`audit_log`) but not implemented          |
| Retention scheduler                     | None                                                                    |
| Tests / CI                              | None                                                                    |

**Conclusion:** §2 is at the "intent / outline" stage. The §1 review already committed to an `audit_log` table; §2 must extend it rather than create a parallel log.

---

## 3. Feasibility research (state of the art, 2026)

### 3.1 Object storage with WORM

- **MinIO** is feature- and API-compatible with **AWS S3 Object Lock** and provides on-prem WORM storage with two retention modes:
  - **Governance** — protects against accidental deletion; privileged users with `s3:BypassGovernanceRetention` can still delete.
  - **Compliance** — cannot be undone within the retention period, **not even by root**.[^minio-objlock][^minio-blog]
- **Legal Hold** is an indefinite WORM flag, independent of the retention timer, useful when a case becomes contested.[^minio-blog]
- Object Lock requires the bucket to be **versioned** and the `ObjectLockConfiguration` to be set; from MinIO `RELEASE.2025-05-20T20-30-00Z` it can also be enabled on pre-existing buckets.[^minio-objlock]
- Forensic/regulatory frameworks (SEC 17a-4, HIPAA, GDPR) explicitly recognise Object Lock Compliance mode as an acceptable WORM control.[^minio-blog]

### 3.2 Resumable / large uploads

- 1 GB through a single HTTP POST is feasible but fragile: any network hiccup re-starts the transfer, and intermediate proxies often cap body size.
- **tus.io** is an open resumable-upload protocol; `tusd` is the reference Go server, supports local disk, GCS and **S3-compatible** back ends (including MinIO), and ships hooks for pre/post-finish that we can use for hashing/AV.[^tus-protocol][^tusd]
- **S3 / MinIO multipart upload with presigned URLs** is the alternative: browser uploads parts directly to MinIO, the backend only signs URLs. Caveat: the S3 multipart **ETag is *not* a SHA-256 of the whole object** — it is a hash of concatenated part-hashes plus the part count.[^minio-multipart][^aws-mpu]
- Boto3's `ChecksumAlgorithm=SHA256` populates per-part SHA-256 and lets the client/server agree on a checksum-of-checksums, but the **whole-file SHA-256 still has to be computed by us** if we want a single forensic fingerprint.[^boto3-checksum]

### 3.3 Streaming SHA-256

- The forensic standard fingerprint is the **SHA-256 of the original byte stream**, computed once at acquisition and re-verified at every custodial transfer.[^nist-iso-compare][^truescreen]
- Practical pattern with tus/MinIO: compute SHA-256 incrementally as bytes arrive (the tus server exposes a `pre-finish` hook with the assembled file); after MinIO finalises the object, **re-read the object server-side and recompute** the SHA-256 to confirm the stored bytes match — this is the moment that closes the chain of custody for the upload.

### 3.4 File-type validation (magic bytes)

- **python-magic** wraps libmagic and exposes `magic.from_file()` / `magic.from_buffer()`; documented best practice is to read at least the first 2048 bytes for accurate identification.[^python-magic]
- Forensic artefacts have stable, well-documented magic numbers we can pin in an allowlist:
  - **EVTX** — `ElfFile\x00` at offset 0 (libyal `libevtx` spec).[^libevtx]
  - **Prefetch (.pf)** — `SCCA` at offset 4, preceded by a 4-byte format version.[^libscca]
  - **Registry hive (REGF)** — `regf` (0x72 0x65 0x67 0x66) at offset 0; `hbin` block markers every 4096 bytes.[^libregf][^msuhanov-regf]
- Magic numbers can still be forged, so we should combine libmagic with a **parser dry-run** for the most security-critical formats (the parser will fail loudly on a crafted artefact long before it produces timeline events).

### 3.5 AV scanning

- **ClamAV** is the de-facto open-source AV; the daemon `clamd` exposes a stream-scan socket and several container images wrap it in a REST API (e.g. `ajilach/clamav-rest` with `/v2/scan`).[^clamav-rest]
- Cold-start of clamd is heavy (signatures loaded into memory), so it must run as a **long-lived sidecar / dedicated container**, not as a per-request Lambda.[^clamav-aws]
- Scan placement options:
  1. **In-stream** during tus pre-finish hook — blocks the upload but the bad file never lands in WORM storage.
  2. **Post-store, pre-PARSING** — the file is already in MinIO but in a quarantine bucket; Celery moves it to the "clean" bucket only after a clean scan. Cleaner for resumable uploads.
- For forensic evidence the second option is preferable: we do not want the AV signature mismatch to lose a 1 GB upload after 20 minutes of streaming.

### 3.6 Chain-of-custody standards

- **ISO/IEC 27037:2012** defines four processes (identification, collection, acquisition, preservation) and three principles: **auditability, repeatability, reproducibility**.[^nist-iso-compare]
- **NIST SP 800-86** emphasises a documented, verifiable, unbroken evidentiary trail and recognises SHA-256 hashing as the standard integrity primitive.[^nist-iso-compare]
- Combined coverage (ISO 27037 + NIST 800-86) is recommended in multi-jurisdictional contexts — exactly Kron-OS's intended scope.

### 3.7 Tamper-evident audit log

- **RFC 3161 Time-Stamp Protocol (TSP)** lets us bind a SHA-256 of an evidence file (or a daily Merkle root of audit-log rows) to a trusted moment in time, via a signed timestamp token. Sigstore's TSA is a production-grade open-source TSA we can self-host.[^rfc3161-metaspike][^sigstore-tsa]
- **Merkle-tree / append-only logs** (Trillian, transparency.dev) are overkill for v1, but the **daily-anchor pattern** (Postgres `audit_log_anchor` row containing SHA-256 root of the day's entries + RFC 3161 token) gives us tamper-evidence with very little machinery and is the natural evolution path.[^trillian][^designgurus-logs]

### 3.8 Retention vs WORM tension

- If we use Object Lock **Compliance** mode with a 365-day retention, **nothing** — including a privileged user — can delete the object before the timer expires. This is the desired forensic property, but it also means our "automatic purge after 365 d" job must wait for Object Lock expiry; it cannot force-delete earlier.
- Practical resolution: align Object Lock retention with the case's retention policy (default 365 d, configurable per case at upload time); the purge Celery beat job runs *after* the lock expires.
- Cases under legal hold get the **Legal Hold** flag set; the purge job must check both `Retention` *and* `LegalHold` before deleting.

---

## 4. Problems identified

### P1. Whole-file SHA-256 is not the same as S3 multipart ETag
The spec says "SHA-256 of the file" without committing to *which* SHA-256 (whole-file vs S3 checksum-of-checksums). For forensic admissibility we **must** record the whole-file SHA-256 of the original bytes, in addition to whatever ETag MinIO produces, and we must re-verify it after the object is stored.

### P2. 1 GB upload protocol is unspecified
A naive `POST /upload` with a 1 GB body will not survive network jitter, will hit reverse-proxy limits (NGINX default `client_max_body_size`), and gives no progress UX. The spec must pick **tus.io** or **S3 multipart with presigned URLs** — they have very different backend shapes.

### P3. WORM mode and Legal Hold are not modelled
"Write-once/read-many by policy" is enforced by application convention only. With MinIO Object Lock available, the platform should rely on **bucket-level Object Lock (Compliance mode)** plus a per-object retention timer, and expose **Legal Hold** as a first-class concept for contested cases.

### P4. Chain-of-custody log overlaps with §1 audit log
§1 already committed to a unified `audit_log` table. §2 risks duplicating that with a parallel "evidence audit trail". We need **one schema**, with an `event_type` field that covers both access decisions (§1) and custody events (§2).

### P5. File-type allowlist is prose only
No concrete mapping of `(extension, libmagic signature, magic bytes)` exists. Without it, the allowlist is impossible to enforce consistently and impossible to audit.

### P6. AV scan placement undecided
Pre-store, post-store, async? The decision affects user-visible upload latency, MinIO bucket layout (quarantine vs clean), and Celery DAG topology.

### P7. Evidence status FSM is a list, not a state machine
The spec lists the six states but never enumerates allowed transitions, retry semantics, or terminal states. Without an FSM, the UI and workers will drift apart.

### P8. Retention purge collides with Object Lock
If retention is enforced by application code only, deletions are not tamper-evident. If retention is enforced by Object Lock Compliance, the app-level purge job must wait for the lock to expire and cannot "delete now to free space" — this trade-off needs explicit acknowledgement.

### P9. No trusted timestamp / signed anchor
§2 mentions "checksums or digital signatures on evidence and logs" but takes no concrete step. RFC 3161 TSP is cheap (Sigstore TSA can be self-hosted) and gives us a non-repudiable acquisition time per evidence file — a forensic standard.

### P10. gVisor sandboxing is referenced but cross-cuts §3 and §5
"In the future consider gVisor" is mentioned in §2, §3, and §5 without a single owner. We should park the gVisor decision in §5 (Security and Compliance) and remove the duplicates.

---

## 5. Plan to reach the objective — detailed

### 5.1 Upload protocol

- **Primary:** S3 multipart upload with **presigned URLs** signed by the backend; browser uploads parts directly to MinIO (`kronos-evidence-{org_alias}-quarantine` bucket). Lowest-latency path, no extra service to run.
- **Resumability:** wrap the browser flow in a small client library that retries individual parts on failure (S3 multipart already supports this); fall back to **tus.io / `tusd`** if a customer hits NAT/proxy issues with multipart.
- **Reverse proxy:** NGINX `client_max_body_size 5g` only on the backend's `POST /evidence` path (which just signs URLs); MinIO is reached directly from the browser.

### 5.2 Object-storage layout (MinIO)

- Buckets per org:
  - `kronos-evidence-{org_alias}-quarantine` — versioning **on**, no Object Lock (AV scan pending).
  - `kronos-evidence-{org_alias}` — versioning **on**, **Object Lock Compliance** mode, default retention = org's `retention_days` (matches §1 `org.retention_days`).
- After a clean AV scan, the backend `CopyObject` from quarantine to evidence bucket with `x-amz-object-lock-mode: COMPLIANCE` and `x-amz-object-lock-retain-until-date: now + retention_days`, then deletes the quarantine version.
- **Legal Hold** is a per-object boolean exposed on `PUT /evidence/{id}/legal-hold` — only `org-admin` or `case-lead` of the case can set/release.

### 5.3 Hashing protocol

1. **Client-side rolling SHA-256** computed during the multipart upload, transmitted to the backend at finalisation time as `X-Kronos-Sha256` on `POST /evidence/{id}/complete`.
2. **Server-side recomputation** in a Celery task `verify_evidence_hash`: stream the just-stored object from MinIO, recompute SHA-256, compare to client-provided hash and to the `ChecksumSHA256` MinIO returns. Mismatch ⇒ status `ERROR`, custody log entry, quarantine bucket retained for forensics.
3. **Store** the verified SHA-256 in `evidence.sha256` (Postgres) and as MinIO user metadata `x-amz-meta-sha256` for redundancy.

### 5.4 File-type validation table (v1)

| Artefact          | Allowed extension(s) | libmagic signature                    | Magic bytes (offset) |
| ----------------- | -------------------- | ------------------------------------- | -------------------- |
| Windows EVTX      | `.evtx`              | `MS Windows Vista Event Log`          | `ElfFile\x00` (0)    |
| Prefetch          | `.pf`                | `data` + parser dry-run               | `SCCA` (4)           |
| Registry hive     | `NTUSER.DAT`, `*.hve`, `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY` | `MS Windows registry file` | `regf` (0) |
| CSV log           | `.csv`               | `CSV text` / `ASCII text`             | n/a (text validation) |
| Browser SQLite    | `.sqlite`, `.db`     | `SQLite 3.x database`                 | `SQLite format 3\x00` (0) |
| JSON log          | `.json`, `.ndjson`   | `JSON data` / `ASCII text`            | n/a                  |
| journald          | `.journal`           | `data` + parser dry-run               | `LPKSHHRH` (0)       |
| EML / MBOX        | `.eml`, `.mbox`      | `news, RFC 822` / `Unix mail`         | n/a                  |

- All other extensions ⇒ `415 Unsupported Media Type` at the `POST /evidence` step.
- Executable extensions (`.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.js`, `.vbs`, `.jar`) are **blocklisted explicitly** even if the user re-extensions them — libmagic catches the PE/ELF/script signatures.

### 5.5 AV scan placement

- **Post-store, pre-promotion** (quarantine bucket scan).
- ClamAV runs as a dedicated container `clamav` exposing the `clamd` stream socket on the internal network; a thin `clamav-rest` sidecar wraps it as `/v2/scan` for convenience. Signatures refreshed via `freshclam` every 6 h.
- Celery task `av_scan_evidence` is triggered by the MinIO **bucket notification** (`s3:ObjectCreated:CompleteMultipartUpload`) on the quarantine bucket. The notification carries the object key, ETag, and size.
- Outcomes:
  - **Clean** ⇒ `verify_evidence_hash` runs, then promote to evidence bucket with Object Lock, status `RECEIVED`.
  - **Infected** ⇒ status `ERROR`, custody entry, quarantine object kept for the org-admin to review.
  - **Scan timeout** ⇒ retry 3× with exponential back-off, then `ERROR`.

### 5.6 Evidence status FSM

```
            ┌──────────────┐
   user ──▶ │  UPLOADING   │   (multipart parts being received)
            └──────┬───────┘
                   │ all parts received + complete-MPU
                   ▼
            ┌──────────────┐
            │  SCANNING    │   (ClamAV)
            └──┬────────┬──┘
       clean  │        │ infected / scan-timeout
              ▼        ▼
       ┌──────────────┐ ┌─────────┐
       │  HASHING     │ │  ERROR  │
       └──────┬───────┘ └─────────┘
              │ hash matches
              ▼
       ┌──────────────┐
       │  RECEIVED    │   (in WORM bucket, custody entry written)
       └──────┬───────┘
              │ §3 dispatcher picks up
              ▼
       ┌──────────────┐
       │   PARSING    │
       └──────┬───────┘
              ▼
       ┌──────────────┐
       │  INGESTING   │
       └──────┬───────┘
              ▼
       ┌──────────────┐
       │  COMPLETE    │
       └──────────────┘
```

- `ERROR` is non-terminal: an org-admin can retry from `ERROR` to either `SCANNING` (re-scan) or `PARSING` (re-parse) depending on which step failed; both transitions are custody-logged.
- `UPLOADING` has a TTL of **24 h** (Celery beat job): orphan multipart uploads are aborted and their parts released to recover storage.

### 5.7 Chain-of-custody schema (extension of §1 `audit_log`)

```sql
-- §1 already created:
-- audit_log (id, ts, org_id, actor_user_id, action, resource_type, resource_id, decision, ip, extra_jsonb)

-- §2 adds these `action` values, no schema change:
--   evidence.upload.start
--   evidence.upload.complete
--   evidence.scan.clean
--   evidence.scan.infected
--   evidence.hash.verified
--   evidence.hash.mismatch
--   evidence.promoted        -- moved to WORM bucket
--   evidence.legal_hold.set
--   evidence.legal_hold.cleared
--   evidence.download
--   evidence.delete
--   evidence.parse.start
--   evidence.parse.success
--   evidence.parse.error
--   evidence.ingest.success
--   evidence.ingest.error

-- New table for evidence metadata itself:
CREATE TABLE evidence (
  id              UUID PRIMARY KEY,
  case_id         UUID NOT NULL REFERENCES case_(id),
  org_id          UUID NOT NULL REFERENCES org(id),
  filename        TEXT NOT NULL,
  size_bytes      BIGINT NOT NULL,
  sha256          BYTEA NOT NULL,
  mime_detected   TEXT NOT NULL,                 -- from libmagic
  artefact_type   TEXT NOT NULL,                 -- enum from §5.4
  status          TEXT NOT NULL CHECK (status IN
                    ('UPLOADING','SCANNING','HASHING','RECEIVED',
                     'PARSING','INGESTING','COMPLETE','ERROR')),
  bucket          TEXT NOT NULL,
  object_key      TEXT NOT NULL,
  object_lock_until TIMESTAMPTZ,                 -- mirrors S3 Object Lock retention
  legal_hold      BOOLEAN NOT NULL DEFAULT false,
  rfc3161_token   BYTEA,                         -- TSA-signed timestamp of sha256
  uploaded_by     UUID NOT NULL REFERENCES app_user(id),
  uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  error_reason    TEXT,
  UNIQUE (org_id, case_id, sha256)               -- dedupe per case
);

CREATE INDEX evidence_case_status_idx ON evidence(case_id, status);
CREATE INDEX evidence_org_uploaded_idx ON evidence(org_id, uploaded_at DESC);
```

- `evidence.sha256` is `BYTEA(32)`; the UNIQUE constraint dedupes accidental re-uploads of the same file within a case.
- Every transition writes one `audit_log` row with the matching `evidence.*` action and references the `evidence.id` in `resource_id`.

### 5.8 Trusted timestamp (RFC 3161)

- Run a self-hosted **Sigstore TSA** (`sigstore/timestamp-authority`) reachable only from the backend.
- On the `evidence.hash.verified` transition, Celery task `tsa_anchor_evidence`:
  1. POSTs the SHA-256 to the TSA → receives a TimeStampToken (TST).
  2. Stores the TST in `evidence.rfc3161_token`.
  3. Writes `audit_log` row `evidence.tsa.anchored`.
- The same TSA is reused in §5.6 for the daily `audit_log_anchor` Merkle root (defined in §1 review).

### 5.9 Retention purge

- Daily Celery beat job `evidence_retention_purge`:
  1. Selects `evidence` rows where `now() > object_lock_until` AND `legal_hold = false`.
  2. Calls `DeleteObject` on MinIO — succeeds because Object Lock has expired.
  3. Soft-deletes the row (sets `status='PURGED'`, keeps the SHA-256 and audit history forever) so we keep the custodial record after the bytes are gone.
  4. Writes `audit_log` row `evidence.delete` with `decision='retention'`.
- OpenSearch ISM rollover policy (§1 review) aligns on the same retention window so the parsed timeline is purged in lock-step.

### 5.10 API boundaries

| Route                                            | Roles allowed                       | Notes |
| ------------------------------------------------ | ----------------------------------- | ----- |
| `POST   /cases/{id}/evidence`                    | `org-admin`, `case-lead`, `analyst` | Creates `evidence` row in `UPLOADING`, returns presigned multipart URLs |
| `POST   /evidence/{id}/complete`                 | uploader                            | Carries client-side SHA-256, triggers SCANNING/HASHING pipeline |
| `GET    /evidence/{id}`                          | members of case                     | Metadata only |
| `GET    /evidence/{id}/download`                 | per matrix (§1)                     | Logs `evidence.download` |
| `PUT    /evidence/{id}/legal-hold`               | `org-admin`, `case-lead`            | Sets/clears `legal_hold` |
| `DELETE /evidence/{id}`                          | `org-admin`, `case-lead`            | Only allowed after `object_lock_until` |

- All routes go through the §1 guard middleware (`org_claim_guard`, `role_guard`) and emit `audit_log` rows.

### 5.11 Incremental milestones

| Milestone | Content | Exit criterion |
| --------- | ------- | -------------- |
| M2.1 | MinIO deployment + 2 buckets per org (quarantine + Object-Lock Compliance) + bucket-notification → Celery | E2E test: upload of a 50 MB file ends up in the WORM bucket with the correct retention timer |
| M2.2 | Presigned multipart upload API + client retry library | E2E test: upload a 1 GB synthetic file over a flaky network, recover all parts |
| M2.3 | `verify_evidence_hash` + custody log entries | Tampering one byte in MinIO causes the verify task to fail and write `evidence.hash.mismatch` |
| M2.4 | libmagic allowlist + magic-byte table from §5.4 + executable blocklist | CI test: each fixture in `tests/fixtures/evidence/*` is correctly accepted/rejected |
| M2.5 | ClamAV sidecar + AV scan pipeline + EICAR test fixture | CI test: EICAR upload ends in `ERROR`, clean upload promotes to WORM bucket |
| M2.6 | RFC 3161 TSA + `rfc3161_token` column + daily anchor anchored | TST verifies with `openssl ts -verify` against the TSA's CA |
| M2.7 | Retention purge Celery beat + Legal Hold endpoint | Time-travel test: set retention to 60 s, observe object purge once expired |

Each milestone lands as its own PR referencing issue #2.

---

## 6. Open questions for the reviewer

1. **Object Lock mode:** lock in **Compliance** (no escape valve, ever) or start with **Governance** (org-admin can `BypassGovernanceRetention` in extremis)?
2. **Per-case retention override:** should a Case Lead be able to *extend* retention past the org default (e.g. for a court-relevant case), or is that an org-admin-only action?
3. **AV engine:** ClamAV is open-source and on-prem-friendly; do any customers require a commercial AV (CrowdStrike, Sophos) for compliance reasons?
4. **TSA:** self-hosted Sigstore TSA is free but the root has to be operated carefully — alternatively pay a commercial TSA per-token. Which posture for v1?
5. **Deduplication scope:** the `UNIQUE (org_id, case_id, sha256)` constraint dedupes within a case. Should we also surface cross-case duplicates (same file uploaded to two cases of the same org)?
6. **Maximum file size:** the spec says ~1 GB; do we want to lift this for disk images (typically 4–500 GB) in v2, or keep raw artefacts only?

---

## 7. Next-day plan

Tomorrow's review should target **Part 3 — Parsing Scope and Timeline Model**. The `evidence` table and the FSM defined here are the prerequisite hand-off point: §3 picks up at the `RECEIVED → PARSING` transition.

---

## References

[^minio-objlock]: [Object Locking and Immutability — MinIO AIStor docs](https://docs.min.io/enterprise/aistor-object-store/administration/object-locking-and-immutability/)
[^minio-blog]: [Object Locking, Versioning, Legal Holds and Modes in MinIO](https://blog.min.io/object-locking-versioning-and-holds-in-minio/)
[^tus-protocol]: [Resumable upload protocol 1.0.x — tus.io](https://tus.io/protocols/resumable-upload)
[^tusd]: [tus/tusd — reference server implementation](https://github.com/tus/tusd)
[^minio-multipart]: [Pre-signed MultiPart Uploads with Minio — vsoch](https://vsoch.github.io/2020/s3-minio-multipart-presigned-upload/)
[^aws-mpu]: [Tutorial: Upload an object through multipart upload and verify its data integrity — AWS docs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/tutorial-s3-mpu-additional-checksums.html)
[^boto3-checksum]: [Boto3 S3 Object.checksum_sha256](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3/object/checksum_sha256.html)
[^python-magic]: [ahupp/python-magic — a python wrapper for libmagic](https://github.com/ahupp/python-magic)
[^libevtx]: [libyal/libevtx — Windows XML Event Log (EVTX) format spec](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc)
[^libscca]: [libyal/libscca — Windows Prefetch File (PF) format spec](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)
[^libregf]: [libyal/libregf — Windows NT Registry File (REGF) format spec](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc)
[^msuhanov-regf]: [msuhanov/regf — Windows registry file format specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)
[^clamav-rest]: [ajilach/clamav-rest — ClamAV with REST API](https://github.com/ajilach/clamav-rest)
[^clamav-aws]: [ClamAV (Anti-Virus) as a REST application on AWS ECS — dev.to](https://dev.to/aws-builders/clamav-anti-virus-as-a-rest-application-on-aws-ecs-1d0e)
[^nist-iso-compare]: [Comparison Study of NIST SP 800-86 and ISO/IEC 27037 — ResearchGate](https://www.researchgate.net/publication/382816264_Comparison_Study_of_NIST_SP_800-86_and_ISOIEC_27037_Standards_as_A_Framework_for_Digital_Forensic_Evidence_Analysis)
[^truescreen]: [Digital Chain of Custody — Truescreen](https://truescreen.io/articles/digital-chain-of-custody-guide/)
[^rfc3161-metaspike]: [Trusted Timestamping (RFC 3161) in Digital Forensics — Metaspike](https://www.metaspike.com/trusted-timestamping-rfc-3161-digital-forensics/)
[^sigstore-tsa]: [sigstore/timestamp-authority — RFC 3161 Timestamp Authority](https://github.com/sigstore/timestamp-authority)
[^trillian]: [Trillian — open-source append-only ledger](https://transparency.dev/)
[^designgurus-logs]: [How to design tamper-evident audit logs — designgurus.io](https://www.designgurus.io/answers/detail/how-do-you-design-tamperevident-audit-logs-merkle-trees-hashing)
