# Project Architecture and Implementation Plan

> **Review log**
> - 2026-04-20 — Part 1 reviewed (see `reviews/Part_1_Review.md`, issues #1 / #7).
>   Key decisions fed back into §1 below: adopt Keycloak 26 **Organizations** rather than Groups-only; commit to an explicit permission matrix; fix the OpenSearch `roles_key` Keycloak-mapper pitfall; plan index rollover to avoid shard explosion.
> - 2026-06-16 — Part 2 reviewed (see `reviews/Part_2_Review.md`, issues #2 / #11).
>   Key decisions fed back into §2 below: presigned S3 multipart upload (tus.io fallback); MinIO **Object Lock Compliance** mode + Legal Hold for true WORM; whole-file SHA-256 verified server-side; libmagic allowlist with a per-artefact magic-byte table; ClamAV post-store quarantine scan; explicit evidence FSM; RFC 3161 timestamping; chain-of-custody reuses §1 `audit_log`.
> - 2026-06-16 — Part 3 reviewed (see `reviews/Part_3_Review.md`, issues #3 / #13).
>   Key decisions fed back into §3 below: ECS-based timeline schema with a `kronos.*` provenance block (case/evidence/sha256); **intermediate ingester** between Plaso and OpenSearch instead of `psort -o opensearch` direct write; per-artefact parser slots (`evtx-rs` fast path, Plaso sandbox container, custom text-log parsers); explicit Celery DAG with deterministic OpenSearch `_id`s; line-aware splitter for text logs only — binary forensic formats are parsed whole; UTC + DST-fold handling; SRUM and other heavy parsers isolated on a memory-capped queue.
> - 2026-06-16 — Part 4 reviewed (see `reviews/Part_4_Review.md`, issues #4 / #15).
>   Key decisions fed back into §4 below: SPA = React 19 + Vite + TanStack Router + Keycloak-js (PKCE); resumable upload via **Uppy** (S3-multipart primary, tus.io fallback) with client-side magic-byte pre-check; OS Dashboards embedded in iframe with mandatory CSP `frame-ancestors` and SSO via the existing Keycloak realm; **one OS Dashboards tenant per org** (not per case) — per-case scoping via locked URL filter on `kronos.case_id`; real-time status via **SSE** authenticated by a short-lived one-shot ticket, polling fallback after 10 s; explicit status-pill mapping per §2 FSM; explicit error catalogue keyed on `evidence.error_reason`; v1 collaboration = independent analysis only (CRDT/shared annotations deferred to v2); Harfanglab-style custom graph view deferred to v2.
> - 2026-06-16 — Part 5 reviewed (see `reviews/Part_5_Review.md`, issues #5 / #17).
>   Key decisions fed back into §5 below: explicit four-zone trust boundary (DMZ / App / Data / Observability) with mTLS on every internal hop; internal CA via **`step-ca`** (or Vault PKI) issuing 24 h workload certs, TLS 1.3 only, no self-signed in v1; MinIO **SSE-KMS** via **KES** backed by **HashiCorp Vault / OpenBao** mandatory from bucket creation (at-rest encryption is no longer deferred); parser sandboxing split — **gVisor** for the fast Celery slot, **Firecracker microVM** for the Plaso slot, both with `network=none`; **tamper-evident audit log** = per-row hash chain + daily Merkle root anchored by the §2 RFC 3161 TSA + standalone `kronos-attest verify` CLI; SIEM = **Wazuh** on the existing OpenSearch cluster (separate `wazuh-alerts-*` indices) with a write-once cold archive bucket, pinned ≥ Wazuh 5.1; **Falco** DaemonSet for runtime detection; hardened **Chainguard / Wolfi** base images with Trivy CI gate and Cosign-signed SBOMs; ISO 27001 mapping migrated to the **2022 revision** with **A.5.28 Collection of Evidence** as the cornerstone control; MinIO active-active replication + erasure coding + Vault snapshots for BC/DR (RPO 5 min / RTO 15 min); explicit incident-response runbook aligned with NIST SP 800-86.
> - 2026-06-16 — Part 6 reviewed (see `reviews/Part_6_Review.md`, issues #6 / #19).
>   Key decisions fed back into §6 below: re-cast §6 as the **integration contract** that consumes §1/§4/§5 rather than restating them; client manifest pins three confidential clients (`kronos-backend`, `opensearch-dashboards`, `kronos-attest`) + one public PKCE SPA client (`kronos-spa`), no client secrets in the browser; canonical token claim shape locked (`organization.<alias>.id` map, top-level multivalued `roles`, `acr` for step-up, `preferred_username` for audit); OpenSearch Security OIDC auth domain pinned `order: 0` / `challenge: false`, `subject_key: preferred_username`, `roles_key: roles`, with the normative `config.yml` / `roles_mapping.yml` / `opensearch_dashboards.yml` snippets committed to the review; backend JWT pipeline = JWKS cache + `kid` re-fetch on miss + strict `iss`/`aud`/`exp`/`alg` (never `none`) + ACR enforcement (RFC 9470); refresh tokens transported as **HttpOnly + Secure + SameSite=Strict** cookies via a backend `/auth/refresh` proxy — `keycloak-js` localStorage default rejected; backend service account scoped by **Keycloak 26.7 FGAP V2 on Organizations** (Authorization-Services policy as 26.6 interim); federation via Keycloak **identity brokering** (LDAP/AD `READ_ONLY`, SAML, upstream OIDC) with first-login Org-assignment Required Action until 26.7 IdP-mapper auto-assignment; **step-up authentication** (`acr=aal2`) required for `org-admin`, `evidence.delete`, `legal_hold.{set,cleared}` — WebAuthn passkey preferred, TOTP fallback; OIDC **backchannel logout** wired for backend + Dashboards (no dots in IdP aliases per #42209); Keycloak realm event-listener → Wazuh sink with a custom Kron-OS decoder/rule pack; canonical end-to-end **session-lifetime table** (access 15 min / refresh 24 h / SSO idle 2 h / SSO max 24 h) committed to §6.

## 1. Users, Teams, and Access Control

> Status: **reviewed 2026-04-20.** Narrative below has been updated; detailed design, permission matrix, and milestones live in `reviews/Part_1_Review.md`.

Multi-Tenancy and Roles:
- The system will be multi-tenant, allowing data segregation by team/organization.
- Each user belongs to a team, and their access is restricted to that team’s cases and data.
- We will implement Role-Based Access Control (RBAC), meaning user roles are scoped to their organization.
- For example, a user could be an Analyst in one team but have no access to another team’s data – the permissions are isolated per tenant. This avoids any cross-tenant data leakage by ensuring each organization’s environment is isolated.

Defined User Roles: We will define roles to mirror typical usage scenarios:
- Org Admin: Can manage the organization (invite users, etc.) and access all cases and files in their org.
- Case Lead: Owner/manager of one or more cases. They can see all files and results for cases they lead.
- Analyst: Can view and work on cases they are assigned to.
- Read-Only: Can view cases/data (if permitted) but cannot make changes. For external user or auditor.

These roles will be implemented in the IdProvider (Keycloak) and enforced in the application. A multi-tenant RBAC model will let us assign roles per tenant instead of globally. In our current plan, a user will likely belong to only one org (migration path for multi-org users is tracked in the Part 1 review, §5.2).

Tenant model (**decision 2026-04-20**):
- Use a **single Keycloak realm** and adopt the first-class **Organizations** feature (Keycloak ≥ 26) instead of modelling tenants only through Groups.
- The `organization` client scope is requested on every login, so each access token carries an `organization` claim (id + alias) that acts as the authoritative `org_id` throughout the platform.
- Groups remain available for secondary grouping inside an org, but they are not the tenancy boundary.
- Realm-per-tenant is rejected for v1 because of Keycloak's documented performance degradation beyond ~100 realms and the duplicated client/flow/theme configuration.

Data Isolation:
- All data objects (cases, evidence, events) will carry a Tenant/Org ID attribute. The backend will always check this against the authenticated user’s org, via a guard middleware that also prepares future Postgres Row-Level Security.
- This guarantees that even if a request is made for an object from another org, it will be denied.
- OpenSearch indices follow the naming convention `kronos-{org_alias}-case-{case_id}-{yyyymm}` fronted by a per-case alias and an ISM rollover policy (size 30 GB / 30 days) to keep shard count bounded (≤ 1 000 shards per 16 GB of heap, per OpenSearch guidance).
- OpenSearch roles (`kronos_org_admin`, `kronos_case_lead`, `kronos_analyst`, `kronos_read_only`) are defined in `roles.yml` and mapped from the JWT using both the flat `roles` claim **and** the `organization.alias` claim, with Document-Level Security on `tenant_id` as defence in depth.

Team Management:
- Initially, each user will be tied to one team (we won’t support multi-org users at first).
- We will provide an interface for an Org Admin to create a team (organization) and invite or add users to it.
- This is done through our backend, which calls Keycloak’s Admin REST API using a service account scoped via **Admin Fine Grained Permissions** to exactly the Organization(s) the caller administers — the backend is never granted realm-wide admin.
- Once a user is part of a team, all cases they create or access will be tagged with that team.

SSO Integration for Multi-Tenancy:
- By leveraging Keycloak, users authenticate through a single login page, and upon success the issued token includes their organization membership (via the standard `organization` scope) and roles.
- A custom client scope `kronos-roles` contains a **Realm-Role mapper with "Multivalued" enabled** that flattens roles to a top-level `roles` claim. This is mandatory because OpenSearch Security's `roles_key` does not walk the default nested `realm_access.roles` path.
- Access-token lifespan is tuned to **15 min**, with refresh-token rotation and reuse detection; SSO session max stays at 24 h. (Previous proposal of 12–24 h access tokens is abandoned for security reasons.)

Org Administration:
- We will create a special section in the UI for Org Admins where they can manage users.
- The backend applies the permission matrix below before calling Keycloak.

Authoritative permission matrix (v1):

| Verb / Resource          | org-admin | case-lead (of case) | analyst (member) | read-only (member) |
| ------------------------ | :-------: | :-----------------: | :--------------: | :----------------: |
| Create case              |     ✔     |          ✔          |         ✘        |          ✘         |
| Assign members           |     ✔     |          ✔          |         ✘        |          ✘         |
| Upload evidence          |     ✔     |          ✔          |         ✔        |          ✘         |
| Read evidence metadata   |     ✔     |          ✔          |         ✔        |          ✔         |
| Download original file   |     ✔     |          ✔          |     ✔ (logged)   |      ✘ (v1)        |
| Search timeline (OS)     |     ✔     |          ✔          |         ✔        |          ✔         |
| Delete case/evidence     |     ✔     |          ✔          |         ✘        |          ✘         |
| Manage org users         |     ✔     |          ✘          |         ✘        |          ✘         |
| View audit log           |     ✔     |        ✔ (own)      |         ✘        |          ✘         |

Open questions (must be resolved before starting §1 implementation): see `reviews/Part_1_Review.md` §6.

By structuring users by organization and role, we satisfy the need to keep data accessible only to the right people. In summary, multi-tenant RBAC will be at the core of access control, with each tenant’s data siloed and roles defined per tenant to limit permissions appropriately.

## 2. Evidence Intake and Chain of Custody

> Status: **reviewed 2026-06-16.** Narrative below has been updated; detailed design, file-type allowlist, evidence FSM and milestones live in `reviews/Part_2_Review.md`.

Evidence Upload Process:
- Users upload evidence files to a case via the web app.
- Raw (uncompressed) files up to **~1 GB** each are accepted in v1.
- Accepted formats are forensic artefacts in their original binary form (EVTX, Prefetch, registry hives, browser SQLite, CSV/JSON/NDJSON logs, journald, EML/MBOX). Executables (`.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.js`, `.vbs`, `.jar`) are blocklisted.
- The allowlist is enforced by **both** extension *and* libmagic / magic-byte signature (see the file-type table in `reviews/Part_2_Review.md` §5.4); a mismatch returns `415 Unsupported Media Type` before any bytes hit storage.

Upload protocol (**decision 2026-06-16**):
- **Primary path:** S3 multipart upload via **presigned URLs**. The backend creates an `evidence` row in status `UPLOADING` and returns the presigned URLs; the browser uploads parts directly to MinIO. Per-part retry recovers from network jitter.
- **Fallback:** `tusd` (tus.io protocol) for environments where multipart-with-presigned-URLs is blocked by intermediate proxies.
- The backend's `POST /evidence` route only mints URLs, so the NGINX body-size limit applies to a tiny metadata payload — not to the 1 GB file.

Storage and Hashing (**decision 2026-06-16**):
- Files land first in a per-org **quarantine bucket** (`kronos-evidence-{org_alias}-quarantine`, versioning on, no Object Lock).
- After AV scan + hash verification, the object is `CopyObject`-ed into the per-org **evidence bucket** (`kronos-evidence-{org_alias}`, versioning on, **MinIO Object Lock in Compliance mode**, retain-until = `now() + retention_days`). The quarantine version is then deleted.
- **Whole-file SHA-256** is the forensic fingerprint. The S3 multipart ETag is *not* a SHA-256 of the file — it is a hash of the part-checksums — so we compute the SHA-256 ourselves and store it in `evidence.sha256` plus as MinIO user metadata `x-amz-meta-sha256`.
- Hash protocol: client streams a rolling SHA-256 and sends it on `POST /evidence/{id}/complete`; Celery task `verify_evidence_hash` re-reads the stored object and confirms the value before promotion. Mismatch ⇒ status `ERROR`, custody entry, quarantine retained for investigation.
- WORM is enforced at the storage layer (Object Lock Compliance), **not** by application convention; even the root account cannot delete before the lock expires.
- **Legal Hold** is exposed as a first-class concept (`PUT /evidence/{id}/legal-hold`, `org-admin` / `case-lead` of the case only). A legal-held object cannot be purged regardless of retention.

Antivirus scan (**decision 2026-06-16**):
- **ClamAV (`clamd`)** runs as a dedicated long-lived sidecar with a thin REST wrapper (`/v2/scan`); `freshclam` refreshes signatures every 6 h.
- Scan is **post-store / pre-promotion**, triggered by the MinIO `s3:ObjectCreated:CompleteMultipartUpload` notification on the quarantine bucket — no UI latency cost, no risk of losing a 1 GB upload to a signature mismatch mid-stream.
- Infected ⇒ status `ERROR`, custody entry `evidence.scan.infected`, quarantine object retained for org-admin review.

Chain-of-Custody Logging (**decision 2026-06-16**):
- **Reuses the unified `audit_log` table defined in §1 review** — one canonical log for access decisions and custody events. New `action` values: `evidence.upload.start|complete`, `evidence.scan.clean|infected`, `evidence.hash.verified|mismatch`, `evidence.promoted`, `evidence.legal_hold.set|cleared`, `evidence.download`, `evidence.delete`, `evidence.parse.start|success|error`, `evidence.ingest.success|error`, `evidence.tsa.anchored`.
- Each entry carries `who / when / action / resource / decision / ip` and references `evidence.id` via `resource_id`.

Trusted Timestamping (**decision 2026-06-16**):
- A self-hosted **Sigstore RFC 3161 TSA** is reachable only from the backend.
- On the `evidence.hash.verified` transition, the SHA-256 is timestamped and the TimeStampToken stored in `evidence.rfc3161_token` — non-repudiable proof of acquisition time, aligned with the ISO/IEC 27037 + NIST SP 800-86 chain-of-custody standards.
- The same TSA anchors the daily Merkle root of `audit_log` rows defined in §1 review.

Evidence status FSM (**decision 2026-06-16**):
- States: `UPLOADING` → `SCANNING` → `HASHING` → `RECEIVED` → `PARSING` → `INGESTING` → `COMPLETE`. `ERROR` is reachable from `SCANNING`, `HASHING`, `PARSING`, `INGESTING` and is non-terminal (org-admin can retry).
- Orphan `UPLOADING` rows older than 24 h are aborted by a Celery beat job, releasing pending multipart parts.

Retention Period (**decision 2026-06-16**):
- Default 365 days, configurable per case (override stored on the case row, capped by org policy).
- The Object Lock retain-until date is set at promotion time. The daily `evidence_retention_purge` Celery beat job deletes objects only after Object Lock has expired *and* `legal_hold = false`; soft-deletes the row (`status='PURGED'`) so the custodial record survives indefinitely.
- OpenSearch ISM rollover (§1) aligns on the same window so timeline data is purged in lock-step.

Security Measures for Intake:
- All uploads use HTTPS (TLS 1.3). The presigned URLs are time-limited (15 min) and bound to the uploader's IP where the LB supports it.
- File type is verified by libmagic *and* a per-artefact magic-byte signature (table in `reviews/Part_2_Review.md` §5.4); the executable blocklist is enforced even when the user re-extensions the file.
- Parser sandboxing (gVisor / Firecracker) is tracked under §5 (Security and Compliance) and not duplicated here.

Authoritative `evidence` schema (v1, summary):

| Column            | Type           | Notes                                                                 |
| ----------------- | -------------- | --------------------------------------------------------------------- |
| id                | UUID PK        |                                                                       |
| case_id           | UUID FK        | references `case_(id)`                                                |
| org_id            | UUID FK        | references `org(id)` (defence in depth for §1 RLS)                    |
| filename          | TEXT           |                                                                       |
| size_bytes        | BIGINT         |                                                                       |
| sha256            | BYTEA(32)      | whole-file SHA-256, unique per `(org_id, case_id, sha256)`            |
| mime_detected     | TEXT           | from libmagic                                                         |
| artefact_type     | TEXT           | enum from §5.4 allowlist                                              |
| status            | TEXT           | FSM enum                                                              |
| bucket / object_key | TEXT         | MinIO location                                                        |
| object_lock_until | TIMESTAMPTZ   | mirrors S3 Object Lock retention                                      |
| legal_hold        | BOOLEAN        | default false                                                         |
| rfc3161_token     | BYTEA          | TSA-signed timestamp of `sha256`                                      |
| uploaded_by       | UUID FK        | references `app_user(id)`                                             |
| uploaded_at       | TIMESTAMPTZ    | default `now()`                                                       |
| error_reason      | TEXT           | populated when `status='ERROR'`                                       |

Open questions (must be resolved before starting §2 implementation): see `reviews/Part_2_Review.md` §6.

## 3. Parsing Scope and Timeline Model

> Status: **reviewed 2026-06-16.** Narrative below has been updated; parser-coverage matrix, ECS-based event schema, Celery DAG, and milestones live in `reviews/Part_3_Review.md`.

Supported artefact types (v1):
- Windows Event Logs (EVTX), Prefetch (.pf), Windows Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, etc.), SRUM, Shimcache, Amcache.
- Browser history SQLite databases (Chrome, Firefox), EML / MBOX.
- Linux journald and syslog; Apache and Nginx access/error logs.
- Cloud audit logs: AWS CloudTrail, GCP audit logs, Azure activity logs (custom text parsers in v1).
- Generic CSV / JSON / NDJSON timeline-shaped logs.
- The complete `(artefact, parser slot, Plaso parser name, notes)` matrix lives in `reviews/Part_3_Review.md` §5.8.

Parser strategy (**decision 2026-06-16**):
- A **dispatcher** maps `evidence.artefact_type` to one of three parser slots:
  - `evtx-rs` (Rust + Python bindings) — fast path for EVTX, on the order of 650–1600× faster than `python-evtx` with multi-threading; Plaso is the fallback for crafted/corrupt records.
  - **Plaso (log2timeline)** runs inside a dedicated `kronos/plaso` container with no network egress and a 2 GB memory cap (4 GB for the SRUM "heavy" queue). Used for Prefetch, REGF, SRUM, Shimcache, Amcache, SQLite, journald, syslog, EML/MBOX.
  - Custom text-log parsers for CSV / NDJSON / Apache / Nginx / CloudTrail / GCP / Azure (no Plaso preset exists for these, and they need ECS-aligned field mappings).
- Plaso's automatic format detection (`pysigscan`) is used to confirm the dispatcher's choice before parsing starts.
- Parser presets (`win_gen`, `linux`, `webhist`, …) scope the work; we never run Plaso with the default "everything" preset.

OpenSearch output path (**decision 2026-06-16**):
- We do **not** use `psort -o opensearch` direct write. Instead Plaso writes JSONL (`psort -o json_line --output-time-zone UTC`) to a tmpfs file, and a Kronos **ingester worker** reads it, normalises into ECS, adds the `kronos.*` provenance block, and bulk-indexes via `opensearch-py` with deterministic `_id`s.
- This preserves the chain of custody (every event carries `kronos.evidence_id` and `kronos.evidence_sha256`) and lets us emit ECS-aligned fields that OpenSearch Dashboards understands out of the box.

Timeline event schema (**decision 2026-06-16**):
- Aligned with the **Elastic Common Schema (ECS)** — `@timestamp` (UTC, ISO-8601 with `Z`), `event.{kind,category,action,module,dataset,original,timezone}`, `host.*`, `user.*`, `process.*`, `file.*`.
- Plus a `kronos.*` provenance/extension block: `tenant_id`, `org_alias`, `case_id`, `evidence_id`, `evidence_sha256`, `tz_fold`, `parser_version`, `ingest_id`. Mandatory on every event.
- `event.original` (raw record) capped at 32 KB; oversized originals spill to MinIO and are referenced via `kronos.original_object_key`.
- Index template that backs `kronos-{org_alias}-case-{case_id}-{yyyymm}` enforces this mapping.

Celery DAG (**decision 2026-06-16**):

```
chain(
   dispatch_parse,                 // status → PARSING
   parse_artefact,                 // Plaso / evtx-rs / text parser → JSONL
   chord(
       group(index_chunk x N),     // status → INGESTING on first chunk
       finalize_evidence           // count check → status COMPLETE
   )
)
```

- Queues: `q.parse.fast` (evtx-rs, text parsers), `q.parse.plaso` (Plaso sandbox), `q.parse.plaso.heavy` (SRUM with 4 GB cgroup), `q.index` (OpenSearch bulk).
- **Idempotent OpenSearch ingestion:** `_id = sha1(evidence_id + ":" + parser + ":" + record_index)`. Retried tasks upsert instead of duplicating.
- **Retry policy:** transient errors (OpenSearch 5xx, MinIO timeouts, container start failure) retry up to 5× with exponential back-off 30 s → 8 min ± jitter. Deterministic errors (parser exception, OOM, format mismatch) go straight to `ERROR` — no retry.
- **Orphan sweeper:** beat job aborts parse tasks running > 6 h.

Large-file handling (**decision 2026-06-16**):
- **Text logs only** (CSV, NDJSON, syslog, Apache, Nginx, CloudTrail/GCP/Azure JSON) are split into ~500 k-line chunks when `line_count > 1 000 000`. Chunk boundaries snap to the next `\n`; the CSV header is re-emitted on every chunk so each `index_chunk` task is self-contained.
- **Binary forensic artefacts** (EVTX, REGF, .pf, SQLite, SRUM, journald) are parsed whole — their internal state (B-trees, chunks, transaction logs) makes mid-file splits incorrect. Parallelism is across files, not within one binary file.
- Plaso already parallelises across files inside a single parse task via its task-based multi-processing; Celery parallelises across evidence items.

UTC and DST-fold handling (**decision 2026-06-16**):
- Every event stores `@timestamp` in UTC with the `Z` suffix.
- When the parser knows the source timezone it populates `event.timezone` (IANA name, e.g. `Europe/Paris`).
- Ambiguous local times (DST fall-back) are resolved with `dateutil.tz.datetime_ambiguous()` / `datetime_exists()` and `fold` semantics (PEP-495). When ambiguity cannot be resolved from artefact context, both candidates are stored (`@timestamp` = early, `kronos.alt_timestamp` = late, `kronos.tz_fold = -1`) and Dashboards surfaces a warning badge. `pytz` is **not** used (deprecated semantics).

Status transitions:
- §2 → §3 entry: `RECEIVED → PARSING` triggered by `dispatch_parse`.
- §3 → §4 exit: `INGESTING → COMPLETE` triggered by `finalize_evidence` once `indexed_docs == parsed_records`. Mismatch ⇒ `ERROR` with `error_reason='ingest_count_mismatch'`. All transitions write to the unified `audit_log` (§1/§2 vocabulary).

Open questions (must be resolved before starting §3 implementation): see `reviews/Part_3_Review.md` §6.

## 4. Workflows and User Experience

> Status: **reviewed 2026-06-16.** Narrative below has been updated; detailed design, route map, component contracts, error catalogue and milestones live in `reviews/Part_4_Review.md`.

SPA stack (**decision 2026-06-16**):
- **React 19 + TypeScript + Vite** with TanStack Router (type-safe routes) and TanStack Query (server cache). UI built with Tailwind v4 + shadcn/ui.
- **Auth:** `keycloak-js` v26 with PKCE. Access token kept in memory; refresh token in an HTTP-only cookie; silent refresh via Keycloak iframe. Routes are protected at the router level using the §1 permission matrix.
- State for transient UI lives in a thin Zustand store; no Redux.

Case Lifecycle:
- The UX is built around cases. A Case is the investigation to which evidence files are attached.
- An Org Admin or Case Lead creates a new case (name, description, reference). On creation a Celery task `provision_dashboards_index_pattern` upserts the OS Dashboards index pattern `kronos-{org_alias}-case-{case_id}-*` and a default Discover view inside the org tenant.
- Team members assigned to the case (Case Lead, Analysts) can then upload evidence via an "Add Evidence" drawer. The evidence list shows filename, size, SHA-256 (truncated, click-to-copy), uploader, uploaded_at, status pill, and progress.

Resumable upload UX (**decision 2026-06-16**):
- **Uppy** is the uploader component, configured with two plugins: `@uppy/aws-s3-multipart` (primary path, talks to the §2 `POST /evidence` presigned-URL endpoints) and `@uppy/tus` (fallback path against tusd).
- Client-side allowlist pre-check (extension + magic bytes via the `file-type` npm package) **before** requesting upload URLs — saves a round-trip on obviously-wrong files. Server-side validation per §2 remains the authority.
- Per-chunk progress drives the row's progress bar via Uppy's `upload-progress` event. On `complete`, the SPA optimistically flips the row to `SCANNING`; the SSE channel reconciles transitions thereafter.

Evidence processing flow:
- The UI surfaces explicit states from the §2 FSM with colour-coded pills and progress:

  | FSM state    | UI label                | Color                     | Progress                                                     |
  | ------------ | ----------------------- | ------------------------- | ------------------------------------------------------------ |
  | `UPLOADING`  | "Uploading"             | slate                     | Uppy per-chunk bytes percent                                 |
  | `SCANNING`   | "Scanning (AV)"         | indigo (indeterminate)    | indeterminate                                                |
  | `HASHING`    | "Verifying hash"        | indigo (indeterminate)    | indeterminate                                                |
  | `RECEIVED`   | "Queued for parsing"    | blue                      | none                                                         |
  | `PARSING`    | "Parsing"               | amber                     | `parsed_bytes / total_bytes` when text, else indeterminate   |
  | `INGESTING`  | "Ingesting"             | amber                     | `indexed_docs / parsed_records` when known                   |
  | `COMPLETE`   | "Ready"                 | emerald                   | full                                                         |
  | `ERROR`      | "Error" + reason chip   | red                       | retry button if FSM and `error_reason` allow                 |
  | `PURGED`     | "Purged (retention)"    | slate (disabled)          | n/a                                                          |

- For large files, the user can leave the page; processing continues in background and the row updates when they return.

Real-time status channel (**decision 2026-06-16**):
- **Server-Sent Events** (SSE) is the primary channel — unidirectional server → client, survives corporate proxies that strip the WebSocket `Upgrade` header. Endpoint: `GET /sse/cases/{caseId}/evidence?ticket={shortLivedTicket}`.
- **Auth via short-lived ticket** (not Bearer JWT) because the W3C `EventSource` API does not accept custom headers. SPA calls `POST /sse/ticket` (Bearer-authenticated) and receives `{ticket, expires_in: 60}` bound to `(user_id, org_id, case_id)`. The ticket is single-use.
- **Polling fallback** if `EventSource` does not reach `OPEN` within 10 s: `GET /cases/{caseId}/evidence` every 5 s. Same UI surface, slower transitions.
- Event payloads:
  ```jsonc
  // evt: status
  {"evidence_id":"…","status":"PARSING","progress":{"kind":"bytes","done":314572800,"total":1073741824}}
  // evt: error
  {"evidence_id":"…","reason_code":"parser_oom","retryable":true}
  ```

Timeline analysis — OpenSearch Dashboards (**decision 2026-06-16**):
- Timeline analysis is delivered by **OpenSearch Dashboards embedded in an iframe** inside the SPA at `/cases/{caseId}/timeline`. No bespoke timeline UI in v1.
- **Tenant strategy:** one Dashboards tenant per org (`kronos-{org_alias}`), **not** one per case. Saved searches, Lens visualisations, and dashboards live in the org tenant; per-case scoping is enforced by a locked URL filter on `kronos.case_id` (plus document-level security on the same field at the OS Security layer).
- **SSO handoff:** Dashboards is configured as an OIDC RP against the same Keycloak realm (cf. `cht42/opensearch-keycloak`); because the user already holds an SSO session cookie from the SPA login, the OIDC dance completes silently — no second password prompt. The OS Security `openid` auth domain MUST be the **first** domain in `config.yml`; `roles_key: roles` matches the flat claim from §1; `subject_key: preferred_username`.
- **Iframe URL template:**
  ```
  https://dashboards.kronos.example/app/data-explorer/discover#/?
    embed=true&show-top-menu=false&show-query-input=true&show-time-filter=true
    &_g=(filters:!((meta:(disabled:!f,key:kronos.case_id),
                    query:(match_phrase:(kronos.case_id:'{caseId}'))))),
        time:(from:now-30d,to:now))
    &_a=(index:'{indexPatternId}',interval:auto,…)
  ```
- **Mandatory reverse-proxy hardening** (NGINX, before day one):
  - `Content-Security-Policy: frame-ancestors 'self' https://app.kronos.example` — OS Dashboards ships with no `X-Frame-Options` / no `frame-ancestors` (clickjacking RFC #5639 still open), so we add it ourselves.
  - `X-Frame-Options: SAMEORIGIN` kept as defence-in-depth for older browsers.
  - When Dashboards is on a different sub-domain, rewrite `Set-Cookie` to add `Partitioned; SameSite=None; Secure` (CHIPS) — required for Chrome 130+ third-party-cookie phase-out. Preferred path is to serve Dashboards under the **same** parent domain (`app.kronos.example/dashboards/`) and avoid CHIPS entirely.

Custom OpenSearch view (Harfanglab-style):
- Explicitly **v2** scope. v1 ships OS Dashboards Discover + a Kron-OS Lens preset (auth events, process-tree summary, top-N hosts/users). A React Flow / D3 process-graph view is deferred.

User interface views (v1):
- **Cases List** (`/cases`) — org-scoped list of cases the user can access; create-new button gated by §1 permission matrix (org-admin or case-lead).
- **Case Detail** (`/cases/{caseId}`) — tabs:
  - *Evidence* (default): list with status pills, hover actions (download, legal-hold toggle, delete, retry) gated by RBAC.
  - *Timeline*: OS Dashboards iframe scoped to this case.
  - *Audit log*: paginated `audit_log` rows filtered to this case (org-admin / case-lead only, per §1 matrix).
  - *Settings*: retention override (capped by org policy), members management.
- **Evidence Detail drawer** — chain-of-custody, hash, timestamps, error detail (when applicable), per-state audit entries.
- **Org Admin** (`/admin/org`) — users, roles, retention defaults, legal-hold overrides.

Collaboration (**decision 2026-06-16**):
- v1 = **independent analysis only.** Two analysts open the same case in their own iframes; each has their own URL/filter state; OS Dashboards already handles transient per-user state. A 30 s polling refresh on the evidence list keeps it current.
- True co-presence (shared cursors, live tags, "Alice tagged event X") needs a CRDT backend (Yjs + Hocuspocus/Liveblocks). **Deferred to v2** — Timesketch's annotation/story model is the north star.

Error UX (**decision 2026-06-16**):
- Authoritative error catalogue keyed on `evidence.error_reason`:

  | `error_reason`                  | UI title                  | Hint                                                                       | Retry? |
  | ------------------------------- | ------------------------- | -------------------------------------------------------------------------- | :----: |
  | `upload_hash_mismatch`          | Hash mismatch             | Try uploading again — the file may have been corrupted in transit.         |   ✔    |
  | `av_infected`                   | Antivirus blocked         | The file matched a malware signature. Contact your org admin.              |   ✘    |
  | `unsupported_format`            | Unsupported file type     | Allowed formats: EVTX, Prefetch, REGF, SRUM, …                             |   ✘    |
  | `parser_oom`                    | Parser ran out of memory  | Use the "heavy" queue or split the artefact.                               |   ✔    |
  | `parser_format_error`           | File could not be parsed  | The file may be corrupted. Re-export from the source machine.              |   ✔    |
  | `ingest_count_mismatch`         | Ingest verification failed| Auto-retried; if it persists, contact support with the diagnostic ID.      |   ✔    |
  | `tsa_unreachable`               | Timestamp authority down  | Custody timestamp will be retried automatically.                           |  auto  |

- Every error row exposes an opaque **diagnostic ID** (= `audit_log.id` of the failing transition). Support reads the audit row for the technical detail; the analyst never sees a stack trace.
- Retry is offered only when `error_reason` is retryable **and** the FSM permits it (per §2). Read-only users never see Retry.

Status transitions hand-off:
- §3 → §4 entry: `COMPLETE` makes the *Timeline* tab clickable. Until then it shows "Indexing in progress…" with a count of completed evidence vs total.
- §4 owns: evidence list rendering, status-pill rendering, SSE channel, upload UX, OS Dashboards embed; consumes §1 (auth, RBAC), §2 (evidence FSM + upload protocol), §3 (event index naming, ECS schema).

Open questions (must be resolved before starting §4 implementation): see `reviews/Part_4_Review.md` §6.


## 5. Security and Compliance

> Status: **reviewed 2026-06-16.** Narrative below has been updated; trust-boundary diagram, ISO 27001:2022 control matrix, parser sandbox decision, tamper-evidence verifier design, and milestones live in `reviews/Part_5_Review.md`.

Trust-boundary model (**decision 2026-06-16**):
- Four zones: **DMZ** (NGINX edge, browser-facing TLS 1.3), **App** (backend API, Keycloak, Celery brokers/workers), **Data** (Postgres, MinIO, OpenSearch, Sigstore RFC 3161 TSA, Vault/KES), **Observability** (Wazuh server/dashboard, Falco aggregator, cold SIEM archive bucket).
- Data zone is unreachable from anything other than the App zone. Observability zone reads from App and Data over a dedicated read-only audit identity.
- Every internal hop is mTLS-authenticated; SPIFFE-style service identities (`spiffe://kronos.example/<service>`) are issued by the internal CA and verified on both ends.

Data residency and retention:
- All evidence stays on the designated on-prem MinIO cluster. Default retention 365 days (configurable per case, capped by org policy — see §2).

Transport security (**decision 2026-06-16**):
- **TLS 1.3 only**, every hop, internal and external. No TLS 1.2 fallback.
- **Internal CA:** `step-ca` deployed HA (or Vault PKI if Vault is already in for SSE-KMS — final choice is an open question, see review §6). Workload certificates are **24 h max** and auto-renewed via ACME (`cert-manager` `ClusterIssuer` on Kubernetes, `step` agent otherwise). "Self-signed initially" is rejected because it trains operators to ignore TLS errors.
- Edge (browser-facing) TLS uses Let's Encrypt or the org's commercial CA; the internal CA stays internal.

At-rest encryption (**decision 2026-06-16**):
- **MinIO SSE-KMS** is mandatory and is set at **bucket creation time** (the configuration cannot be retro-fitted without copying every object out and back in).
- **KES** sidecar runs alongside MinIO and talks to **HashiCorp Vault** or **OpenBao** (open-source MPL fork; pick is an open question) via the Transit engine. Master keys never leave Vault.
- Combined with §2 Object Lock Compliance + Legal Hold, this gives encrypted WORM storage. A stolen disk reveals nothing; a compromised MinIO root account still cannot delete locked objects nor decrypt them without Vault unsealed.
- **Auto-unseal is rejected for v1** because it shifts custody of the unseal key to a cloud KMS, defeating the audit story. Unseal uses 3-of-5 offline key shares.

Input validation and file-type restrictions:
- Enforced by §2 (libmagic + per-artefact magic-byte table + executable blocklist). §5 owns nothing additional here — listed for completeness.

Antivirus scan:
- ClamAV post-store / pre-promotion scan per §2 decision. §5 owns the alert path (ClamAV signal → Wazuh rule pack).

Parser sandboxing (**decision 2026-06-16**):
- **Two-slot model**:

  | Celery queue          | Sandbox             | RAM cap | Network | Used for                                            |
  | --------------------- | ------------------- | ------- | ------- | --------------------------------------------------- |
  | `q.parse.fast`        | gVisor (`runsc`)    | 1 GB    | none    | evtx-rs, text-log parsers — startup matters         |
  | `q.parse.plaso`       | Firecracker microVM | 2 GB    | none    | Plaso (REGF/SRUM/EVTX/SQLite C parsers)             |
  | `q.parse.plaso.heavy` | Firecracker microVM | 4 GB    | none    | SRUM / Amcache only                                 |

- Read-only Wolfi rootfs + writable tmpfs scratch; MinIO access via one-shot presigned URL injected at boot; **no outbound network device** in either sandbox. Sandbox escape attempts are caught by Falco rules on the host kernel.

Tamper resistance and audit-log integrity (**decision 2026-06-16**):
- Per-row hash chain on `audit_log` (`row_hash = sha256(prev_row_hash || canonical_json(row))`) — silent row deletion becomes detectable.
- Daily Merkle root of all `audit_log` rows is anchored by the same Sigstore RFC 3161 TSA used for evidence timestamping (§2). Stored in a new `audit_anchor(date, root_hash, tsa_token)` table.
- Standalone **`kronos-attest verify` CLI** is the third-party-runnable verifier: `--day` rechecks the audit chain + Merkle root + TSA token; `--case` re-reads every evidence object from MinIO, recomputes SHA-256 against `evidence.sha256`, re-verifies the per-evidence RFC 3161 token. Read-only access only — no write paths.

Logging, monitoring and SIEM (**decision 2026-06-16**):
- **Wazuh** is the SIEM. Wazuh Indexer is a logical layer on the existing OpenSearch cluster (separate index prefix `wazuh-alerts-*`, separate role, dedicated DLS).
- Wazuh agents on every host forward FIM, syscall, and auth events. Keycloak event plugin, MinIO bucket access logs, OpenSearch Security audit log, backend application audit events, and Falco runtime alerts all converge in the same cluster.
- Custom Kron-OS rule pack: RBAC-denial bursts, `evidence.delete` by non-admin, Object Lock override attempts, Vault seal/unseal events out of hours, shell-in-container in any parser sandbox.
- **Cold SIEM archive:** every Wazuh alert is mirrored to a write-once MinIO bucket (`kronos-siem-archive`, Object Lock 7 y) so a compromised SIEM cannot rewrite history.
- Pin **Wazuh ≥ 5.1** (the 5.0 silent-data-destruction CVE is patched in 5.1; tracked in the runbook).

Runtime threat detection (**decision 2026-06-16**):
- **Falco** DaemonSet (or sidecar on non-K8s deployments), eBPF CO-RE probe, kernel ≥ 5.8. Default rules + Kron-OS overlay. Alerts → fluent-bit → `falco-alerts-*` → Wazuh.

Vulnerability management (**decision 2026-06-16**):
- **Chainguard Wolfi** base images for every Kron-OS container. Daily upstream rebuild track.
- CI gate: `trivy image --severity HIGH,CRITICAL --exit-code 1` on every PR. SBOM (SPDX) published as an OCI artefact next to the image; Cosign signature with a Vault-Transit-resident key (Sigstore-compatible).
- Nightly `trivy fs` against running images, results indexed and SIEM-alerted.
- Patch SLA: CRITICAL = 24 h, HIGH = 7 d, MEDIUM = 30 d.

Secrets management (**decision 2026-06-16**):
- **Vault / OpenBao** is the system-of-record for: KES master keys, MinIO root creds, Postgres dynamic creds, OpenSearch admin certs, Keycloak admin client secrets, TSA signing key, Cosign signing key.
- No secrets in env vars, ConfigMaps, or git. Service identity via AppRole or Kubernetes-auth; Postgres dynamic creds where supported. Vault audit log shipped into Wazuh.

Backup and disaster recovery (**decision 2026-06-16**):
- MinIO **active-active replication** between the primary on-prem cluster and a warm-standby cluster (mesh topology; per-bucket replication; versioning + Object Lock required). RPO ≈ minutes (async replication lag), **RPO target 5 min / RTO target 15 min**.
- Intra-cluster **Reed-Solomon erasure coding** (default 10+4) for drive-failure tolerance; MinIO "rewind" for point-in-time recovery.
- Postgres WAL ship to a dedicated encrypted backup bucket (separate SSE key from evidence); 7-day PITR.
- Vault integrated-storage snapshots every 6 h to the same encrypted backup bucket; unseal-key shares stored offline.
- OpenSearch snapshot repository on MinIO; daily; quarterly restore test.
- DR drill: full failover tested twice a year.

Rate-limiting and API hardening:
- NGINX edge enforces per-IP and per-`sub`-claim `limit_req`; request-body cap (per §2, the `POST /evidence` payload is metadata-only after the presigned-URL refactor).
- Backend: Keycloak brute-force protection on the IDP side; backend's own per-user soft cap on evidence creation.
- Security headers at the edge: HSTS (`max-age=63072000; includeSubDomains; preload`), CSP (`frame-ancestors 'self' https://app.kronos.example`, see §4), `Referrer-Policy: strict-origin-when-cross-origin`, `X-Content-Type-Options: nosniff`.

ISO 27001:2022 alignment (**decision 2026-06-16** — migrated from the 2013 numbering):

| Control (2022) | Title                                       | Kron-OS evidence                                                                                |
| -------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| A.5.15         | Access control                              | §1 RBAC matrix; Keycloak Organizations; OpenSearch DLS.                                         |
| A.5.17         | Authentication information                  | Keycloak PKCE + refresh-rotation; 15-min access tokens.                                         |
| A.5.24/.25/.26 | Incident management / assessment / response | Wazuh detection + NIST SP 800-86 runbook (collect / examine / analyse / report).                 |
| **A.5.28**     | **Collection of evidence**                  | The product itself — §2 FSM + RFC 3161 + Merkle root + `kronos-attest verify`.                  |
| A.5.30         | ICT readiness for business continuity       | MinIO active-active + Vault HA + OpenSearch snapshots; RPO 5 / RTO 15.                          |
| A.5.33         | Protection of records                       | Object Lock Compliance + Legal Hold + SSE-KMS.                                                  |
| A.8.5          | Secure authentication                       | Keycloak + mandatory MFA for org-admin.                                                         |
| A.8.7          | Protection against malware                  | ClamAV (§2) + Falco runtime + Trivy CI.                                                         |
| A.8.13         | Information backup                          | §5 backup-and-DR section.                                                                       |
| A.8.15         | Logging                                     | `audit_log` (§1) + Wazuh + daily Merkle anchor.                                                 |
| A.8.16         | Monitoring activities                       | Wazuh, Falco, OS Security audit log.                                                            |
| A.8.20         | Network security                            | Four-zone trust-boundary diagram + mTLS + egress allowlist.                                     |
| A.8.24         | Use of cryptography                         | TLS 1.3 + SSE-KMS + RFC 3161 + Cosign.                                                          |
| A.8.25/.28     | Secure SDLC / coding                        | Trivy + Cosign + SBOM + Semgrep + CodeQL in CI.                                                 |

The full control matrix (incl. A.8.2/.6/.9/.10/.23) and per-control owner are in `reviews/Part_5_Review.md` §5.7.

Incident response (**decision 2026-06-16**):
- Aligned with NIST SP 800-86 / ISO/IEC 27037: **collect → examine → analyse → report**.
- Kron-OS dogfoods itself: an internal forensic case is opened in the product for every incident; raw logs are uploaded as evidence; `kronos-attest verify` produces the chain-of-custody attestation appended to the post-incident report.

Open questions (must be resolved before starting §5 implementation): see `reviews/Part_5_Review.md` §6.

## 6. Identity, Authorization, and Single Sign-On (SSO)

> Status: **reviewed 2026-06-16.** Narrative below has been updated; realm export, client manifests, the OpenSearch Security OIDC YAML, the backend JWT pipeline, federation, MFA / step-up, backchannel logout, and the Keycloak → Wazuh sink live in `reviews/Part_6_Review.md`. §6 consumes §1 (RBAC + Organizations + `kronos-roles` scope), §4 (Dashboards iframe + CSP), and §5 (Vault, Wazuh, ACR step-up policy).

Keycloak deployment (**decision 2026-06-16**):
- **Keycloak ≥ 26.6** (target 26.7 for FGAP V2 on Organizations), deployed on-prem in the App zone (§5) behind mTLS.
- **Single realm `kronos`.** Tenants are modelled as **Keycloak Organizations** (§1), not Groups. Realm-per-tenant is rejected; Groups are kept available for in-org sub-grouping only.
- Secrets (admin password, client secrets, signing keys, event-listener bearer) live in Vault / OpenBao (§5); no secrets in env vars, ConfigMaps, or git.

Realm topology and client manifest (**decision 2026-06-16**):

| Client                  | Type          | Flow                                | Default scopes                              | Notes                                                                              |
| ----------------------- | ------------- | ----------------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------- |
| `kronos-spa`            | public        | Auth Code + PKCE (S256)             | `openid profile email roles organization`   | redirect=`https://app.kronos.example/*`; post-logout=`/login`; **no client secret**; refresh tokens never exposed to JS |
| `kronos-backend`        | confidential  | client-credentials + token exchange | `roles organization`                        | client secret in Vault; FGAP-V2 scoped to caller's Organization(s); rotated quarterly |
| `opensearch-dashboards` | confidential  | Auth Code                           | `openid profile email roles organization`   | client secret in Vault; backchannel-logout URL set; logout URL `/dashboards/auth/logout` |
| `kronos-attest`         | confidential  | client-credentials                  | `openid roles`                              | used by §5 `kronos-attest verify --online`; read-only audit role only               |

Realm roles: `org-admin`, `case-lead`, `analyst`, `read-only` (mirror the §1 permission matrix). Mapped 1-to-1 to OpenSearch roles `kronos_org_admin` / `kronos_case_lead` / `kronos_analyst` / `kronos_read_only` (`roles_mapping.yml`).

Client scopes:
- `kronos-roles` — Realm-Role mapper with **Multivalued = true** flattening roles to a top-level `roles` claim. Mandatory because OpenSearch Security's `roles_key` cannot walk the default nested `realm_access.roles` path.
- `organization` — built-in optional scope (Keycloak 26 Organizations); requested on every login so the token carries the org claim.
- `openid profile email` — standard.

Token claim shape (**decision 2026-06-16**) — canonical access-token payload:

```jsonc
{
  "iss": "https://idp.kronos.example/realms/kronos",
  "aud": ["kronos-backend"],
  "sub": "9c7f4e1a-…",
  "preferred_username": "alice@acme.example",
  "given_name": "Alice", "family_name": "Doe",
  "email": "alice@acme.example", "email_verified": true,
  "roles": ["analyst"],
  "organization": { "acme": { "id": "0f2c1f1c-…" } },
  "acr": "aal1",        // → "aal2" after step-up
  "amr": ["pwd"],       // → ["pwd","webauthn"] after step-up
  "exp": 1750008900, "iat": 1750008000
}
```

The token shape is already multi-org-ready (`organization` is a map keyed by alias). For v1 the backend reads the first entry; for v2 (multi-org users) it loops.

Session-lifetime table (**decision 2026-06-16** — supersedes §1's loose statement; single source of truth):

| Setting                                  | v1 value                       |
| ---------------------------------------- | ------------------------------ |
| Access-token lifetime                    | **15 min**                     |
| Refresh-token lifetime                   | 24 h                           |
| SSO session idle                         | 2 h                            |
| SSO session max                          | 24 h                           |
| Refresh-token rotation                   | On                             |
| Refresh-token reuse detection            | On (full-chain revoke)         |
| OpenSearch Dashboards session            | Aligned to OIDC token (no separate cookie max) |
| MFA required for `org-admin`             | Yes (`acr=aal2`)               |
| Required Action: WebAuthn on first login | `org-admin` only (v1)          |

SPA OIDC wiring (**decision 2026-06-16**):
- `keycloak-js` v26 with `pkceMethod: 'S256'`, `responseMode: 'fragment'`, `useNonce: true`, `checkLoginIframe: false`.
- Access token kept in memory; **refresh token in an HttpOnly + Secure + SameSite=Strict cookie** scoped to `/auth`, proxied via the backend `POST /auth/refresh` route. `keycloak-js`'s default localStorage path is **rejected** — XSS-readable.
- Silent refresh `(exp - now - 60s)` ahead of expiry; on refresh failure → Keycloak login (preserving `returnTo`).
- Step-up: on backend `401 insufficient_user_authentication` (RFC 9470), SPA calls `keycloak.login({ acrValues: 'aal2', prompt: 'login' })` and replays the original request.

Backend JWT validation pipeline (**decision 2026-06-16**):
1. Extract Bearer at the gateway; unauthenticated requests are rejected before reaching the application.
2. **JWKS cache** keyed by `(iss, kid)`, TTL 10 min; on `kid` miss re-fetch JWKS once before failing (handles Keycloak key rotation).
3. **Verify** `alg ∈ {RS256, PS256}` (never `none`); `iss` matches the realm URL; `aud` contains `kronos-backend`; `exp > now - 30s`; `nbf <= now + 30s`; `typ` is `Bearer` (never `ID`).
4. **Decode** `org_id` from `organization[*].id` (first entry for v1), `org_alias` from the key, `roles` from the top-level claim, `acr` for step-up checks.
5. **Authorise** against the §1 permission matrix; if `required_acr > token.acr`, return `401 insufficient_user_authentication` with `acr_values` hint.
6. **Audit** to the unified `audit_log` (§1/§2) with `who / when / action / resource / decision / ip`.

OpenSearch Security OIDC integration (**decision 2026-06-16**):
- OIDC auth domain **first** in `config.yml` (`order: 0`, `challenge: false`); basic-auth domain after for internal probes only.
- `subject_key: preferred_username` (audit-friendly); `roles_key: roles` (matches the flat `kronos-roles` claim); `jwt_clock_skew_tolerance_seconds: 30`.
- OS Dashboards configured as an OIDC RP against the same realm (`cht42/opensearch-keycloak` pattern): `opensearch_security.openid.connect_url` points at the realm's `.well-known/openid-configuration`; secret rendered from Vault at boot; cookies `Secure; SameSite=Lax`; multi-tenancy enabled (one OS Dashboards tenant per org per §4).
- Per-tenant Document-Level Security on `tenant_id` and the locked URL filter on `kronos.case_id` (§4) provide belt-and-braces isolation.

Service-account scoping (**decision 2026-06-16**):
- `kronos-backend` has **no realm-wide role**. With Keycloak 26.7+ it is granted FGAP V2 `manage` scope on each Organization it administers; on 26.6 the equivalent is achieved via an Authorization-Services policy on `realm-management` keyed off Group/Org membership (slower — ~200 ms per Admin API call, tolerated for v1).
- The backend re-checks `target_user.organization == caller.organization` before dispatching the Admin REST call (defence-in-depth even if FGAP later misconfigures).

Federation — upstream IdPs (**decision 2026-06-16**):
- **Keycloak Identity Brokering** is the federation strategy. Realm-per-IdP is rejected (same reasoning as realm-per-tenant).
- **LDAP / Active Directory** via the built-in User Storage Provider: LDAPS only, bind credential in Vault, **edit mode = `READ_ONLY`** (clients keep their own directory), weekly full + hourly changed sync.
- **SAML 2.0 upstream IdP** (e.g. Azure AD, Okta): added via Identity Brokering; per-IdP claim mapper translates a SAML attribute (e.g. Azure AD `tid`) into the Kron-OS `organization` shape; IdP-init flow needs the Phase Two `RelayState` SPI.
- **Upstream OIDC IdP** (e.g. customer's Okta tenant): same brokering pattern; claim mapper for `organization`.
- **Org auto-assignment on first login:** v1 uses a Required Action ("Confirm Organization"); v1.1+ (Keycloak 26.7) switches to the new IdP-mapper auto-assignment from external claims.

MFA and step-up authentication (**decision 2026-06-16**):
- **OAuth 2.0 Step-Up Authentication Challenge (RFC 9470)** is the contract between backend and SPA.
- ACR policy:

| Action / role                                            | Required ACR | Factor                              |
| -------------------------------------------------------- | :----------: | ----------------------------------- |
| Login (any user)                                         | `aal1`       | Password                            |
| `evidence.upload`, `evidence.download` (analyst, audited) | `aal1`      | Password                            |
| `evidence.delete`                                        | `aal2`       | Password + WebAuthn / TOTP          |
| `evidence.legal_hold.set` / `.cleared`                   | `aal2`       | Password + WebAuthn / TOTP          |
| Any `org-admin` action                                   | `aal2`       | Password + WebAuthn (passkey) preferred; TOTP fallback |

- **WebAuthn (passkey)** is the preferred second factor; TOTP (OATH) is the fallback. Passkey-autofill (Conditional UI) tracked but not in v1 (SPI add-on).
- Backend issues `401 insufficient_user_authentication` with `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="aal2"` when policy is unmet.

OIDC Backchannel Logout (**decision 2026-06-16**):
- `kronos-backend`, `opensearch-dashboards`, and `kronos-attest` register `backchannel.logout.url`; `kronos-spa` does not (no server-side session — backend invalidation is authoritative, the SPA re-authenticates on next request).
- Backend's endpoint `POST /auth/backchannel-logout` validates the `logout_token` JWT and invalidates the session cache + revokes the refresh-token chain.
- OS Dashboards uses the OpenSearch Security plugin's built-in endpoint.
- **IdP aliases avoid dots** (workaround for keycloak/keycloak#42209).
- `backchannel.logout.session.required: true` for all confidential clients (workaround for keycloak/keycloak#45761).

Keycloak event sink → Wazuh SIEM (**decision 2026-06-16**):
- Realm Events on for login + admin events; persisted 30 d in the Keycloak DB as defence-in-depth (the long-term archive lives in the §5 cold MinIO bucket).
- Event listener emits one-line JSON to stdout; Wazuh agent on the Keycloak host tails it; custom Wazuh decoder pack `kronos-keycloak.xml`; alerts feed `wazuh-alerts-*` (§5).
- Custom rule pack: ≥5 failed logins in 5 min, `client.create|update` outside the GitOps window, `user.deletion` not preceded by a backend `user.purge`, `org-admin` grant outside change window (high), IdP added/modified (critical, potential federation tampering).
- Every successful login, token issuance and admin event is also mirrored into the unified `audit_log` (§1) via `POST /internal/admin/audit-event` from a Keycloak admin webhook, so tenant traceability lives in one canonical store.

Open questions (must be resolved before starting §6 implementation): see `reviews/Part_6_Review.md` §6.
