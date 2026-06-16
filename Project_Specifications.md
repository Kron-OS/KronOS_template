# Project Architecture and Implementation Plan

> **Review log**
> - 2026-04-20 — Part 1 reviewed (see `reviews/Part_1_Review.md`, issues #1 / #7).
>   Key decisions fed back into §1 below: adopt Keycloak 26 **Organizations** rather than Groups-only; commit to an explicit permission matrix; fix the OpenSearch `roles_key` Keycloak-mapper pitfall; plan index rollover to avoid shard explosion.
> - 2026-06-16 — Part 2 reviewed (see `reviews/Part_2_Review.md`, issues #2 / #11).
>   Key decisions fed back into §2 below: presigned S3 multipart upload (tus.io fallback); MinIO **Object Lock Compliance** mode + Legal Hold for true WORM; whole-file SHA-256 verified server-side; libmagic allowlist with a per-artefact magic-byte table; ClamAV post-store quarantine scan; explicit evidence FSM; RFC 3161 timestamping; chain-of-custody reuses §1 `audit_log`.
> - 2026-06-16 — Part 3 reviewed (see `reviews/Part_3_Review.md`, issues #3 / #13).
>   Key decisions fed back into §3 below: ECS-based timeline schema with a `kronos.*` provenance block (case/evidence/sha256); **intermediate ingester** between Plaso and OpenSearch instead of `psort -o opensearch` direct write; per-artefact parser slots (`evtx-rs` fast path, Plaso sandbox container, custom text-log parsers); explicit Celery DAG with deterministic OpenSearch `_id`s; line-aware splitter for text logs only — binary forensic formats are parsed whole; UTC + DST-fold handling; SRUM and other heavy parsers isolated on a memory-capped queue.

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


Case Lifecycle: 
- The user experience is built around cases. A Case represents an investigation to which evidence files are attached. 
- The typical workflow will be: an authorized user (Case Lead or Org Admin) creates a new case, providing basic info like case name, description, and maybe a case ID/reference. Once the case exists, team members (Case Lead, Analysts on that case) can begin uploading evidence to the case. 
- The UI will have an “Add Evidence” button, which allows file selection and upload (multiple files allowed). Users will see an evidence list for the case, with each file’s name, size, hash, uploader, and current status.

Evidence Processing Flow:
- After upload, the user will observe the file going through states: e.g., "Uploading", “Received – parsing queued”, then “Parsing”, then “Ingesting”, then “Complete”.
- We will provide a progress indicator or at least a spinner and status text.
- For large files, parsing could take a long time, so we may also show logs or a percentage if we can get that.
- The user can continue using the app or come back later – the processing happens in background.

Viewing Results (Timeline Analysis):
- Once evidence is ingested (Complete), the user can switch to the Timeline view for that case.
- Rather than building a completely new UI for timeline analysis from scratch (which is complex), we will integrate OpenSearch Dashboards as the primary analysis interface.
- OpenSearch Dashboards (the Kibana-equivalent for OpenSearch) will be set up with index patterns for the case timelines. For example, when a case “Alpha” is created, we might create an index pattern case_alpha_* in Dashboards.
- The user can click a “Open Timeline Analysis” button in our web app, which either embeds the Dashboards in an iframe or opens a new browser tab to OpenSearch Dashboards pointed at the case’s index. Since we plan to have SSO integration, the user will not need to re-login – Keycloak will allow Dashboards access.
- In Dashboards, we can have pre-built visualizations or just let users use Discover to filter and search events.
- We may create a custom front end app using js framework to visualize data in different opensearch views, as Harfanglab makes with network connections. 

User Interface Design: The web application will have a clean UI with a few main views:
 - Dashboard/Cases List: shows all cases the user has access to. From here they can create a new case or select an existing one.
 - Case Detail View: shows case info and the list of evidence items. This is where files can be uploaded and their statuses seen. We’ll also show maybe summary stats.
 - Timeline/Analysis View: this might simply link into OpenSearch Dashboards as described. 
 - Collaborative Features: Since data is team-based, multiple analysts might be looking at the timeline simultaneously. Using OpenSearch Dashboards means they could each apply filters independently, etc., without interfering with each other.

Handling Errors:
- If a file fails to parse (status goes to ERROR), the UI will reflect that and perhaps offer a retry button.
- The error details (from logs) might be surfaced in a minimal way, e.g., “Parse failed: invalid format” or a generic “An error occurred. Please check the file format or contact support.” We will not expose raw stack traces to the end user, but we will log them for developers/admins.


## 5. Security and Compliance

Security is paramount given the sensitive nature of digital evidence. We will implement several measures in line with ISO 27001 controls and general best practices:


Data Residency and Retention: 
- All user data (uploaded evidence) resides on the designated on-premises server/storage. We will enforce the retention period as mentioned: by default, 365 days.

Transport Security (TLS 1.3): All network communication in the system will be secured with encryption. This includes:
 - The web app and API will be served over HTTPS with TLS 1.3 only, using strong cipher suites. We’ll obtain or generate certificates (for on-prem, likely a self-signed or enterprise CA certificate initially; we can also integrate Let’s Encrypt if the server is internet-accessible for convenience).
 - Internal components like OpenSearch and Keycloak will also communicate over TLS where applicable. OpenSearch nodes will have certificates for inter-node encryption and for the client (Dashboards) to node encryption. Keycloak can be run with HTTPS enabled.


Input Validation and File Type Restrictions: 
- As mentioned, we will block certain file types from being uploaded. Executable files (.exe, .dll, scripts, etc.) will be rejected. 
- Additionally, all files will be treated as untrusted, even if they are of allowed type. We won’t execute them except through our parsers.
- We may also run a quick antivirus scan on uploaded files as a precaution, especially if users might inadvertently upload infected files.

Sandboxed Parsing: 
- To enhance security when data parsing, we could use a sandbox like gVisor.
- We must make performance tests to ckeck if it is light or very time consuming. 


Logging and Monitoring:
- All security-relevant events will be logged. This includes login attempts on the web app, any permission denials, uploads and downloads of evidence, and system errors.
- If someone tries to access a case they shouldn’t, we will log the denied request and the username/IP. We will review these logs periodically or integrate with a SIEM.

Access Control:
- Within the application, we enforce least privilege.

Secure Configuration: We will follow best practices for securing each component:
 - Keycloak: use secure passwords for admin, turn off any unnecessary open registration or public endpoints, set token lifespans appropriately. We’ll also configure Keycloak to require strong passwords for user accounts.
 - OpenSearch: enable its security plugin, disable demo accounts, use HTTPS for client and node communication, and keep it on a private network or localhost-only for access.
 - API: implement rate limiting to mitigate brute force or DoS, and use input validation on all API parameters. We will also ensure serialization is handled safely.

We will document everything as part of an “Information Security Management” approach:
 - A.8.2 (Information Classification): Case data is clearly sensitive, we treat all evidence as confidential. Only authorized team members access it.
 - A.9 (Access Control): As described, strong authentication via Keycloak and role-based access ensures only the right people access the right data.
 - A.10 (Cryptography): TLS for data in transit, in the future we will consider encrypting files on rest and implementing a key manager.
 - A.12.3 (Backup): We should consider backups of the data within retention period.
 - A.12.4 (Logging): We have extensive logging of actions, stored securely (not modifiable by normal users).
 - A.14 (System acquisition, development, maintenance): As developers, we’ll follow secure coding practices. The user specifically is asking for this plan, which shows security is built-in from design (secure by design).
 - A.13 (Communications security): Covered with TLS and network segregation.

Tamper Resistance: We might implement additional protections like checksums or digital signatures on evidence and logs.

## 6. Identity, Authorization, and Single Sign-On (SSO)

We have chosen Keycloak (an open-source Identity and Access Management solution) as the central authentication and authorization server. Keycloak will handle user identities, authentication (login), and issuing tokens that our services (API, OpenSearch) will trust. This provides a unified SSO experience and robust security features out-of-the-box.

Keycloak Setup: We will deploy a Keycloak server on-prem (via a container). The following configuration will be done in Keycloak:
Create a Realm to contain our users and roles.
Within the realm, define Clients for our applications:
- One client for our Web App/API.
- One client for OpenSearch Dashboards integration. OpenSearch’s security plugin acts as an OpenID Connect Relying Party. In the Keycloak realm we’ll create a client (e.g., opensearch-dashboards) that will represent OpenSearch Dashboards. We will configure this client with settings Keycloak requires.

Define the Roles in Keycloak that match our application roles: org-admin, case-lead, analyst, read-only.

Model the Team/Org membership. There are a couple of ways:
- Use a separate realm per organization, but that gets complex to manage. Instead, we’ll use a single realm and use Groups to represent organizations/teams. For example, create a Group for each team (Team A, Team B). Users can be placed into a group corresponding to their org. We can also map a group membership into the token as a claim (so our app knows which org the user is in). Keycloak can include group membership in the JWT token. We might also encode the org in the username or a custom attribute.
- Use Keycloak’s multi-tenant support via Realms: but managing multiple realms (one per tenant) would mean replicating client configuration for each, and dealing with identity across realms beacause Keycloak doesn’t share identities across realms

Configure token settings: 
- We will set the access token lifespan to a suitable length. By default Keycloak uses short time tockens but since the users are expected to stay connected for a long time we will extend it to 12h or a day.
- Another possibility is to rely on refresh tokens and an SSO session lifespan. Keycloak can keep the user logged, even if tokens expire sooner, it will refresh them. We’ll set “SSO Session Max” to 24 hours. 
- We will enable “Refresh Token” rotation for security, so each refresh invalidates the old token.

SSO User Login Flow: 
- When a user accesses our web application, if not already authenticated, they will be redirected to Keycloak’s login page;
- The user enters credentials;
- Upon successful login, Keycloak will issue an ID Token and Access Token (JWT) for the client.

JWT Tokens: 
- The Access Token JWT is the crucial piece, it will contain the user’s identity and roles. 
- We will configure a Role Mapper in Keycloak to ensure the roles are in the token.
- The token will contains essentials information about the client (org, team, role)

API Authorization with JWT: 
- Our backend API will use the JWT access token for auth on each request (the frontend will include it in Authorization: Bearer <token> header); 
- The API needs to verify and decode the JWT;
- We will fetch Keycloak’s public key or certificate to verify the token’s signature (Keycloak exposes the public keys).
- We can cache this key. 
- Using a library like python-jose or PyJWT with the RS256 public key, we validate that the token is valid.

- On each API request, we will check the actions: e.g., if a user tries to access a case that is not their org, we deny. If an Analyst tries to call an admin-only API, we deny. This check is straightforward since we have the roles list from the JWT. By doing this in the API, we ensure even if someone got an access token, they can only do what their token’s roles allow (and tokens can’t be modified by the user due to the signature).

Integration with OpenSearch Security Plugin: 
- One powerful aspect is that OpenSearch can also directly trust JWTs (Keycloak-issued) for auth. We will configure OpenSearch’s securityconfig to use JWT/OpenID auth. 
- In opensearch-security/config.yml, define an authentication domain of type openid. 
- The steps to make opensearch use keycloak auth system have to be defined
- In OpenSearch Dashboards config , we’ll configure the OpenID settings to point to Keycloak. Dashboards will redirect users to Keycloak, just like our app does. After login, Keycloak redirects back to Dashboards with a JWT, and Dashboards will pass that to OpenSearch cluster on requests. We will ensure the roles_key in config is set to “roles” so that the roles from the token are mapped.

Role Mapping in OpenSearch: 
- We will map the Keycloak roles to OpenSearch permissions. For example, create OpenSearch roles: org-admin-role, analyst-role, etc., with specific index permissions. We can then map JWT claims to these.
- We might use a one-to-one naming to keep it simple. This way, when an Analyst uses Dashboards, their token’s “analyst” role will map to a role that perhaps allows read-only search on indices. We might give case-lead a role that allows managing index patterns or writing annotations. Org-admin might have a role to view all indices in that org (though if indices are per case and prefixed, we might incorporate org identifier into the index name and use wildcards in permissions).
- see cht42/opensearch-keycloak

Logging and Audit (Keycloak): 
- Keycloak can log all logins and events. We will enable logging of events like login success, failure, logout, admin changes. 
