# KronOS — Full Implementation Roadmap

> **Status:** Backend complete (Phases 1–5). Roadmap covers all remaining implementation work through production-ready v1.
>
> **Design authority:** `Project_Specifications.md` + `reviews/Part_1_Review.md` through `Part_6_Review.md`.
> Each agent prompt below is self-contained — no prior conversation assumed.

---

## Table of Contents

1. [Backend Core](#1-backend-core) ✅
2. [Frontend SPA](#2-frontend-spa)
3. [Advanced Parsing & Celery DAG](#3-advanced-parsing--celery-dag)
4. [Chain of Custody & Attestation CLI](#4-chain-of-custody--attestation-cli)
5. [Security Layer](#5-security-layer)
6. [Observability & SIEM](#6-observability--siem)
7. [Infrastructure & Kubernetes](#7-infrastructure--kubernetes)
8. [CI/CD Pipeline](#8-cicd-pipeline)
9. [v2 Features](#9-v2-features-deferred)

---

## 1. Backend Core

> **Status: ✅ COMPLETE** — all 5 phases implemented, 374 tests passing, 89% coverage.
> Detailed implementation guidelines live in [`CLAUDE.md`](./CLAUDE.md).

### What was built

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Domain models, DI container, audit hash chain, exception hierarchy | ✅ |
| 2 | Evidence intake workflow (UPLOADING → RECEIVED), validators, ClamAV scanner, hash service, FastAPI routes | ✅ |
| 3 | Parser framework (ForensicParser ABC, ParserRegistry), EVTX / CloudTrail / Nginx parsers, Celery task stubs | ✅ |
| 4 | Timeline ingestion into OpenSearch (ECS schema, bulk indexing, ISM policy, DLS role provisioning) | ✅ |
| 5 | Multi-tenancy middleware (Keycloak JWT, TenantContext, RBAC, step-up auth, query isolation) | ✅ |

### Key architecture decisions
- FastAPI + Pydantic v2 (frozen models), SQLAlchemy Core (no ORM), asyncpg
- Abstract base classes for all adapters (parsers, storage, repositories, scanners)
- Append-only audit log with SHA-256 hash chain per row
- OpenSearch index naming: `kronos-{org_alias}-case-{case_id}-{yyyymm}`
- RFC 9470 step-up auth (aal2 required for evidence deletion)

---

## 2. Frontend SPA

> **Spec refs:** `Project_Specifications.md` §4 + `reviews/Part_4_Review.md`

**Stack decision (locked):** React 19 + TypeScript + Vite + TanStack Router + TanStack Query + Tailwind v4 + shadcn/ui + Uppy + keycloak-js v26 (PKCE).

### Steps

#### 2.1 — Project scaffold & auth wiring
- [ ] Vite + React 19 + TypeScript scaffold
- [ ] TanStack Router with type-safe route tree
- [ ] `keycloak-js` PKCE auth: access token in memory, refresh token in HttpOnly cookie via backend `/auth/refresh` proxy
- [ ] Route-level RBAC guards (§1 permission matrix)
- [ ] Zustand for transient UI state (no Redux)
- [ ] Tailwind v4 + shadcn/ui base components

#### 2.2 — Cases & evidence list views
- [ ] `/cases` — org-scoped case list, create-case modal (org-admin / case-lead only)
- [ ] `/cases/{caseId}` — tabs: Evidence (default), Timeline, Audit Log, Settings
- [ ] Evidence list rows: filename, truncated SHA-256 (click-to-copy), uploader, uploaded_at, status pill
- [ ] Status pills per FSM state (slate/indigo/amber/emerald/red matching §4 colour map)
- [ ] Evidence Detail drawer: chain-of-custody, hash, timestamps, error detail

#### 2.3 — Resumable upload (Uppy)
- [ ] Uppy configured with `@uppy/aws-s3-multipart` (primary: calls `POST /api/evidence/upload/request` presigned URL endpoint)
- [ ] `@uppy/tus` plugin as fallback (against tusd when presigned URLs blocked by proxies)
- [ ] Client-side pre-check: `file-type` npm package validates extension + magic bytes before requesting upload URLs
- [ ] Per-chunk progress drives row's progress bar via `upload-progress` event
- [ ] On `complete`, optimistically flip status to `SCANNING`; SSE reconciles thereafter

#### 2.4 — Real-time status via SSE
- [ ] `POST /sse/ticket` — mints a 60-second one-shot ticket (Bearer-authenticated)
- [ ] Backend: `GET /sse/cases/{caseId}/evidence?ticket={ticket}` SSE endpoint
- [ ] Frontend: `EventSource` consuming the SSE channel, updating evidence row state on each `status` / `error` event
- [ ] Polling fallback (every 5 s) if `EventSource` does not reach `OPEN` within 10 s
- [ ] Step-up flow: on backend `401 insufficient_user_authentication`, call `keycloak.login({ acrValues: 'aal2' })` and replay the original request

#### 2.5 — OpenSearch Dashboards iframe embed
- [ ] Timeline tab renders OS Dashboards at `/app/data-explorer/discover` with `embed=true`, `show-top-menu=false`
- [ ] Locked URL filter on `kronos.case_id` injected in the `_g` parameter
- [ ] NGINX reverse-proxy rules: `Content-Security-Policy: frame-ancestors 'self' https://app.kronos.example`, `X-Frame-Options: SAMEORIGIN`
- [ ] CHIPS cookie rewrite (`Partitioned; SameSite=None; Secure`) when Dashboards served on different sub-domain
- [ ] SSO handoff: silent OIDC dance because user already holds Keycloak SSO session

#### 2.6 — Org Admin section
- [ ] `/admin/org` — user management (invite, assign role, remove)
- [ ] Retention defaults, legal-hold overrides
- [ ] All calls routed through backend (backend calls Keycloak Admin REST API scoped via FGAP V2)

#### 2.7 — Error UX & accessibility
- [ ] Authoritative error catalogue (`error_reason` → human title + hint + retry button) per §4 table
- [ ] Diagnostic ID surfaced per error row (= `audit_log.id`), never a stack trace
- [ ] Keyboard navigation, WCAG 2.1 AA baseline, dark/light mode

---

### Agent Prompts — Frontend SPA

#### Prompt 2.1: Scaffold & Auth

```
You are implementing the KronOS frontend SPA (React 19 forensic evidence management platform).

Context:
- Backend is complete at src/ (FastAPI, Python). API docs at GET /docs.
- Auth: Keycloak 26+ Organizations, PKCE flow. Backend issues JWTs with claims:
  { roles: ["analyst"], organization: { "acme": { "id": "uuid" } }, acr: "aal1"|"aal2" }
- Refresh tokens must travel as HttpOnly + Secure + SameSite=Strict cookies via backend
  POST /auth/refresh proxy. keycloak-js localStorage default is rejected (XSS risk).
- Access token kept in memory only. Silent refresh 60 s before expiry.
- Backend returns HTTP 401 with WWW-Authenticate: Bearer acr_values="aal2" for step-up.
  SPA must call keycloak.login({ acrValues: 'aal2', prompt: 'login' }) and replay.

Deliverables:
1. Vite + React 19 + TypeScript project scaffold in frontend/
2. TanStack Router (type-safe routes): /login, /cases, /cases/:caseId, /admin/org
3. keycloak-js v26 integration: pkceMethod: 'S256', responseMode: 'fragment', useNonce: true,
   checkLoginIframe: false. Auth guard HOC that wraps protected routes.
4. Backend /auth/refresh proxy route in src/external/routes/auth.py that receives the
   cookie and issues a fresh access token (keep it thin — validate with Keycloak).
5. Zustand store: { accessToken, user: TenantContext, isAuthenticated }
6. Tailwind v4 + shadcn/ui base (Button, Card, Badge, Dialog, Drawer, Tabs)
7. Route-level RBAC guard using roles from TenantContext. Permission matrix:
   - Create case: org-admin, case-lead
   - Upload evidence: org-admin, case-lead, analyst
   - Delete evidence: org-admin (requires aal2)
   - Manage org users: org-admin
8. Step-up interceptor: Axios/fetch wrapper that catches 401 with acr_values hint,
   triggers keycloak.login({ acrValues: 'aal2' }), retries original request.

Testing:
- Unit tests for the auth guard (mock Keycloak, assert redirect vs render)
- Unit test for step-up interceptor (mock 401, assert login call)
- No Playwright tests in this step (covered in 2.7)

Tech constraints:
- No Redux. Zustand only.
- No localStorage for tokens.
- All API calls go through a typed API client (openapi-fetch from the backend's OpenAPI spec).
- ESLint + Prettier + TypeScript strict mode.
```

#### Prompt 2.2: Cases & Evidence List

```
You are implementing the KronOS case and evidence list views (React 19 SPA, TypeScript).

Context:
- Scaffold from step 2.1 is in place (TanStack Router, Zustand auth, shadcn/ui).
- Backend API (FastAPI):
  GET  /api/cases                           → paginated list of org-scoped cases
  POST /api/cases                           → create case (body: {title, description, reference})
  GET  /api/cases/{caseId}                  → case detail
  GET  /api/cases/{caseId}/evidence         → paginated evidence list
  GET  /api/evidence/{evidenceId}           → evidence detail with chain-of-custody
- Evidence FSM states: UPLOADING, SCANNING, HASHING, RECEIVED, PARSING, INGESTING,
  COMPLETE, ERROR, PURGED. Colour mapping from spec:
  UPLOADING=slate, SCANNING/HASHING=indigo (indeterminate), RECEIVED=blue,
  PARSING/INGESTING=amber, COMPLETE=emerald, ERROR=red, PURGED=slate disabled.
- Roles: org-admin, case-lead, analyst, read-only. TenantContext in Zustand store.

Deliverables:
1. /cases page: org-scoped case list with card grid. "New Case" button (org-admin, case-lead).
   Create-case modal (shadcn Dialog): title (required), description, reference number.
2. /cases/:caseId page with 4 tabs:
   - Evidence (default): evidence list table
   - Timeline: placeholder (will embed OS Dashboards in step 2.5)
   - Audit Log: placeholder (org-admin / case-lead only, per RBAC guard)
   - Settings: placeholder
3. Evidence list row: filename, size (human-readable), SHA-256 (truncated to 8 chars,
   full hash in tooltip + click-to-copy), uploader username, uploaded_at (relative time),
   StatusPill component, hover actions (Download, Legal Hold toggle, Delete, Retry) — each
   gated by RBAC and evidence state.
4. Evidence Detail Drawer (shadcn Sheet from right): chain-of-custody timeline (one entry
   per audit event), full SHA-256, timestamps, error_reason chip with hint text from the
   authoritative error catalogue (see spec §4 table), diagnostic ID.
5. Error catalogue component that maps error_reason strings to { title, hint, retryable }.
6. TanStack Query for all data fetching: stale-time 30 s, refetch on window focus.

Testing:
- Storybook stories for StatusPill (one per FSM state), ErrorCatalogue chip, EvidenceRow
- Unit tests for RBAC guard (mock TenantContext, assert action visibility)
- No Playwright in this step
```

#### Prompt 2.3: Resumable Upload (Uppy)

```
You are implementing the resumable evidence upload flow for KronOS (React 19 SPA).

Context:
- Backend endpoints (Phase 2 of backend):
  POST /api/evidence/upload/request  → { evidence_id, presigned_url, object_key, expires_in_seconds }
  POST /api/evidence/upload/finalize/{evidence_id}  → { state: "SCANNING", ... }
- Primary upload path: S3 multipart via presigned URLs (Uppy @uppy/aws-s3-multipart).
- Fallback: tus.io protocol against tusd sidecar (Uppy @uppy/tus).
- Client-side pre-validation: check extension + magic bytes (first 8 bytes) before
  requesting presigned URL. Accepted: .evtx (ElfFile\x00), .json/.jsonl/.csv/.log (text),
  .pf (MAM\x04), SQLite (SQLite format 3\x00), gzip (\x1f\x8b), zip (PK\x03\x04).
  Blocked: .exe .dll .scr .bat .cmd .ps1 .js .vbs .jar .msi .com (all refused client-side).
- Files up to 1 GB. Multipart chunk size: 50 MB.

Deliverables:
1. "Add Evidence" button on the Evidence tab opens a shadcn Dialog.
2. Drag-drop zone + file picker (Uppy Dashboard plugin, minimal UI).
3. Client-side pre-check using file-type npm package (checks magic bytes of ArrayBuffer
   slice of first 262 bytes). Show inline error if blocked extension or unrecognised type.
4. On file accepted: call POST /api/evidence/upload/request with { filename, content_type,
   size_bytes, case_id }. Pass evidence_id and presigned_url into Uppy's S3 multipart
   companion options.
5. Uppy @uppy/aws-s3-multipart plugin configured with custom createMultipartUpload,
   signPart, completeMultipartUpload, abortMultipartUpload implementations that call the
   backend presigned URL endpoints.
6. Per-chunk progress from Uppy upload-progress event → evidence row progress bar (0–100%).
7. On upload-success: call POST /api/evidence/upload/finalize/{evidence_id} with
   { client_sha256 } (computed client-side with SubtleCrypto SHA-256 during upload).
   Optimistically flip row status to SCANNING.
8. Uppy @uppy/tus fallback: if S3 multipart fails with a network error (not a validation
   error), offer a "Retry via resumable upload" button that switches the active plugin to tus.
9. Cancel button aborts in-flight multipart parts.

Testing:
- Unit test for the client-side pre-check (ArrayBuffer with EVTX magic → accepted;
  .exe magic MZ → rejected; .json text → accepted)
- Unit test for SHA-256 streaming computation
- Mock Uppy's upload events to test progress bar update
```

#### Prompt 2.4: Real-time SSE Status

```
You are implementing the real-time evidence status channel for KronOS (React 19 SPA +
FastAPI backend).

Context:
- Evidence FSM transitions are emitted by the backend as Celery task side effects.
  The SPA needs to show state transitions without the user polling manually.
- W3C EventSource cannot set Authorization headers. Solution: one-shot short-lived ticket.
- Backend already has StepUpAuth for one-time tickets. This SSE ticket is separate and
  simpler (no ACR requirement, no operation binding — just user+org+case scoped, 60 s TTL).
- Polling fallback required: some DLP proxies kill long-running HTTP responses.

Backend deliverables (add to src/external/routes/):
1. POST /api/sse/ticket  (requires Bearer JWT via get_tenant_context)
   Body: { case_id: UUID }
   Returns: { ticket: str, expires_in: 60 }
   Stores ticket in-memory (dict keyed by ticket UUID, value = {user_id, org_id, case_id, exp}).
2. GET /api/sse/cases/{case_id}/evidence?ticket={ticket}
   Validates ticket (single-use, not expired, org_id matches).
   Returns Server-Sent Events stream (text/event-stream).
   Event format:
     event: status\ndata: {"evidence_id":"…","status":"PARSING","progress":{"kind":"bytes","done":N,"total":M}}\n\n
     event: error\ndata: {"evidence_id":"…","reason_code":"parser_oom","retryable":true}\n\n
   Heartbeat: ": keep-alive\n\n" every 15 s to prevent proxy timeout.
3. Mechanism for backend Celery tasks to push updates to open SSE connections:
   Use an asyncio.Queue per (case_id, connection) stored in a module-level dict.
   Celery tasks call a thin helper that pushes to Redis pub/sub; the SSE endpoint
   subscribes via aioredis and forwards messages.

Frontend deliverables:
4. useCaseSSE(caseId) hook: mints ticket via POST /api/sse/ticket, opens EventSource,
   parses status/error events, updates TanStack Query cache for affected evidence_id.
5. Polling fallback: if EventSource.readyState !== OPEN after 10 s, fall back to
   GET /api/cases/{caseId}/evidence every 5 s via TanStack Query refetchInterval.
6. On component unmount, close the EventSource and clear the polling interval.
7. Evidence list subscribes to useCaseSSE — rows update in-place without full refetch.

Testing:
- Unit test the ticket mint + expiry logic (backend, pytest)
- Unit test SSE event parsing in the hook (mock EventSource)
- Integration test: open SSE connection with valid ticket → receive status event → row updates
```

#### Prompt 2.5: OpenSearch Dashboards Embed

```
You are implementing the Timeline tab for KronOS — embedding OpenSearch Dashboards inside
the React SPA (forensic timeline analysis).

Context:
- One OS Dashboards tenant per org (kronos-{org_alias}), NOT one per case.
  Per-case scoping via locked URL filter on kronos.case_id.
- OS Dashboards is an OIDC RP against the same Keycloak realm (cht42/opensearch-keycloak
  pattern). User already has an SSO session → silent OIDC completion, no second login.
- OS Dashboards has NO X-Frame-Options / frame-ancestors out of the box (clickjacking gap,
  RFC #5639). We add them at NGINX reverse-proxy layer.
- When Dashboards served on different sub-domain, cookies need CHIPS for Chrome 130+.

Backend deliverables:
1. GET /api/cases/{caseId}/dashboard-url (requires Bearer JWT + case membership)
   Returns { url: str } — the fully-formed OS Dashboards embed URL with:
   - embed=true, show-top-menu=false, show-query-input=true, show-time-filter=true
   - Locked _g filter: kronos.case_id matches caseId
   - index_pattern_id resolved for the org's index pattern
   Base URL from config (OPENSEARCH_DASHBOARDS_URL env var).

2. NGINX configuration snippet (docker/nginx/kronos.conf):
   - server block for dashboards.kronos.example (or /dashboards/ path)
   - add_header Content-Security-Policy "frame-ancestors 'self' https://app.kronos.example"
   - add_header X-Frame-Options SAMEORIGIN
   - proxy_pass to OS Dashboards upstream
   - If sub-domain: proxy_cookie_flags ~ "Partitioned SameSite=None Secure" (CHIPS)

Frontend deliverables:
3. Timeline tab in /cases/:caseId renders an <iframe> with the URL from step 1.
   Loading state: skeleton while the URL is fetched.
   Error state: "Timeline unavailable — evidence is still processing" when no COMPLETE
   evidence exists for this case.
4. iframe must have:
   - allow="fullscreen"
   - sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
   - title="Timeline Analysis" (accessibility)
5. Provision OS Dashboards index pattern + saved search on case creation:
   Add a Celery task provision_dashboards_tenant that, after a case is created, upserts
   the index pattern kronos-{org_alias}-case-{caseId}-* in the org's OS Dashboards tenant
   via the Dashboards API (POST /_dashboards/api/saved_objects/index-pattern).

Testing:
- Unit test dashboard-url endpoint: valid case → correct URL shape; wrong org → 404
- Unit test NGINX config (nginx -t) in CI
- Manual test: navigate to Timeline tab → iframe loads Dashboards scoped to case
```

#### Prompt 2.6: Org Admin Section

```
You are implementing the Org Admin section for KronOS (React 19 SPA + FastAPI backend).

Context:
- Only users with role=org-admin (acr=aal2 required for mutations) can access this section.
- Backend calls Keycloak Admin REST API using the kronos-backend service account, scoped
  via Keycloak 26.7 FGAP V2 to the caller's organization only (not realm-wide admin).
- Permission matrix for org admin actions (from Project_Specifications.md §1):
  - Invite user: org-admin only
  - Assign/change role: org-admin only
  - Remove user: org-admin only
  - Set retention default: org-admin only
  - Set/clear legal hold: org-admin, case-lead (of case)

Backend deliverables (add to src/external/routes/admin.py):
1. GET /api/admin/org/users → list of { user_id, username, email, roles, joined_at }
2. POST /api/admin/org/invite → { email, role } — calls Keycloak invitation API
3. PATCH /api/admin/org/users/{userId}/role → { role } — updates Keycloak realm role
4. DELETE /api/admin/org/users/{userId} — removes user from org in Keycloak
5. GET /api/admin/org/settings → { retention_days, legal_hold_default }
6. PATCH /api/admin/org/settings → { retention_days }
All endpoints: require org-admin role (requires_role decorator) + aal2 ACR (assert_acr).
All mutations: emit AuditEventType.ORG_USER_INVITED / ORG_USER_ROLE_CHANGED / ORG_USER_REMOVED.

Frontend deliverables:
7. /admin/org route (org-admin only RBAC guard)
8. Users tab: data table with username, email, role badge, joined date.
   Row actions: Change Role (dropdown), Remove (confirmation dialog).
   "Invite User" button: email + role select modal.
9. Settings tab: retention default input (days, 1–3650), save button.
10. Step-up: all mutations check aal2 before calling API. If acr=aal1, trigger step-up
    flow (from prompt 2.1 interceptor).

Testing:
- Unit tests for all 6 backend routes (mock Keycloak Admin REST calls)
- Audit event emitted on each mutation (assert in InMemoryAuditLogRepository)
- RBAC: non-org-admin receives 403
- ACR: org-admin with aal1 receives 401 step-up challenge
```

---

## 3. Advanced Parsing & Celery DAG

> **Spec refs:** `Project_Specifications.md` §3 + `reviews/Part_3_Review.md`

**What phase 3 of the backend built:** parser ABC, registry, EVTX/CloudTrail/Nginx parsers, Celery task stubs.
**What this phase adds:** Plaso in Firecracker, tusd, full Celery DAG with retries, large-file chunking.

### Steps

#### 3.1 — Plaso parser in Firecracker microVM
- [ ] Kronos/plaso container image (Wolfi base, no network egress, 2 GB RAM cgroup)
- [ ] Firecracker microVM launcher for Celery `q.parse.plaso` queue
- [ ] Plaso execution: `log2timeline.py --output-type json_line --output-time-zone UTC`
- [ ] Ingester worker reads Plaso JSONL → ECS normalisation → OpenSearch bulk index
- [ ] Supported: Prefetch, REGF, SRUM/Amcache, SQLite (browser history), journald, EML/MBOX

#### 3.2 — Full Celery DAG
- [ ] `chain(dispatch_parse, parse_artefact, chord(group(index_chunk × N), finalize_evidence))`
- [ ] Queues: `q.parse.fast` (gVisor), `q.parse.plaso`, `q.parse.plaso.heavy` (4 GB), `q.index`
- [ ] Retry policy: 5× exponential back-off 30 s → 8 min for transient errors; straight to ERROR for deterministic
- [ ] Orphan sweeper beat job: abort parse tasks running > 6 h
- [ ] `finalize_evidence`: verify `indexed_docs == parsed_records`; set COMPLETE or ERROR with `ingest_count_mismatch`

#### 3.3 — Large-file text chunking
- [ ] Line-aware splitter for CSV/NDJSON/syslog/Apache/Nginx/CloudTrail > 1 M lines → 500 k-line chunks
- [ ] CSV header re-emitted on every chunk
- [ ] Binary forensic formats (EVTX, REGF, .pf, SQLite, SRUM) always parsed whole

#### 3.4 — tusd fallback for resumable upload
- [ ] tusd Docker sidecar configuration (tus.io protocol, same-org quarantine bucket destination)
- [ ] Backend `PUT /api/evidence/tus` webhook handling on upload completion
- [ ] Frontend already wired in step 2.3

---

### Agent Prompts — Advanced Parsing

#### Prompt 3.1: Plaso Firecracker Integration

```
You are implementing the Plaso parser sandbox for KronOS (Python/Docker/Firecracker).

Context:
- Existing: FastEvtxParser (evtx-rs), CloudTrailParser, NginxParser all run under gVisor
  on the q.parse.fast Celery queue (src/external/parsers/).
- Plaso is needed for: Windows Registry (REGF), Prefetch, SRUM, Amcache, SQLite (browser
  history), journald, EML/MBOX — complex C parsers with historical CVEs.
- Sandbox decision (spec §5): Firecracker microVM, no network egress, 2 GB RAM cap,
  tmpfs scratch, MinIO access via one-shot presigned URL injected at VM boot.
- Plaso writes JSONL (log2timeline.py --output-type json_line --output-time-zone UTC).
  The Kronos ingester worker reads the JSONL file, normalises to ECS + kronos.* provenance,
  and bulk-indexes to OpenSearch.

Deliverables:
1. docker/plaso/Dockerfile — Wolfi base, install log2timeline + python3-plaso,
   ENTRYPOINT: /usr/local/bin/kronos-plaso-worker.py
2. docker/plaso/kronos-plaso-worker.py — script that:
   - Reads env vars: EVIDENCE_URL (presigned GET URL), OUTPUT_TMPFS_PATH, PARSER_PRESETS
   - Downloads evidence from EVIDENCE_URL into tmpfs (no persistent disk write)
   - Runs log2timeline.py with the specified parser presets
   - Writes JSONL to OUTPUT_TMPFS_PATH/output.jsonl
   - Streams JSONL lines to stdout (one JSON per line) so the host ingester can read
3. src/external/parsers/plaso.py — PlasoParser(ForensicParser):
   - parser_type = ParserType.HEAVY
   - supports(): returns True for artefact types in PLASO_SUPPORTED set (REGF, PREFETCH,
     SRUM, AMCACHE, SQLITE, JOURNALD, EML)
   - parse(): launches Firecracker microVM (via firecracker Python SDK or subprocess),
     injects presigned URL, reads JSONL stdout, yields TimelineRecord via _to_record()
   - _to_record(): maps Plaso JSONL fields to ECS + kronos.* provenance
4. Firecracker launcher helper (src/external/sandbox/firecracker.py):
   - Builds Firecracker VM config JSON (kernel, rootfs, network: none, mem_size: 2048)
   - Injects EVIDENCE_URL as kernel cmdline parameter
   - Starts VM, reads stdout JSONL pipe, terminates VM after parse completes or timeout
5. Register PlasoParser in src/external/dependencies.get_parser_registry()
6. Unit tests: mock Firecracker subprocess, verify JSONL → TimelineRecord conversion
   for each supported artefact type (fixtures with sample JSONL in tests/fixtures/)
```

#### Prompt 3.2: Full Celery DAG & Retries

```
You are implementing the complete Celery parsing DAG for KronOS (Python, Celery, Redis).

Context:
- Existing: Celery task stubs in src/external/celery_app.py; ParsingOrchestrationService
  in src/application/parsing_orchestration.py; InMemoryTaskQueue for tests.
- Evidence FSM: RECEIVED → PARSING → INGESTING → COMPLETE (or ERROR from any of these).
- Queues: q.parse.fast (gVisor, short tasks), q.parse.plaso (Firecracker, heavy),
  q.parse.plaso.heavy (Firecracker, 4 GB, SRUM only), q.index (OpenSearch bulk writes).
- Idempotent OpenSearch _id: sha1(evidence_id + ":" + parser + ":" + record_index).
  Retried tasks upsert, never duplicate.

Deliverables:
1. Replace Celery task stubs with full implementations:
   - dispatch_parse(evidence_id, org_id, user_id): loads evidence, resolves parser slot,
     transitions to PARSING, enqueues parse_artefact on the correct queue.
   - parse_artefact(evidence_id, org_id, user_id): downloads first 8 KB header for
     parser detection, runs the parser, streams TimelineRecord output to JSONL in tmpfs,
     enqueues index_chunk tasks (group), chains finalize_evidence.
   - index_chunk(evidence_id, org_id, chunk_path, chunk_index): reads JSONL chunk,
     normalises to ECS, bulk-indexes to OpenSearch with deterministic _ids.
     Transitions evidence to INGESTING on first successful chunk.
   - finalize_evidence(evidence_id, org_id, indexed_docs, parsed_records):
     verifies indexed_docs == parsed_records; transitions to COMPLETE on match,
     ERROR with error_reason=ingest_count_mismatch on mismatch.
2. Retry policy via Celery autoretry_for / max_retries / countdown:
   - Transient (OpenSearch 5xx, MinIO timeout, container start): retry 5× exponential
     30 s → 8 min with ±15 % jitter.
   - Deterministic (ParsingError, ValidationError, OOM captured from exit code): set
     evidence.state=ERROR, evidence.error_reason=<code>, log to audit, no retry.
3. Celery beat tasks:
   - abort_orphan_uploads: every hour, find UPLOADING evidence older than 24 h, abort
     multipart parts, set ERROR with error_reason=upload_timeout.
   - abort_orphan_parses: every hour, find PARSING/INGESTING evidence older than 6 h,
     revoke Celery tasks, set ERROR with error_reason=parse_timeout.
4. CeleryTaskQueue(TaskQueue) concrete implementation (replaces InMemoryTaskQueue in prod):
   src/adapter/queue/celery.py
5. Integration tests (no Docker needed): use InMemoryTaskQueue mock, verify full FSM
   RECEIVED → COMPLETE with a sample EVTX fixture and the existing FastEvtxParser.

Testing:
- All task state transitions must emit the correct AuditEventType
- Deterministic _id verified: parse same evidence twice → same doc IDs in OpenSearch
- Retry: mock OpenSearch returning 503 → assert task retried up to 5 times
```

---

## 4. Chain of Custody & Attestation CLI

> **Spec refs:** `Project_Specifications.md` §2 + §5 + `reviews/Part_2_Review.md` + `reviews/Part_5_Review.md`

### Steps

#### 4.1 — RFC 3161 trusted timestamping
- [ ] Self-hosted Sigstore RFC 3161 TSA (Docker sidecar, reachable only from backend App zone)
- [ ] On `evidence.hash.verified` transition: send SHA-256 digest to TSA, store `TimeStampToken` in `evidence.rfc3161_token`
- [ ] TSA also anchors the daily Merkle root of `audit_log` rows (stored in `audit_anchor` table)

#### 4.2 — Daily Merkle root + anchor
- [ ] Celery beat job: compute SHA-256 Merkle root over all `audit_log` rows for the day
- [ ] Submit Merkle root to TSA, store token in `audit_anchor(date, root_hash, tsa_token)`
- [ ] Merkle tree construction: sort by `sequence_number`, leaf = sha256(row.row_hash)

#### 4.3 — `kronos-attest verify` CLI
- [ ] Standalone Python CLI (no FastAPI import): `kronos-attest verify --day YYYY-MM-DD`
- [ ] `--day`: reconstruct Merkle root from DB, verify against stored TSA token
- [ ] `--case CASE_ID`: re-read every evidence object from MinIO, recompute SHA-256, verify RFC 3161 token
- [ ] `--online`: use `kronos-attest` Keycloak client (read-only audit role)
- [ ] Outputs a signed attestation report (JSON, human + machine readable)

---

### Agent Prompts — Chain of Custody & Attestation

#### Prompt 4.1: RFC 3161 Timestamping

```
You are implementing RFC 3161 trusted timestamping for KronOS evidence (Python + FastAPI).

Context:
- KronOS is a forensic evidence management platform. Every piece of evidence needs a
  non-repudiable timestamp proving it existed in a specific state at a specific time.
- Spec decision (§2 review): self-hosted Sigstore RFC 3161 TSA. Backend calls it on the
  evidence.hash.verified audit event. The TimeStampToken (DER-encoded ASN.1) is stored in
  evidence.rfc3161_token (BYTEA column, already in the schema but not populated yet).
- The TSA is also used for daily Merkle root anchoring of the audit_log table.
- TSA is only reachable from the backend App zone (not from the internet).

Deliverables:
1. docker/tsa/docker-compose.tsa.yml — Sigstore timestamp-authority container
   (ghcr.io/sigstore/timestamp-authority:latest), configured with a self-signed CA
   cert generated by step-ca (see security phase for PKI). For this phase, use a
   self-signed cert for the TSA to unblock development.
2. src/application/timestamping.py — RFC3161TimestampService:
   - __init__(tsa_url: str) — configurable, from settings
   - async timestamp(digest: bytes, hash_alg: str = "sha256") -> bytes:
     Builds a TimeStampReq (rfc3161ng library), POSTs to TSA, returns DER-encoded
     TimeStampToken bytes.
   - async verify(token: bytes, digest: bytes) -> datetime:
     Parses the token, verifies the digest matches, returns the timestamp from genTime.
3. Integrate into EvidenceIntakeService.finalize_upload():
   After evidence.sha256 is verified (HASHING → RECEIVED transition),
   call timestamp_service.timestamp(bytes.fromhex(evidence.sha256)) and persist
   the returned token to evidence.rfc3161_token via evidence_repository.update().
   Emit AuditEventType.EVIDENCE_TSA_ANCHORED.
   If TSA is unreachable: set error_reason=tsa_unreachable (retryable), but do NOT
   block the RECEIVED transition — custody record is created even if TSA is temporarily down.
   A Celery beat job (retry_tsa_pending, every 5 min) picks up any RECEIVED evidence
   where rfc3161_token IS NULL.
4. Add rfc3161_token column to evidence_table (postgres_evidence.py) and _to_row/_from_row.
5. Unit tests: mock the TSA HTTP call, verify token is stored and audit event emitted.
   Verify TSA-unreachable path does not block RECEIVED transition.
   Verify retry_tsa_pending picks up pending evidence.

Dependencies: rfc3161ng (Python), httpx (already in deps).
```

#### Prompt 4.2: Merkle Root & Audit Anchor

```
You are implementing the daily Merkle root anchoring for the KronOS audit log (Python).

Context:
- KronOS stores every security-relevant action in an append-only audit_log table with a
  per-row SHA-256 hash chain (row_hash = sha256(prev_row_hash || canonical_json(event))).
- Spec §5 decision: each day's audit rows are Merkle-rooted and anchored via the RFC 3161
  TSA (from step 4.1). Stored in audit_anchor(date, root_hash, tsa_token).
- This makes it detectable if any row is silently deleted (hash chain breaks) and provides
  a timestamped external witness to the state of the log at day-close.
- The existing AuditLogService in src/application/audit_log.py has verify_chain() which
  walks the chain. The Merkle root is an additional daily proof.

Deliverables:
1. audit_anchor table: add to postgres_audit_log.py schema.
   Columns: date DATE PK, root_hash TEXT (hex SHA-256), tsa_token BYTEA.
2. src/application/audit_log.py additions:
   - build_merkle_root(events: list[AuditEvent]) -> str:
     Sorts by sequence_number. Leaf i = sha256(events[i].row_hash.encode()).
     Builds tree bottom-up: parent = sha256(left_child || right_child).
     Returns hex root hash. Empty list → sha256(b"empty").
   - async anchor_day(date: date, org_id: uuid.UUID) -> None:
     Fetches all audit events for org_id on date (via stream_by_case with date filter).
     Calls build_merkle_root(). Calls RFC3161TimestampService.timestamp() on the root hash.
     Persists to audit_anchor. Emits AuditEventType.AUDIT_MERKLE_ANCHORED.
3. Celery beat task anchor_audit_log: runs daily at 01:00 UTC, calls anchor_day for
   every org that has audit events from the previous day.
4. AuditLogRepository ABC: add get_by_date(org_id, date) → list[AuditEvent].
   PostgresAuditLogRepository: implement via SELECT WHERE org_id=? AND DATE(created_at)=?.
5. Unit tests:
   - build_merkle_root: known input → known root (test vectors)
   - build_merkle_root: single event, even/odd count, empty list
   - anchor_day: verify TSA called with root hash bytes, verify audit_anchor row created
```

#### Prompt 4.3: `kronos-attest verify` CLI

```
You are implementing the kronos-attest standalone CLI for KronOS (Python, Click).

Context:
- Spec §5: "standalone kronos-attest verify CLI, third-party-runnable, no write paths".
- Two modes:
  --day YYYY-MM-DD: reads audit_anchor row, reconstructs Merkle root from audit_log rows
    for that date, verifies root_hash matches, verifies TSA token.
  --case CASE_ID: re-reads every evidence object from MinIO, recomputes SHA-256 against
    evidence.sha256, re-verifies the per-evidence RFC 3161 token.
- CLI has READ-ONLY access. The kronos-attest Keycloak client has only the audit read role.
- Output: JSON attestation report + human-readable summary (rich table).
- Can run offline (--offline) using only local DB access (no Keycloak), or online with
  the kronos-attest Keycloak client_credentials token.

Deliverables:
1. kronos_attest/ Python package (separate from src/):
   - cli.py: Click group with two commands: verify-day, verify-case
   - verifier.py: KronosAttestVerifier class with:
     - verify_day(date, org_id) -> DayReport
     - verify_case(case_id, org_id) -> CaseReport
   - report.py: DayReport, CaseReport dataclasses with JSON serialisation + rich rendering
   - db.py: read-only SQLAlchemy connection (asyncpg, NullPool)
   - storage.py: MinIO client (read-only presigned GET, no write credentials)
   - tsa.py: RFC 3161 token verifier (rfc3161ng, offline — no TSA network call needed)
2. verify_day logic:
   a. Load audit_anchor row for the date.
   b. Load all audit_log rows for that date from DB.
   c. Verify per-row hash chain (same logic as AuditLogService.verify_chain).
   d. Rebuild Merkle root, compare to audit_anchor.root_hash.
   e. Verify TSA token (offline): token's MessageImprint must match root_hash.
   f. Report: PASS / FAIL per check, row count, root hash, TSA cert chain info.
3. verify_case logic:
   a. Load all Evidence rows for case_id from DB.
   b. For each evidence with state=COMPLETE:
     - Download object from MinIO (stream), compute SHA-256.
     - Compare to evidence.sha256.
     - Verify evidence.rfc3161_token: token's MessageImprint must match SHA-256.
   c. Report: per-evidence PASS/FAIL, overall verdict.
4. pyproject.toml: [project.scripts] kronos-attest = "kronos_attest.cli:cli"
5. Unit tests:
   - verify_day: mock DB + known audit events → verify Merkle root matches, TSA stub passes
   - verify_case: mock MinIO stream returning known bytes → SHA-256 matches → PASS
   - Tampered row: change one row_hash → verify_day reports FAIL at correct row
   - Tampered evidence: different bytes from MinIO → verify_case reports FAIL for that item
```

---

## 5. Security Layer

> **Spec refs:** `Project_Specifications.md` §5 + §6 + `reviews/Part_5_Review.md` + `reviews/Part_6_Review.md`

### Steps

#### 5.1 — Internal PKI (step-ca)
- [ ] `step-ca` deployed HA in Docker (or `cert-manager` ClusterIssuer on Kubernetes)
- [ ] 24 h max workload certificates, auto-renewed via ACME
- [ ] All internal services (backend ↔ Postgres, backend ↔ MinIO, backend ↔ OpenSearch, Keycloak ↔ backend) use mTLS

#### 5.2 — MinIO SSE-KMS (KES + Vault/OpenBao)
- [ ] HashiCorp Vault / OpenBao Transit engine for master keys
- [ ] KES sidecar alongside MinIO, configured with Vault backend
- [ ] `mc encrypt set sse-kms` applied to every evidence + audit bucket at creation
- [ ] Combined with Object Lock Compliance mode = encrypted WORM

#### 5.3 — Parser sandbox hardening
- [ ] gVisor `runsc` as the default container runtime for `q.parse.fast` workers
- [ ] Firecracker microVM launcher hardened: read-only rootfs, writable tmpfs scratch only, `network=none`
- [ ] Falco rules: any shell execution in parser container → critical alert

#### 5.4 — NGINX edge hardening
- [ ] TLS 1.3 only, HSTS (`max-age=63072000; includeSubDomains; preload`)
- [ ] Security headers: CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy`
- [ ] Per-IP + per-sub `limit_req`, body-size cap on `/api/evidence/upload/request`
- [ ] Rate limiting: Keycloak brute-force protection + backend per-user evidence creation soft cap

---

### Agent Prompts — Security Layer

#### Prompt 5.1: Internal PKI with step-ca

```
You are implementing the internal PKI for KronOS (step-ca, mTLS, Docker).

Context:
- All internal traffic must use TLS 1.3 (mTLS on every service-to-service hop).
  "Self-signed initially" is explicitly rejected in the spec — trains ops to ignore errors.
- step-ca (smallstep) issues short-lived (24 h max) workload certs via ACME.
- Services that need mTLS: backend API ↔ Postgres, backend ↔ MinIO, backend ↔ OpenSearch,
  backend ↔ Keycloak, backend ↔ TSA, Celery workers ↔ Redis, Celery workers ↔ MinIO.
- In Kubernetes: cert-manager ClusterIssuer wraps step-ca. In Docker Compose: step agent
  on each service container renews its own cert.
- No TLS 1.2 fallback anywhere. Cipher suites: TLS_AES_128_GCM_SHA256,
  TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.

Deliverables:
1. docker/pki/docker-compose.pki.yml — step-ca HA pair (primary + replica) with shared
   persistent volume for the root CA. Bootstrap script creates:
   - Root CA (offline, 10-year, stored in Vault ideally but in a file for dev)
   - Intermediate CA (online, 1-year)
   - Initial server cert for step-ca itself
2. docker/pki/bootstrap.sh — generates root CA, intermediate CA, configures step-ca
   with the correct provisioners (ACME + JWK for service accounts).
3. Per-service cert provisioning in docker-compose.yml:
   Each service gets a step sidecar that renews the cert on a 12 h cron. Cert placed at
   /etc/kronos/tls/cert.pem and /etc/kronos/tls/key.pem. CA bundle at /etc/kronos/tls/ca.pem.
4. Backend TLS configuration (src/config.py):
   - TLS_CERT_PATH, TLS_KEY_PATH, TLS_CA_PATH settings (from env vars)
   - configure_tls() helper that builds an ssl.SSLContext (protocol=TLS_SERVER,
     minimum_version=TLSVersion.TLSv1_3, CA bundle for client-cert verification).
5. Postgres asyncpg connection: ssl=ssl_context (mTLS) in the engine factory.
6. MinIO boto3/aioboto3 client: ssl_context with mTLS in S3EvidenceStorage.__init__().
7. httpx AsyncClient for Keycloak JWKS fetching: ssl=ssl_context.
8. Unit test: verify that an SSLContext built by configure_tls() refuses TLS 1.2
   (mock ssl handshake with protocol=TLSv1_2 → connection refused).
```

#### Prompt 5.2: MinIO SSE-KMS with KES + Vault

```
You are implementing MinIO at-rest encryption (SSE-KMS + KES + Vault) for KronOS.

Context:
- Spec §5 decision: SSE-KMS is mandatory from bucket creation. Cannot be retro-fitted.
  Losing Vault unseal = losing access to all encrypted evidence.
- KES (MinIO Key Encryption Service) is a stateless shim that sits between MinIO and Vault.
- HashiCorp Vault / OpenBao Transit engine holds the master key (never leaves Vault).
- Combined with Object Lock Compliance (already in src/adapter/storage/s3.py):
  encrypted WORM — stolen disk + root MinIO account cannot read or delete evidence.
- Auto-unseal is rejected for v1: unseal uses 3-of-5 Shamir key shares, stored offline.

Deliverables:
1. docker/vault/docker-compose.vault.yml — Vault dev-mode for local dev (file backend for
   production, Integrated Storage / Raft for HA). Initialises the Transit engine and creates
   the kronos-evidence master key on first boot.
2. docker/kes/docker-compose.kes.yml — MinIO KES sidecar. Config file references Vault
   Transit endpoint + AppRole credentials (loaded from env). Policy: KES can use/generate
   data keys with kronos-evidence master key; cannot read the master key directly.
3. docker/minio/docker-compose.minio.yml — updated MinIO config:
   MINIO_KMS_KES_ENDPOINT, MINIO_KMS_KES_CERT_FILE, MINIO_KMS_KES_KEY_FILE,
   MINIO_KMS_KES_CA_PATH — all pointing to mTLS certs from step 5.1.
4. scripts/provision_buckets.sh — creates all buckets with SSE-KMS enabled:
   mc mb myminio/kronos-evidence-{org}-quarantine
   mc encrypt set sse-kms kronos-evidence myminio/kronos-evidence-{org}-quarantine
   mc mb myminio/kronos-evidence-{org}
   mc encrypt set sse-kms kronos-evidence myminio/kronos-evidence-{org}
   mc retention set COMPLIANCE 365d myminio/kronos-evidence-{org}
5. Update S3EvidenceStorage (src/adapter/storage/s3.py) to pass
   ServerSideEncryption='aws:kms' on every PutObject/CopyObject call.
6. Vault AppRole credentials for KES loaded from environment (never in git).
   Rotation procedure documented in docs/operations/key-rotation.md.
```

---

## 6. Observability & SIEM

> **Spec refs:** `Project_Specifications.md` §5 + `reviews/Part_5_Review.md`

### Steps

#### 6.1 — Wazuh SIEM deployment
- [ ] Wazuh Server + Indexer on the existing OpenSearch cluster (separate `wazuh-alerts-*` prefix + DLS)
- [ ] Wazuh agents on every host (FIM, syscall, auth events)
- [ ] Custom Kron-OS rule pack: RBAC-denial bursts, `evidence.delete` by non-admin, Object Lock override attempts, shell-in-parser-container

#### 6.2 — Keycloak event sink
- [ ] Keycloak event listener plugin → structured JSON to stdout → Wazuh agent tails → `wazuh-alerts-*`
- [ ] Custom Wazuh decoder `kronos-keycloak.xml`
- [ ] Alert on: ≥5 failed logins in 5 min, IdP added/modified, org-admin grant outside change window

#### 6.3 — Falco runtime detection
- [ ] Falco DaemonSet (eBPF CO-RE probe, kernel ≥ 5.8)
- [ ] Kron-OS overlay rules: shell-in-container in any parser sandbox → critical alert
- [ ] Falco alerts → fluent-bit → `falco-alerts-*` → Wazuh

#### 6.4 — Cold SIEM archive
- [ ] Every Wazuh alert mirrored to write-once MinIO bucket (`kronos-siem-archive`, Object Lock 7 y)
- [ ] Pin Wazuh ≥ 5.1 (5.0 silent-data-destruction CVE patched in 5.1)

---

### Agent Prompts — Observability & SIEM

#### Prompt 6.1: Wazuh SIEM Integration

```
You are deploying Wazuh SIEM for KronOS and writing the custom Kron-OS rule pack.

Context:
- Wazuh ≥ 5.1 required (CVE in 5.0 causes silent data destruction — DO NOT use 5.0).
- Wazuh Indexer uses the existing OpenSearch cluster (separate wazuh-alerts-* index prefix,
  dedicated DLS role, no overlap with kronos-* evidence indices).
- Wazuh agents collect: FIM, syscall, auth events from all hosts. Keycloak events, MinIO
  bucket access logs, OpenSearch Security audit log, backend application audit events, and
  Falco runtime alerts all converge here.
- Cold archive: every Wazuh alert mirrored to kronos-siem-archive MinIO bucket
  (Object Lock 7 years) so a compromised SIEM cannot rewrite history.

Deliverables:
1. docker/wazuh/docker-compose.wazuh.yml:
   - wazuh-manager (≥5.1), wazuh-indexer (OpenSearch-based), wazuh-dashboard
   - Wazuh indexer configured to write to wazuh-alerts-* on the shared OpenSearch cluster
   - OpenSearch role kronos_wazuh_writer: index_permissions on wazuh-alerts-* only
2. docker/wazuh/etc/kronos-rules.xml — Kron-OS custom rule pack:
   Rule IDs 100100–100200 (local range). Rules for:
   - 100100: RBAC denial burst: ≥5 HTTP 403 from same user in 60 s → high
   - 100101: evidence.delete by non-org-admin (from backend audit log JSON)
   - 100102: MinIO Object Lock override attempt (from MinIO access log)
   - 100103: shell exec inside any kronos-parser-* container (Falco event)
   - 100104: Vault unseal outside business hours (08:00–18:00 UTC)
   - 100105: Keycloak IdP added or modified (from Keycloak event listener)
   - 100106: org-admin role granted outside GitOps change window
3. docker/wazuh/etc/kronos-decoders.xml — decoders for:
   - Backend audit log (JSON, keyed on event_type field)
   - Keycloak event listener JSON (keyed on type field)
   - Falco alert JSON (keyed on rule field)
4. fluent-bit config (docker/fluent-bit/fluent-bit.conf):
   - INPUT: Falco socket / stdout → FILTER: parse JSON → OUTPUT: Wazuh manager (syslog)
   - INPUT: MinIO access log → OUTPUT: Wazuh manager
5. scripts/provision_wazuh.sh — creates the wazuh-alerts-* index template + DLS role
   on the shared OpenSearch cluster (restricted to wazuh service account only).
6. docs/runbooks/siem-alert-response.md — one page per alert rule: description, triage
   steps, escalation path, NIST SP 800-86 phase (collect / examine / analyse / report).
```

---

## 7. Infrastructure & Kubernetes

> **Spec refs:** `Project_Specifications.md` §5 + all reviews (deployment context)

### Steps

#### 7.1 — Docker Compose (development)
- [ ] Full `docker-compose.dev.yml`: Postgres, Redis, MinIO, Keycloak, OpenSearch, step-ca, TSA, ClamAV, tusd
- [ ] `docker-compose.test.yml`: testcontainers-compatible subset for CI (Postgres, MinIO, OpenSearch)
- [ ] Health checks, dependency ordering, volume mounts for hot-reload

#### 7.2 — Helm chart
- [ ] `charts/kronos/` Helm chart covering all services
- [ ] Values: image tags, resource limits, ingress hostname, SSE-KMS configuration flags
- [ ] cert-manager integration for step-ca-issued workload certs
- [ ] Horizontal Pod Autoscaler for backend API and Celery workers

#### 7.3 — Kubernetes manifests (production)
- [ ] Namespace `kronos-prod` with NetworkPolicies (implement four-zone trust boundary)
- [ ] PodSecurityPolicy / PodSecurityAdmission: parser pods use gVisor/Firecracker runtimes
- [ ] MinIO operator or StatefulSet with persistent volumes + erasure coding (10+4)
- [ ] Vault + KES in HA, auto-renewal via cert-manager

---

### Agent Prompts — Infrastructure

#### Prompt 7.1: Docker Compose Stack

```
You are writing the full Docker Compose development stack for KronOS.

Context:
- KronOS is a multi-service forensic platform:
  Backend: FastAPI (Python), Celery workers, Redis (broker + result backend)
  Database: Postgres 16 (audit_log + evidence metadata)
  Storage: MinIO (evidence WORM + quarantine buckets)
  Search: OpenSearch 2.x (timeline events, ECS schema)
  Auth: Keycloak 26+ (Organizations, PKCE, FGAP V2)
  AV: ClamAV (clamd + freshclam)
  Upload: tusd (tus.io resumable upload fallback)
  PKI: step-ca (internal CA for mTLS)
  TSA: Sigstore timestamp-authority (RFC 3161)
- Frontend (React 19 SPA) runs separately via Vite dev server (not in Docker Compose).
- Test environment needs only: Postgres, MinIO, OpenSearch (for testcontainers-based
  integration tests — those currently error when Docker is unavailable).

Deliverables:
1. docker-compose.dev.yml — all services, hot-reload for backend:
   - postgres:16-alpine: data volume, health check, POSTGRES_DB=kronos
   - redis:7-alpine: health check
   - minio/minio: console on :9001, API on :9000, data volume
   - keycloak/keycloak:26: dev mode, realm import from docker/keycloak/kronos-realm.json
   - opensearchproject/opensearch:2: security plugin disabled for dev, single-node
   - opensearchproject/opensearch-dashboards:2
   - clamav/clamav:stable: freshclam sidecar, data volume for virus DB
   - tus/tusd: points to MinIO as backend storage
   - smallstep/step-ca: internal CA for PKI
   - ghcr.io/sigstore/timestamp-authority: TSA for RFC 3161
   - backend: FastAPI with uvicorn --reload, mounts src/ for hot-reload
   - celery-worker: Celery worker consuming all queues
   - celery-beat: Celery beat scheduler
2. docker-compose.test.yml — minimal for CI testcontainers integration tests:
   postgres:16-alpine, minio/minio, opensearchproject/opensearch:2
3. docker-compose.prod.yml — production overrides:
   - No hot-reload, no dev mode
   - Vault + KES replacing direct MinIO creds
   - All services with resource limits (cpu/memory)
   - No exposed ports except NGINX (80→443) and Keycloak (8443)
4. docker/keycloak/kronos-realm.json — Keycloak realm export with:
   - Realm: kronos
   - Clients: kronos-spa, kronos-backend, opensearch-dashboards, kronos-attest
   - Client scopes: kronos-roles (Realm-Role mapper, Multivalued=true), organization
   - Roles: org-admin, case-lead, analyst, read-only
   - Dev seed: one org "dev-org", one user "admin@kronos.dev" with org-admin role
5. .env.example — all required env vars with comments, no secrets (use CHANGE_ME placeholders)
6. Makefile — targets: dev, test, logs, shell-backend, shell-postgres, reset-db, seed-data
```

#### Prompt 7.2: Helm Chart

```
You are writing the Helm chart for KronOS production Kubernetes deployment.

Context:
- Four trust zones (from spec §5): DMZ (NGINX), App (backend, Keycloak, Celery),
  Data (Postgres, MinIO, OpenSearch, Vault, KES, TSA), Observability (Wazuh, Falco).
- Kubernetes NetworkPolicies enforce zone boundaries: App zone pods cannot reach the
  internet directly; Data zone only reachable from App zone; Observability reads from
  App + Data over a read-only audit identity.
- Parser pods must use gVisor (runsc) or Firecracker as the container runtime.
  This requires the node pool to have gVisor installed.
- cert-manager + step-ca ClusterIssuer for workload certs (24 h TTL, auto-renewed).
- All secrets managed by Vault; injected via vault-agent-injector sidecar annotations.

Deliverables:
1. charts/kronos/ — Helm chart (Helm 3):
   Chart.yaml: name=kronos, version=0.1.0, appVersion=0.1.0
   values.yaml: image tags, replica counts, resource limits, ingress config,
     keycloak URL, opensearch URL, vault addr, minio endpoint.
   templates/:
   - namespace.yaml
   - backend/ (Deployment, Service, HorizontalPodAutoscaler, PodDisruptionBudget)
   - celery/ (Deployment for each queue: fast-workers, plaso-workers, index-workers, beat)
   - postgres/ (StatefulSet, Service, PersistentVolumeClaim)
   - minio/ (StatefulSet with 4 volumes for erasure coding 2+2 dev / 10+4 prod, Service)
   - opensearch/ (StatefulSet, Service)
   - keycloak/ (StatefulSet, Service)
   - redis/ (StatefulSet, Service)
   - clamav/ (Deployment with freshclam sidecar)
   - nginx/ (Deployment, Service, Ingress with TLS cert from cert-manager)
   - networkpolicies/ — one NetworkPolicy per zone boundary
   - vault-agent/ — annotations template helper for secret injection
2. charts/kronos/templates/networkpolicies/:
   - dmz-to-app.yaml: allow DMZ (nginx) → App zone only on :8000
   - app-to-data.yaml: allow App zone → Data zone (Postgres :5432, MinIO :9000,
     OpenSearch :9200, Vault :8200, KES :7373, TSA :8080, Redis :6379)
   - deny-app-egress.yaml: deny App zone → internet (egress default deny, allow
     only to Data zone + Keycloak + DNS)
   - observability-read.yaml: allow Wazuh + Falco aggregator read from App + Data
3. charts/kronos/values.yaml defines:
   - gvisorRuntimeClass: "gvisor" (applied to fast-worker pods)
   - firecrackerRuntimeClass: "firecracker" (applied to plaso-worker pods)
4. Makefile targets: helm-lint, helm-template, helm-install-dev, helm-install-prod
5. docs/deployment.md — quickstart: prerequisites, cert-manager setup, step-ca
   ClusterIssuer config, vault-agent-injector setup, helm install command.
```

---

## 8. CI/CD Pipeline

> **Spec refs:** `Project_Specifications.md` §5 + `reviews/Part_5_Review.md`

### Steps

#### 8.1 — Unit + integration tests in CI
- [ ] GitHub Actions: `pytest tests/unit/` on every PR (< 5 s target)
- [ ] GitHub Actions: `pytest tests/integration/` on main merge (uses docker-compose.test.yml)
- [ ] Coverage gate: `fail-under=80` enforced

#### 8.2 — Container build + Trivy scan
- [ ] Chainguard/Wolfi base images for all Kron-OS containers
- [ ] `trivy image --severity HIGH,CRITICAL --exit-code 1` on every PR
- [ ] Build matrix: backend, celery-worker, plaso-parser, frontend-nginx

#### 8.3 — SBOM + Cosign signing
- [ ] `syft` generates SPDX SBOM on merge to main, published as OCI artefact
- [ ] `cosign sign` with Vault-Transit-resident key (Sigstore-compatible)
- [ ] Nightly `trivy fs` against running images, results in Wazuh

#### 8.4 — Lint, type check, format gate
- [ ] `mypy src/`, `ruff check`, `black --check` on every PR (must be zero warnings)
- [ ] Frontend: `tsc --noEmit`, `eslint`, `prettier --check`
- [ ] Semgrep + CodeQL for SAST on every PR

---

### Agent Prompts — CI/CD

#### Prompt 8.1: GitHub Actions Pipeline

```
You are writing the full GitHub Actions CI/CD pipeline for KronOS.

Context:
- Monorepo: Python backend (src/), React frontend (frontend/), Helm chart (charts/),
  Docker configs (docker/).
- Python: pytest, mypy, ruff, black. Coverage ≥ 80% enforced.
- Frontend: TypeScript, eslint, prettier. tsc --noEmit must pass.
- Container builds: backend, celery-worker, plaso-parser, frontend-nginx.
  All use Chainguard/Wolfi base images.
- Security:
  - Trivy: scan every built image, fail on HIGH/CRITICAL CVEs.
  - Cosign: sign images on merge to main using Vault Transit key
    (via VAULT_ADDR + VAULT_TOKEN secrets in GitHub).
  - Syft: generate SPDX SBOM as OCI artefact attached to the image.
  - Semgrep + CodeQL: SAST on every PR.
  - Patch SLA: CRITICAL=24h, HIGH=7d (Dependabot alerts auto-assigned to on-call).
- Deployment: push signed images to ghcr.io/kron-os/ on merge to main.
  Helm chart version bumped automatically from the git tag.

Deliverables:
1. .github/workflows/test.yml — triggers on PR and push to main:
   jobs:
   - python-test: checkout, setup Python 3.11, install deps, run:
     mypy src/, ruff check src/ tests/, black --check src/ tests/,
     pytest tests/unit/ --timeout=30 (must pass in < 5 s)
   - python-integration: runs on main merge only (needs docker-compose.test.yml):
     start postgres + minio + opensearch via docker compose,
     pytest tests/integration/ --timeout=120 --ignore=tests/integration/test_evidence_intake.py
     (the postgres-based intake tests run here with a real container)
   - frontend-check: node 22, npm ci, tsc --noEmit, eslint --max-warnings 0, prettier --check
   - coverage-report: upload pytest coverage.xml to Codecov (badge in README)

2. .github/workflows/build.yml — triggers on merge to main and version tags:
   jobs:
   - build-matrix: matrix over [backend, celery-worker, plaso-parser, frontend-nginx]
     For each image:
     - docker buildx build --platform linux/amd64,linux/arm64
     - trivy image --severity HIGH,CRITICAL --exit-code 1
     - syft <image> -o spdx-json > sbom.spdx.json
     - cosign sign --key vault://transit/kronos-signing <image>
     - docker push ghcr.io/kron-os/<image>:<sha>
   - helm-lint: helm lint charts/kronos/ with values.yaml + values.test.yaml

3. .github/workflows/deploy.yml — triggers on version tag (v*.*.*):
   - Runs build.yml first (needs: build-matrix)
   - Updates charts/kronos/Chart.yaml appVersion to the tag
   - Commits the bump (signed commit via GitHub App token)
   - Creates a GitHub Release with SBOM attachments

4. .github/dependabot.yml — weekly updates for pip, npm, docker, github-actions.
   Auto-assignee: security team.

5. .github/CODEOWNERS — backend: @kron-os/backend-team, frontend: @kron-os/frontend-team,
   docker/: @kron-os/infra-team, charts/: @kron-os/infra-team

6. docs/contributing.md — local dev setup (make dev), running tests (make test),
   commit convention (Conventional Commits), PR template, how to request a CVE exception.
```

---

## 9. v2 Features (Deferred)

> These are explicitly out of scope for v1. Tracked here for planning.

| Feature | Spec Reference | Rationale for Deferral |
|---|---|---|
| Real-time co-presence (CRDT / Yjs + Liveblocks) | §4 review §3.6 | Needs sync server, conflict resolution, annotation index — materially more complex |
| Custom React Flow / D3 process-graph timeline view | §4 review §3.7 | Harfanglab-style graph; deferred because OS Dashboards Discover covers v1 needs |
| Multi-org user support | §1, §6 | Token shape is multi-org-ready; backend reads first entry only in v1 |
| Plaso Conditional UI passkey autofill | §6 | Requires SPI add-on not available in Keycloak 26.x stable |
| `event.original` spill to MinIO for records > 32 KB | §3 | Edge case; referenced via `kronos.original_object_key` in v2 |
| SAML / OIDC federation auto-assignment (Keycloak 26.7 IdP mapper) | §6 | Requires Keycloak 26.7 FGAP V2 stable |
| Browser forensic SQLite artefact visualisation | §3 | Plaso covers extraction; browser-history timeline UI is v2 |

---

## Appendix: Quick Decision Reference

| Decision | Choice | Spec Section |
|---|---|---|
| Auth flow | Keycloak PKCE (S256), access token in memory, refresh in HttpOnly cookie | §6 |
| Multi-tenancy model | Keycloak 26 Organizations (not realm-per-tenant, not Groups-only) | §1 |
| Upload protocol | S3 multipart presigned URLs (Uppy), tusd fallback | §2, §4 |
| Storage | MinIO Object Lock Compliance + SSE-KMS via KES + Vault | §2, §5 |
| AV scan | ClamAV post-store / pre-promotion on quarantine bucket | §2 |
| Parser sandboxing | gVisor (fast: EVTX/text), Firecracker (Plaso: REGF/SRUM/SQLite) | §3, §5 |
| Timeline schema | ECS + `kronos.*` provenance block, OpenSearch | §3 |
| Real-time channel | SSE with short-lived ticket, polling fallback | §4 |
| Dashboards strategy | One OS Dashboards tenant per org, locked case_id URL filter | §4 |
| Internal TLS | step-ca / cert-manager, 24 h workload certs, TLS 1.3 only | §5 |
| SIEM | Wazuh ≥ 5.1 on existing OpenSearch cluster (wazuh-alerts-* prefix) | §5 |
| Runtime detection | Falco DaemonSet (eBPF CO-RE probe) | §5 |
| Container baseline | Chainguard/Wolfi, daily Trivy, Cosign SBOM | §5 |
| Secrets | Vault / OpenBao (Transit + KV), no secrets in env vars or git | §5, §6 |
| Trusted timestamping | Sigstore RFC 3161 TSA (self-hosted), per-evidence + daily Merkle | §2, §5 |
| Attestation CLI | `kronos-attest verify` (read-only, offline-capable) | §5 |
