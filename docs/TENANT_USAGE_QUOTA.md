# Tenant Storage Usage & Quota Enforcement

**Status:** design scope, written by the orchestrator before dispatch (same
pattern as `docs/NEXTGEN_SOC_ROADMAP.md`'s H4/I2/I3/I5 items — this file
exists so a cold agent isn't left to invent the whole scope). Not part of
the closed M0-M8 roadmap; a new, standalone initiative, requested directly
by the project owner 2026-08-08.

## 0. Verified starting facts (read before designing anything)

- **`OrgSettings` is a complete stub today, zero real persistence.**
  `src/external/routes/admin.py`: `GET /admin/settings` reads
  `retentionDays` off the **global**, env-var-backed `Settings()` object
  (not anything per-org), and `PATCH /admin/settings` doesn't write
  anywhere at all — it just echoes the request body back and logs an audit
  event. There is no per-org settings table anywhere in this codebase.
  **This means the quota feature is also the first real per-org settings
  persistence layer this platform gets** — scope accordingly, but do not
  scope-creep into fixing the pre-existing `retentionDays`/
  `legalHoldDefault` stub gap; report it, don't fix it (it's real,
  pre-existing, and unrelated to quota).
- `Evidence.metadata.size_bytes` already exists and is populated at real
  upload time (`src/domain/evidence.py` / `EvidenceMetadata`) — the raw
  material for computing real per-org usage already exists, no new
  size-tracking primitive needs inventing.
- `src/config.py`'s `max_upload_bytes` (default 5 GiB) is a **global,
  per-file** size ceiling — a completely different concept from what this
  feature adds (a **per-org, aggregate, cross-file** storage ceiling).
  Don't confuse the two or reuse the same setting for both purposes.
- CLAUDE.md §E ("Ingestion Pipeline Rules") is binding and unchanged by
  this feature: every FSM transition is server-triggered only, no route
  handler sets Evidence state directly, and the established beat-task
  recovery pattern (`auto_dispatch_received`, `docker/celery_app.py`) is
  the correct shape for "something changed, re-check and resume
  automatically" — this feature's own auto-resume mechanism (§3 below)
  should mirror that pattern, not invent a new one.

## 1. Scope, precisely (resolving the request's own ambiguity)

The request: track tenant storage usage against a spend limit (e.g. 50 GB)
for the **"ingestion mode / direct upload"** path; keep storing data up to
1.5x the limit but stop *ingestion*; resume ingestion automatically if the
org's limit is later raised.

**"Ingestion mode / direct upload" is read here as the Phase 1-5 evidence
upload+intake pipeline** (`EvidenceIntakeService`/`ParsingOrchestrationService`
— upload → autonomous parse → OpenSearch index), **not** the D1-D5
continuous stream/collector-mTLS ingestion path. Continuous-stream quota
enforcement (metering per-event/per-batch volume from `StreamIngestAdapter`/
`BatchSealingService`) is a real, natural follow-up but a materially
different metering unit (event count/rate vs. file bytes) and is explicitly
**out of scope** for this pass — flag it as follow-up, don't fold it in
speculatively.

Two distinct ceilings, both per-org, both derived from one configured
`storage_quota_bytes`:

1. **Storage ceiling, hard, at 1.5× quota.** Once an org's real total
   stored bytes would exceed `1.5 * storage_quota_bytes`, **new uploads are
   rejected outright** (a real, clear error — not silently accepted then
   dropped). Below that ceiling, uploads succeed and bytes land in MinIO
   exactly as they do today — no behavior change.
2. **Ingestion ceiling, soft, at 1.0× quota.** Once an org's real total
   stored bytes is **at or above** `storage_quota_bytes` (but still under
   the 1.5× hard ceiling), newly-uploaded evidence is still accepted and
   stored, but the autonomous pipeline's dispatch-to-parse step is **held**
   rather than proceeding — the evidence sits in a real, honest, named
   state (not silently stuck, not misrepresented as still "processing").
   No data is lost; it simply isn't parsed/indexed yet.
3. **Auto-resume.** If an org admin later raises `storage_quota_bytes`
   (or usage drops, e.g. after evidence deletion) such that current usage
   is back under 1.0×, any evidence held under (2) is automatically
   dispatched for parsing — no client action, no manual admin re-trigger,
   mirroring `auto_dispatch_received`'s own "the system heals itself"
   precedent.

## 2. Design (OOP, per CLAUDE.md §A)

- **`OrgQuota`** (`src/domain/quota.py`, pure Pydantic, no framework
  imports): `org_id`, `storage_quota_bytes: int | None` (`None` = 
  unlimited — a real, valid, common case, not a sentinel to special-case
  awkwardly), `updated_at`. This is the first real per-org settings
  domain object in the codebase — keep it narrowly scoped to quota, not a
  generic `OrgSettings` grab-bag (that's a separate, larger refactor of the
  existing stub, out of scope here).
- **`OrgQuotaRepository`** (ABC, `src/adapter/repository/quota.py`) +
  `PostgresOrgQuotaRepository` + `InMemoryOrgQuotaRepository` (test double)
  — mirrors every other repository ABC in this codebase exactly
  (`DetectionRepository`, `SealedBatchRepository`, etc.). New real
  Postgres table (`org_quotas`), one row per org that has ever had a quota
  set; absence of a row means unlimited (don't default to some magic
  number).
- **`TenantUsageService`** (`src/application/tenant_usage.py`) — computes
  real current usage for an org. Start with the simplest correct
  implementation: a real `SUM(size_bytes)` query scoped to non-purged
  Evidence for that org (reuse `EvidenceRepository`'s existing query
  surface rather than adding a raw-SQL bypass) — do not build a
  maintained running-counter/cache in this first pass unless a real,
  measured performance problem shows up in the PoC (CLAUDE.md's own
  "don't design for hypothetical future requirements" applies directly
  here: a `SUM` query is correct and simple; a cached counter is an
  optimization with its own real invalidation-correctness risk, not
  justified without evidence it's needed).
- **`StorageQuotaGate`** (`src/application/quota_gate.py`) — the one class
  both enforcement points below actually call. Two methods:
  `check_upload_allowed(org_id, incoming_size_bytes) -> QuotaDecision`
  (the 1.5× hard check) and `is_ingestion_held(org_id) -> bool` (the 1.0×
  soft check). `QuotaDecision` is a small frozen value object (`allowed:
  bool`, `reason: str | None`, `current_usage_bytes`, `quota_bytes`) —
  mirrors `MetricResult`'s/`ApprovalDecision`'s own "never a bare bool,
  always carry the real numbers" idiom from this session's own prior work.
- **Enforcement hook 1 (storage ceiling):** `EvidenceIntakeService
  .request_upload()` (`src/application/evidence_intake.py`) calls
  `StorageQuotaGate.check_upload_allowed()` before issuing a presigned URL.
  A denial raises a new `StorageQuotaExceededError` (add to
  `src/exceptions.py`), mapped to a real, distinct HTTP status (409 or 413
  — decide and justify) in the FastAPI exception handler, with the real
  current/quota numbers in the response body so the frontend can render a
  specific, actionable message (not a generic 500).
- **Enforcement hook 2 (ingestion ceiling):** the dispatch-to-parse step
  (`EvidenceIntakeService._promote()`'s `task_queue.enqueue_dispatch()`
  call, or wherever `ParsingOrchestrationService.start_parsing()` is
  invoked from — read the real current autonomous-pipeline call chain in
  CLAUDE.md §E before deciding exactly where) checks
  `StorageQuotaGate.is_ingestion_held()` first. If held: do **not** enqueue
  `dispatch_parse`; instead mark the Evidence with a new, honest indicator
  that it's quota-held (a new `EvidenceState`-adjacent field or a specific
  `error_reason`-like value — **not** the `ERROR` state, since this isn't
  an error, it's an expected, recoverable hold; check whether
  `EvidenceState` needs a new value or whether a boolean/reason field on
  existing states is more correct — this is a real domain-modeling
  decision to make deliberately, not default without thought). Audit the
  hold event (`AuditLogService`, a new `AuditEventType`).
- **Auto-resume beat task:** a new Celery beat task (`src/external/
  celery_app.py`, alongside `auto_dispatch_received`) that periodically
  re-scans quota-held evidence per org, re-checks `is_ingestion_held()`,
  and re-dispatches any org that's now back under the soft ceiling. Mirror
  `auto_dispatch_received`'s own real schedule/idiom (it runs hourly at
  :15 — decide whether quota re-check needs to be more frequent, e.g. on
  every `PATCH` to the quota setting itself as a direct trigger, **plus**
  the periodic beat sweep as the same belt-and-braces safety net
  `auto_dispatch_received` already provides for its own concern).
- **Admin route:** extend (don't replace) the existing stub
  `GET/PATCH /admin/settings` — or add a dedicated
  `GET/PATCH /admin/quota` if that's cleaner given the existing route's
  stub nature; make and justify the call — real persistence via
  `OrgQuotaRepository`, `ORG_ADMIN`-only (mirrors the existing
  `_ADMIN_ROLES` gate on that route), audited on every change.

## 3. Hard invariants (this platform's own established §1 discipline, applied here)

- **Tenant isolation computed, never supplied:** `org_id` for every quota
  check comes from the authenticated `TenantContext`, never from a
  client-supplied field — a malicious upload request cannot claim a
  different org's quota headroom.
- **Audit every mutation:** quota-set, upload-denied-for-quota, and
  ingestion-held/resumed are each real, distinct, audited events.
- **Fail loudly:** a quota-check that can't reach Postgres must raise, not
  silently allow (fail-closed) or silently deny (fail-open denial-of-service
  for a legitimate org) — decide and justify which failure mode is
  correct here (this repo's own precedent, e.g. ClamAV's dev-fail-open/
  prod-fail-closed gate, is the right analogy to reason from, not a
  default to copy blindly since a storage cap has different risk
  characteristics than a virus scan).
- **Verification-first (CLAUDE.md §F):** real PoC against real Postgres +
  MinIO before any `src/` change — seed a real org, real Evidence rows
  with real `size_bytes`, prove the 1.0×/1.5× thresholds trigger correctly
  against real computed usage, prove a real held-evidence row actually
  resumes for real after a real quota update, before writing the
  production classes.

## 4. Explicitly out of scope this pass (name it, don't silently drop it)

- Continuous stream/collector-ingest quota (different metering unit, see §1).
- A UI for org admins to see/set their own quota (this is a backend
  feature this pass; a frontend settings page is natural follow-up,
  sequenced after real settings persistence exists per the E2E test
  plan's own §3.4 note).
- Any actual "spend"/billing integration — this is a **storage byte**
  ceiling, not a cost/dollar calculation; "spend limit" in the request is
  read as shorthand for "storage limit," not a literal billing feature.
- Per-case or per-user quotas (org-level only, matching every other
  tenant-scoped concept in this platform).

## STATUS (implementation pass, 2026-08-08)

**Built:** everything in §2's design, implemented essentially as scoped,
plus the decisions this doc deliberately left open (below). New files:
`src/domain/quota.py` (`OrgQuota`), `src/adapter/repository/quota.py` +
`postgres_quota.py` (`OrgQuotaRepository` ABC + Postgres/in-memory),
`src/application/tenant_usage.py` (`TenantUsageService`),
`src/application/quota_gate.py` (`StorageQuotaGate` + `QuotaDecision`).
Modified: `Evidence` (new `quota_held: bool` field +
`with_quota_held()`), `EvidenceRepository` ABC (+`get_total_size_bytes`,
`stream_quota_held`, `stream_all_quota_held`, implemented in both Postgres
and the test in-memory double), `EvidenceIntakeService.request_upload()`
(hook 1), `ParsingOrchestrationService.start_parsing()` (hook 2, the one
authoritative gate every dispatch path funnels through), a new
`kronos.auto_resume_quota_held` beat task (every 15 min) in
`celery_app.py`, a dedicated `GET/PATCH /api/admin/org/quota` route, 4 new
`AuditEventType`s, and `StorageQuotaExceededError`. `org_quotas` table
creation wired into both `startup.py` variants (the exact D3-class gap the
brief warned about) and `celery_runtime.py`'s `TaskResources`.

**The open decisions, made and why:**
- **413, not 409, for a quota-denied upload.** The real cause is a size
  ceiling (aggregate/per-org, but still a size ceiling), not a
  concurrent-modification conflict a client would retry unchanged and
  expect to succeed — 409 in this codebase already means the latter
  (`admin.py`'s `_to_http_error`). Registered both as a route-level catch
  in `evidence.py` and a global handler in `fastapi_app.py`.
- **A boolean flag (`quota_held`), not a new `EvidenceState`.** Mirrors
  `legal_hold`'s own established shape exactly: a real property orthogonal
  to FSM state, not a failure and not a new transition to wire
  bidirectionally into `_VALID_TRANSITIONS`. Evidence sits in `RECEIVED`
  the whole time it's held — nothing about its lifecycle branched.
- **Fail-open**, on both quota checks, when `OrgQuotaRepository`/
  `TenantUsageService` can't reach Postgres. Deliberately the *opposite* of
  ClamAV's prod-fail-closed gate: ClamAV protects against a security risk
  (malware reaching storage) where failing open is a real hole; a storage
  quota is a cost/capacity control, and failing closed here would let one
  new, narrow subsystem's own bad moment block the platform's central
  mission (capturing forensic evidence) for orgs nowhere near their quota.
  Every fail-open event is logged (a legitimate alerting signal), so
  there's no silent failure mode, only the fail-vs-block tradeoff.
- **A dedicated `/admin/quota` route**, not an extension of `/settings`.
  `/settings`'s DTOs are shaped 1:1 around a specific, already-shipped
  frontend interface unrelated to quota, and that stub's own persistence
  gap is explicitly out of scope to touch here — bolting a third field
  onto it would conflate two independent admin concerns in one
  contract/audit-event.
- **Beat sweep every 15 min, plus a direct trigger on the quota-raising
  PATCH** — both, as suggested. The sweep is the required belt-and-braces
  safety net (it also catches usage dropping via evidence deletion, which
  has no PATCH of its own); 15 min, not hourly like the orphan-cleanup
  tasks, because a quota hold is a routine, analyst-visible condition, not
  a rare failure — every minute held is timeline data an analyst can't see
  yet.

**Real captured PoC result:** `poc/tenant_storage_quota/` — 22/22 checks
passed against real Postgres 16 + real MinIO + the real shared dev-stack
OpenSearch, plus the real `auto_resume_quota_held`/`dispatch_parse`/
`parse_artefact_fast` Celery task functions (called directly; see that
PoC's README for exactly what "called directly" does and doesn't verify).
A genuinely quota-held evidence row was confirmed to never reach
`COMPLETE`, then reached real `COMPLETE` after a real quota increase with
no manual FSM mutation anywhere in the script — only two `OrgQuota`
Postgres upserts, exactly what a real admin PATCH does. Full audit trail
independently re-read from a fresh Postgres connection in a separate
script afterward.

**Verified:** unit suite 1345 passed, 1 skipped (was 1315/1, so +30 new
tests, zero regressions — confirmed via `git stash -u` against the
pre-change tree). mypy: 29 pre-existing errors, unchanged (confirmed same
way) — one new file (`postgres_quota.py`) initially reproduced the same
known `dict[str,object]`-vs-`tzinfo` false positive `postgres_sealed_batch.py`
already has; fixed by mirroring `postgres_evidence.py`'s cleaner
`dict[str, Any]` + shared `_ensure_utc` shape instead, net zero new errors.

**What was NOT verified, and why:**
- No live Celery worker process consuming the real broker queue — the PoC
  calls the real task functions directly (mirroring `poc/celery_beat`'s own
  established precedent), and independently confirms the re-enqueued
  message really lands on the real Redis broker first. The one hop not
  re-verified is specifically "a live worker dequeues and dispatches that
  message" — already-covered ground (`poc/celery_redis/`), not new logic
  this feature adds.
- The admin route's HTTP layer is covered by unit tests (`TestClient` +
  dependency overrides), not the PoC — the PoC exercises the same
  `OrgQuotaRepository.upsert()` call the route makes, directly, since the
  PoC's focus is the service/repository/Celery layer per CLAUDE.md §F, not
  re-verifying FastAPI routing (already covered elsewhere for this exact
  router).
- Real ClamAV was not exercised in the PoC (`NoOpScanner` used instead,
  same choice `poc/full_pipeline` documents making for the same reason) —
  AV scanning is orthogonal to quota logic and independently verified in
  `poc/clamav/`.
- The pre-existing `/admin/settings` `retentionDays`/`legalHoldDefault`
  stub gap (§0) was confirmed to still exist but was **not** touched, as
  instructed.

**What remains (real, named follow-ups, not silently dropped):**
- A frontend settings page for org admins to view/set their own quota (§4,
  explicitly out of scope this pass).
- Continuous-stream/collector-ingest quota enforcement (§4, different
  metering unit).
- The `/admin/settings` stub's own pre-existing non-persistence gap (§0) —
  real, pre-existing, unrelated to quota, not fixed here.
