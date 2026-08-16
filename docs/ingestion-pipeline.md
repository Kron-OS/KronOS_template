# KronOS Evidence Ingestion Pipeline

**Status:** Implemented (Phases 1–5).  Intake (validate/scan/hash/promote) was
split out of the FastAPI request thread into its own Celery task
(`kronos.process_intake`) after the original synchronous version left
evidence orphaned in `SCANNING`/`HASHING` when an unanticipated exception hit
the request thread — see `EvidenceIntakeService.start_intake()`'s docstring
in `src/application/evidence_intake.py` for the full account.  This document
describes the **current** async-all-the-way-down pipeline.
**Design authority:** This document + `Project_Specifications.md`

---

## Guiding Principle: Autonomous after Upload Confirmation

Once a user uploads a file to MinIO via a presigned URL and calls
`POST /api/evidence/upload/finalize/{id}`, **every subsequent step —
including validation, AV scan, and hashing, not just parsing — is triggered
by the server, never by the client.**  This is non-negotiable because:

- Parsing must be deterministic and reproducible without client cooperation.
- Chain-of-custody requires every state transition to be audited by the server.
- Client-triggered transitions create race conditions and allow users to skip
  security steps (scan, hash verification, WORM promotion).

`finalize_upload` itself now does almost no work: it does one cheap
existence check, persists the client-declared hash, and hands off to Celery.
See Phase 2 below.

---

## Evidence Lifecycle (FSM)

```
UPLOADING ──► SCANNING ──► HASHING ──► RECEIVED ──► PARSING ──► COMPLETE
                │               │           │             │
                └───────────────┴───────────┴─────────────┴──► ERROR
                                                                  │  │
                                                    (retry-intake)│  │(retry-parse)
                                                          SCANNING◄┘  └►PARSING

Any non-terminal state ──► PURGED   (DELETE /api/evidence/{id}, soft-delete)
```

| State     | Who sets it                   | Description |
|-----------|-------------------------------|-------------|
| UPLOADING | `EvidenceIntakeService.request_upload()` | Record created; client is PUT-ing to MinIO. |
| SCANNING  | `EvidenceIntakeService._run_validation()` (runs inside the `kronos.process_intake` **Celery task**, not the request thread) | Magic-byte + extension check, ClamAV scan in progress. |
| HASHING   | `EvidenceIntakeService._run_hash()` (same Celery task) | SHA-256 + MD5 computed; client hash compared. |
| RECEIVED  | `EvidenceIntakeService._promote()` (same Celery task) | Promoted to evidence WORM bucket; `dispatch_parse` enqueued. |
| PARSING   | Celery `dispatch_parse` → `start_parsing()` | Parser detected; Celery task executing. |
| COMPLETE  | Celery `parse_artefact_*` → `execute_parse()` | Records indexed to OpenSearch. |
| ERROR     | Any failing step | Terminal for reasons like `validation_failed`/`infected:*`/`hash_mismatch`/`no_parser_found`; **retryable** for connectivity-style reasons via `retry-intake` (re-enters SCANNING) or `retry-parse` (re-enters PARSING) — see `src/domain/evidence.py`'s `is_retryable_error_reason` / `is_parse_stage_error_reason`. |
| PURGED    | `EvidenceIntakeService.delete_evidence()` | Terminal soft-delete; reachable from every other state. The metadata record is removed, the WORM object itself is retained until its MinIO Object Lock retention expires. Not part of the autonomous ingest flow — triggered by `DELETE /api/evidence/{id}` (ORG_ADMIN or case-lead-of-case, + step-up). |

Transitions are enforced by `_VALID_TRANSITIONS` / `EvidenceState.transition_to()`
in `src/domain/evidence.py`.  **No code may skip a transition or set state
out-of-order.**  `ERROR` is reachable from any non-terminal state and can
itself transition back to `SCANNING` (intake-stage retry) or `PARSING`
(parse-stage retry) — these are the only two re-entry points, chosen per the
failed step, not a generic "retry" edge.

---

## User Interactions

Users interact with evidence at these points:

| Interaction | API | Actor |
|-------------|-----|-------|
| Initiate upload | `POST /api/evidence/upload/request` | ORG_ADMIN / CASE_LEAD / ANALYST |
| PUT file to MinIO | Presigned URL (direct) | Same |
| Finalize upload | `POST /api/evidence/upload/finalize/{id}` | Same — returns **202 Accepted** with evidence still in `UPLOADING`; this is a hand-off, not a completion |
| Retry intake-stage error | `POST /api/evidence/{id}/retry-intake` | Same — only offered for retryable, intake-stage `error_reason`s |
| Retry parse-stage error | `POST /api/evidence/{id}/retry-parse` | Same — only offered for retryable, parse-stage `error_reason`s |
| View evidence list | `GET /api/cases/{id}/evidence` | Any authenticated member |
| Real-time status | SSE `GET /api/sse/cases/{id}/evidence` | Any authenticated member |
| Delete evidence | `DELETE /api/evidence/{id}` | ORG_ADMIN, or CASE_LEAD of the case, + step-up ticket |
| **Manual re-trigger** | `POST /api/evidence/parse/start/{id}` | **ORG_ADMIN only — recovery use** |

All transitions from `SCANNING` onward are **server-initiated**, running
inside Celery tasks, never on the FastAPI request thread.  The
`POST /api/evidence/parse/start/{id}` endpoint exists only for operational
recovery (stuck `RECEIVED` after a broker outage) and requires `ORG_ADMIN`.
`retry-intake`/`retry-parse` are the normal, non-admin recovery path for
`ERROR` evidence with a retryable reason; the route re-validates the reason
server-side rather than trusting client-side gating.

---

## Full Pipeline Detail

### Phase 1: Client Upload

```
Client                      Backend (FastAPI)               MinIO
  │                              │                             │
  │── POST /upload/request ──────►│                             │
  │   {filename, contentType,    │  create Evidence(UPLOADING)  │
  │    sizeBytes, caseId}        │  request presigned URL ─────►│
  │                              │◄───────────────── presigned │
  │◄─ {evidenceId, presignedUrl} │                             │
  │                              │                             │
  │── PUT <presignedUrl> ────────────────────────────────────►│
  │   (file bytes direct to MinIO)                             │
  │◄──────────────────────────────────────────────── 200 OK   │
  │                              │                             │
  │── POST /upload/finalize ─────►│                             │
  │   {client_sha256}            │  (see Phase 2 — hand-off,   │
  │◄── 202 Accepted (UPLOADING) ─┤   not synchronous work)     │
```

### Phase 2a: `finalize_upload` (FastAPI, lightweight hand-off only)

`EvidenceIntakeService.start_intake()` — called directly from the
`finalize_upload` route — does **not** run validate/scan/hash/promote
itself.  It does exactly one cheap, synchronous check and then hands off:

1. Loads the evidence record; requires it to be in `UPLOADING`.
2. `object_exists(quarantine_key, bucket="quarantine")` — a MinIO `HEAD`,
   not a `GET` — confirms the client's PUT actually landed. If not yet
   visible, raises `ValidationError` (HTTP 422) **without touching FSM
   state**, so the client can simply call `finalize` again shortly; nothing
   needs to be undone because nothing was ever committed.
3. Persists `client_declared_sha256` on the evidence row (so the Celery task
   below doesn't need it re-supplied).
4. Enqueues `kronos.process_intake` on Celery queue `q.intake` via
   `task_queue.enqueue_intake()`, and returns immediately.
5. If no `task_queue` is configured (e.g. a test double with Celery not
   wired up), falls back to running `process_intake` inline synchronously —
   this is a dev/test fallback, not the production path.

The route returns **HTTP 202 Accepted** with the evidence still in
`UPLOADING` state. The client does **not** poll or trigger anything
further — it subscribes to SSE for the `RECEIVED`/`ERROR` transition that
follows.

### Phase 2b: `process_intake` (Celery `q.intake`, fully autonomous)

`EvidenceIntakeService.process_intake()` — run from the
`kronos.process_intake` Celery task (`max_retries=3`,
`default_retry_delay=30`s) — performs the actual validate → scan → hash →
promote sequence, off the FastAPI thread entirely:

1. **Validate** (`_run_validation`): Sets state → `SCANNING`. Reads first
   64 KB from the quarantine bucket (large enough for magic-byte detection
   and for the ZIP-central-directory check used by the disguised-JAR
   validator); checks file extension allowlist and magic bytes. Failure →
   `ERROR("validation_failed")`, terminal (not retried).

2. **AV Scan** (`_run_scan`): Streams the file through `AntivirusScanner`
   (ClamAV in production, `NoOpScanner` in tests), enforcing the real
   uploaded byte count against `max_upload_bytes` as it streams. Infected →
   `ERROR("infected:<threat>")`, terminal. Oversized → `ERROR("size_limit_exceeded")`,
   terminal.

3. **Hash** (`_run_hash`): Sets state → `HASHING`. SHA-256 + MD5 computed
   over the full stream; compared against the client-provided
   `client_sha256`. Mismatch → `ERROR("hash_mismatch")`, terminal. On
   success, also RFC 3161-timestamps the hash if a `timestamp_service` is
   configured (a TSA outage is logged, not fatal — the hash itself is
   already verified).

4. **Promote** (`_promote`): Sets state → `RECEIVED`. Copies the object
   from the quarantine bucket to the WORM evidence bucket with Object Lock,
   deletes the quarantine copy, and stamps `object_lock_until` (now +
   `default_retention_days`, 365 by default per `Project_Specifications.md`).

5. **Auto-dispatch** (last step of `_promote`): Calls
   `task_queue.enqueue_dispatch(evidence_id, tenant)` to enqueue
   `kronos.dispatch_parse`. If the broker is unavailable the warning is
   logged and evidence stays safely in `RECEIVED` — the
   `auto_dispatch_received` beat task (hourly at :15) recovers it.

**Failure handling at the task level:** a `ValidationError` from any step
above means a terminal, already-categorized `ERROR` — the Celery task
returns `"ERROR"` without retrying (retrying the same bytes can never
produce a different verdict). Any other, unanticipated exception (storage
or scanner connectivity, etc.) is caught, and if the evidence isn't already
in a terminal state it's flipped to `ERROR("intake_failed:<ExceptionType>")`
before the Celery task itself retries (`self.retry()`, up to 3 attempts,
30s apart) — this closes the original bug where an unhandled exception on
the request thread left evidence permanently stuck in `SCANNING`/`HASHING`
with no sweeper watching those states. `ERROR` is itself a valid retry
re-entry point (`ERROR → SCANNING`), so both a Celery-level retry and a
client-triggered `retry-intake` call simply re-run the whole sequence
against the same still-quarantined object.

### Phase 3: Celery Parse Pipeline (fully autonomous)

```
[Celery q.intake]      [Celery q.index]         [Celery q.parse.fast / q.parse.plaso]
process_intake                │                              │
  └─► RECEIVED, enqueues ────►│                              │
                        dispatch_parse                       │
                          └─► start_parsing()                │
                                detect parser                │
                                set PARSING                  │
                                enqueue ───────────────────►│
                                                      parse_artefact_fast / parse_artefact_heavy
                                                        execute_parse()
                                                          stream records
                                                          index to OpenSearch
                                                          set COMPLETE
                                                          ──► finalize_evidence.apply_async(...)  [q.index]
                                                                (INGEST_COMPLETED audit event)
```

**Task chain:**

| Task | Queue | Retries | Responsibility |
|------|-------|---------|----------------|
| `kronos.process_intake` | `q.intake` | 3 (30s delay) | Validate, AV scan, hash, promote → `RECEIVED`; auto-enqueues `dispatch_parse` |
| `kronos.dispatch_parse` | `q.index` | 0 | Detect parser, transition → `PARSING`, route to fast/heavy |
| `kronos.parse_artefact_fast` | `q.parse.fast` | 3 (30s delay) | EVTX / CloudTrail / Nginx parsing (gVisor-sandboxed) |
| `kronos.parse_artefact_heavy` | `q.parse.plaso` | 2 (120s delay), 10 min hard limit | Plaso in Firecracker microVM |
| `kronos.finalize_evidence` | `q.index` | 3 | Emit `INGEST_COMPLETED` audit event — dispatched via `apply_async()` from `parse_artefact_fast`/`parse_artefact_heavy` on success, not a static Celery `chain()` |

`parse_artefact_fast`/`parse_artefact_heavy` only flip evidence to the
terminal `ERROR` state on their **final** retry attempt
(`self.request.retries >= self.max_retries`) — an earlier failure just
raises `self.retry()` and lets Celery reschedule, so a transient parse
failure doesn't need a manual `retry-parse` call.

### Phase 4: Indexing

`ParsingOrchestrationService.execute_parse()` streams records from the parser
as `AsyncIterator[TimelineRecord]`, passes them through `_annotate_records()`
(assigns deterministic `document_id`, org alias), then feeds them to
`TimelineIngestionService.ingest_records()` which bulk-indexes to OpenSearch.

Records use ECS schema with `kronos.*` provenance fields.  `document_id` is
`SHA1(evidence_id:parser_name:index)` for idempotent re-indexing.

---

## Orphan Recovery

| Beat task | Schedule | Threshold | Purpose |
|-----------|----------|-----------|---------|
| `abort_orphan_uploads` | Hourly :00 | `UPLOADING` > 2h | → `ERROR("upload_timeout")` |
| `auto_dispatch_received` | Hourly :15 | `RECEIVED` > 5min | Re-enqueue `dispatch_parse` |
| `abort_orphan_parses` | Hourly :30 | `PARSING` > 3h | → `ERROR("parse_timeout")` |
| `abort_orphan_intake` | Hourly :45 | `SCANNING` or `HASHING` > 30min | → `ERROR("intake_timeout")` — defense-in-depth for a worker crash mid-task (OOM, node lost) that `process_intake`'s own exception handling can't catch, since no exception is ever raised in that case |
| `anchor_audit_log` | Daily 02:00 UTC | — | Merkle-root daily events + TSA anchor |

`auto_dispatch_received` is the recovery mechanism for the `RECEIVED →
PARSING` handoff specifically (broker unavailable during `_promote()`).
`abort_orphan_intake` is the newer counterpart covering the
`process_intake` Celery task itself dying without raising — added when
intake moved off the request thread, since `process_intake`'s own
try/except can only catch exceptions that are actually raised in-process.

---

## Security Properties

- **No client-controlled transitions**: the FSM is enforced server-side
  only, and as of the `process_intake` split, entirely inside Celery tasks
  — not even `finalize_upload`'s request thread touches `SCANNING`/`HASHING`/`RECEIVED`.
- **Hash integrity**: SHA-256 is computed server-side and compared to the
  client-provided hash.  Mismatch blocks promotion.
- **AV gate**: ClamAV scan is mandatory before `RECEIVED` state.
- **WORM enforcement**: evidence bucket uses MinIO Object Lock (Compliance
  mode); even the platform cannot delete objects before retention expiry.
- **Audit immutability**: every transition writes an append-only audit event
  with SHA-256 hash chain.  Daily Merkle root is RFC 3161-anchored.
- **Tenant isolation**: `org_id` is extracted from the verified JWT claim, not
  from user-supplied input.  All DB queries include `org_id` filter.
- **parse/start is admin-gated**: the manual re-trigger endpoint requires
  `ORG_ADMIN` role.
- **retry-intake / retry-parse are reason-gated**: both routes re-check
  `is_retryable_error_reason()` (and route to the correct stage via
  `is_parse_stage_error_reason()`) server-side, so a client can't retry a
  terminal verdict (e.g. `infected:*`, `hash_mismatch`) by calling the
  endpoint directly even if the UI's own gating is bypassed.

---

## What NOT to Do

- **Never call `parse/start` from the frontend** on normal upload flow.
  The backend auto-dispatches after `finalize` via `process_intake` → `dispatch_parse`.
- **Never skip validation or scan** by changing the FSM transitions.
- **Never call `start_parsing()` or `process_intake()` directly** from a
  client-facing API without going through the designated routes
  (`finalize_upload`, `retry-intake`, `retry-parse`, admin-only
  `parse/start`) — this would allow any user to re-trigger parsing or
  intake outside the audited, role-gated paths.
- **Never expose `stream_all_by_state`** in request handlers — it crosses org
  boundaries and is reserved for Celery beat tasks
  (`abort_orphan_uploads`, `abort_orphan_intake`, `abort_orphan_parses`,
  `auto_dispatch_received`).
- **Never assume `finalize_upload` did the validate/scan/hash/promote work
  synchronously** — it returns 202 with evidence still in `UPLOADING`; that
  work happens asynchronously in `kronos.process_intake`. Any caller
  (including tests) needing the post-intake state must wait for the
  `RECEIVED`/`ERROR` transition (SSE in production, direct Celery task
  execution in test fixtures), not assume it's done when the HTTP call returns.
