# KronOS Evidence Ingestion Pipeline

**Status:** Implemented (Phases 1–5)  
**Design authority:** This document + `Project_Specifications.md`

---

## Guiding Principle: Autonomous after Upload

Once a user uploads a file to MinIO via a presigned URL, **the entire
ingestion pipeline is autonomous and backend-driven**.  The client never
triggers parsing, indexing, or any subsequent step.  This is non-negotiable
because:

- Parsing must be deterministic and reproducible without client cooperation.
- Chain-of-custody requires every state transition to be audited by the server.
- Client-triggered transitions create race conditions and allow users to skip
  security steps (scan, hash verification, WORM promotion).

---

## Evidence Lifecycle (FSM)

```
UPLOADING ──► SCANNING ──► HASHING ──► RECEIVED ──► PARSING ──► COMPLETE
                │               │           │             │
                └───────────────┴───────────┴─────────────┴──► ERROR
```

| State     | Who sets it                   | Description |
|-----------|-------------------------------|-------------|
| UPLOADING | `EvidenceIntakeService.request_upload()` | Record created; client is PUT-ing to MinIO. |
| SCANNING  | `EvidenceIntakeService._run_validation()` | Magic-byte + extension check, ClamAV scan in progress. |
| HASHING   | `EvidenceIntakeService._run_hash()` | SHA-256 + MD5 computed; client hash compared. |
| RECEIVED  | `EvidenceIntakeService._promote()` | Promoted to evidence WORM bucket; parse dispatch enqueued. |
| PARSING   | Celery `dispatch_parse` → `start_parsing()` | Parser detected; Celery task executing. |
| COMPLETE  | Celery `parse_artefact_*` → `execute_parse()` | Records indexed to OpenSearch. |
| ERROR     | Any failing step | Terminal. Error reason stored. Requires admin re-upload. |

Transitions are enforced by the `EvidenceState` FSM in `src/domain/evidence.py`.
**No code may skip a transition or set state out-of-order.**

---

## User Interactions

Users interact with evidence only at two points:

| Interaction | API | Actor |
|-------------|-----|-------|
| Initiate upload | `POST /api/evidence/upload/request` | Any authenticated member |
| PUT file to MinIO | Presigned URL (direct) | Any authenticated member |
| Finalize upload | `POST /api/evidence/upload/finalize/{id}` | Any authenticated member |
| View evidence list | `GET /api/cases/{id}/evidence` | Any authenticated member |
| Real-time status | SSE `GET /api/sse/cases/{id}/evidence` | Any authenticated member |
| Delete evidence | `DELETE /api/evidence/{id}` | ORG_ADMIN + step-up ticket |
| **Manual re-trigger** | `POST /api/evidence/parse/start/{id}` | **ORG_ADMIN only — recovery use** |

All transitions from SCANNING onward are **server-initiated**.  The
`POST /api/evidence/parse/start/{id}` endpoint exists only for operational
recovery (stuck RECEIVED after a broker outage) and requires `ORG_ADMIN`.

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
  │   {client_sha256}            │                             │
```

### Phase 2: Server-Side Finalization (synchronous, in-request)

`EvidenceIntakeService.finalize_upload()` runs these steps serially.  Any
failure sets state = ERROR and raises an exception (HTTP 422/500):

1. **Validate** (`_run_validation`): Reads first 8 KB from quarantine bucket;
   checks file extension allowlist and magic bytes.  Sets state → SCANNING.

2. **AV Scan** (`_run_scan`): Streams file through `AntivirusScanner`
   (ClamAV in production, `NoOpScanner` in tests).  If infected → ERROR.

3. **Hash** (`_run_hash`): SHA-256 + MD5 computed over full stream.  Compared
   against client-provided `client_sha256`.  Mismatch → ERROR.  Sets state
   → HASHING.

4. **Promote** (`_promote`): Copies object from quarantine bucket to WORM
   evidence bucket with Object Lock.  Deletes quarantine copy.  Sets state
   → RECEIVED.

5. **Auto-dispatch** (in `_promote`): Calls
   `task_queue.enqueue_dispatch(evidence_id, tenant)`.  If the broker is
   unavailable the warning is logged and the `auto_dispatch_received` beat
   task (runs every hour at :15) will recover.

The API response returns the evidence in RECEIVED state.  The client does
**not** poll or trigger anything further — it subscribes to SSE for updates.

### Phase 3: Celery Pipeline (fully autonomous)

```
[Celery q.index]         [Celery q.parse.fast / q.parse.plaso]
      │                              │
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
                                  ──► finalize_evidence (audit)
```

**Task chain:**

| Task | Queue | Retries | Responsibility |
|------|-------|---------|----------------|
| `kronos.dispatch_parse` | `q.index` | 0 | Detect parser, transition → PARSING, route to fast/heavy |
| `kronos.parse_artefact_fast` | `q.parse.fast` | 3 (30s delay) | EVTX / CloudTrail / Nginx parsing |
| `kronos.parse_artefact_heavy` | `q.parse.plaso` | 2 (120s delay) | Plaso in Firecracker (10 min limit) |
| `kronos.finalize_evidence` | `q.index` | 3 | Emit `INGEST_COMPLETED` audit event |

### Phase 4: Indexing

`ParsingOrchestrationService.execute_parse()` streams records from the parser
as `AsyncIterator[TimelineRecord]`, passes them through `_annotate_records()`
(assigns deterministic `document_id`, org alias), then feeds them to
`TimelineIngestionService.ingest_records()` which bulk-indexes to OpenSearch.

Records use ECS schema with `kronos.*` provenance fields.  `document_id` is
`SHA1(evidence_id:parser_name:index)` for idempotent re-indexing.

---

## Orphan Recovery

| Beat task | Schedule | Purpose |
|-----------|----------|---------|
| `abort_orphan_uploads` | Hourly :00 | Evidence stuck in UPLOADING >2h → ERROR |
| `auto_dispatch_received` | Hourly :15 | Evidence stuck in RECEIVED >5min → re-enqueue dispatch |
| `abort_orphan_parses` | Hourly :30 | Evidence stuck in PARSING >3h → ERROR |
| `anchor_audit_log` | Daily 02:00 UTC | Merkle-root daily events + TSA anchor |

The `auto_dispatch_received` task is the primary recovery mechanism: if the
broker was temporarily unavailable during `_promote()`, the next scheduled
run will pick up the evidence and re-enqueue `dispatch_parse`.

---

## Security Properties

- **No client-controlled transitions**: the FSM is enforced server-side only.
- **Hash integrity**: SHA-256 is computed server-side and compared to the
  client-provided hash.  Mismatch blocks promotion.
- **AV gate**: ClamAV scan is mandatory before RECEIVED state.
- **WORM enforcement**: evidence bucket uses MinIO Object Lock (Compliance
  mode); even the platform cannot delete objects before retention expiry.
- **Audit immutability**: every transition writes an append-only audit event
  with SHA-256 hash chain.  Daily Merkle root is RFC 3161-anchored.
- **Tenant isolation**: `org_id` is extracted from the verified JWT claim, not
  from user-supplied input.  All DB queries include `org_id` filter.
- **parse/start is admin-gated**: the re-trigger endpoint requires `ORG_ADMIN`
  role to prevent any non-admin from influencing parsing state.

---

## What NOT to Do

- **Never call `parse/start` from the frontend** on normal upload flow.
  The backend auto-dispatches after `finalize`.
- **Never skip validation or scan** by changing the FSM transitions.
- **Never call `start_parsing()` directly** from a client-facing API without
  the `ORG_ADMIN` check — this would allow any user to re-trigger parsing.
- **Never expose `stream_all_by_state`** in request handlers — it crosses org
  boundaries and is reserved for Celery system tasks.
