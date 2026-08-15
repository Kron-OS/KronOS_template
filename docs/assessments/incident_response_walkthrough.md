# Incident-Response Walkthrough Assessment (Task #14)

**Date:** 2026-08-15
**Scope:** Trace one concrete, plausible SOC incident through KronOS's real,
current code on `feat/nextgen-soc-cert-platform` (post Milestone V2/V5/V8,
per `docs/GAP_AUDIT_2026-08.md`). Code-reading assessment only — no
containers were started; one route table was grepped to strengthen a
finding per the task's own allowance.

---

## §0 The scenario

A SOC analyst is handling a suspected compromised Windows workstation
(`WKS-FIN-042`) at a KronOS tenant (`org_alias = acme-soc`):

1. IR pulls a triage EVTX export (`Security.evtx`) from the host and
   uploads it to an existing KronOS case as evidence, expecting KronOS's
   autonomous pipeline to validate, hash, parse, and index it into a
   searchable timeline.
2. Independently, the org's Wazuh manager — connected via KronOS's Q2
   webhook-push connector — has an `wazuh-integratord` real-time alert for
   suspicious PowerShell activity on the same host, timestamped minutes
   before the analyst even started the upload.
3. The analyst expects to see a `Detection` for that Wazuh alert (or at
   least a correlated timeline event) in the KronOS UI, triage it, and
   fire a SOAR playbook step that pushes the confirmed detection to the
   org's Splunk instance (`SplunkHecSink`, R2/V6).
4. At case close-out, the analyst needs a court-admissible chain-of-custody
   report they can hand to counsel/regulators, generated via
   `kronos-attest case-report`.

This is the exact shape the task's four numbered steps describe; each is
traced below against real files, not the docs' own description of them.

---

## §1 Step-by-step trace through the real code

### 1. Evidence intake (EVTX upload)

The real pipeline is **not** what `docs/ingestion-pipeline.md` currently
describes. That doc (§"Phase 2: Server-Side Finalization (synchronous,
in-request)", lines 86–111) says `finalize_upload` runs
validate→scan→hash→promote synchronously on the request thread. The real
code has since split this into a two-phase, fully-async design:

- `POST /api/evidence/upload/request` → `EvidenceIntakeService.request_upload()`
  (`src/application/evidence_intake.py:119-206`) creates `Evidence(UPLOADING)`
  and a presigned MinIO PUT URL. Quota-gated first (`StorageQuotaExceededError`
  → HTTP 413, `src/external/routes/evidence.py:148-160`).
- Client PUTs the file directly to MinIO, then calls
  `POST /api/evidence/upload/finalize/{id}`
  (`src/external/routes/evidence.py:178-222`), which now only calls
  `EvidenceIntakeService.start_intake()` (`evidence_intake.py:208-276`) — a
  cheap, synchronous existence check (`storage.object_exists`, a HEAD) that
  enqueues a **Celery task**, `kronos.process_intake`
  (`src/external/celery_app.py:168-209`), and returns **HTTP 202** with
  evidence still in `UPLOADING`.
- `process_intake` (Celery, `q.intake` queue) runs
  `EvidenceIntakeService.process_intake()` (`evidence_intake.py:278-359`),
  which is what actually does validate → scan → hash → promote
  (`_run_validation`/`_run_scan`/`_run_hash`/`_promote`,
  `evidence_intake.py:379-543,762-805`) and transitions
  `UPLOADING → SCANNING → HASHING → RECEIVED`. `_promote()`
  (`evidence_intake.py:762-805`) is the one that calls
  `task_queue.enqueue_dispatch()` at the end, exactly matching CLAUDE.md
  §E's contract.
- `dispatch_parse` (`celery_app.py:217-241`) → `start_parsing()`
  (`src/application/parsing_orchestration.py:80-209`) detects the parser
  via `ParserRegistry`, transitions `RECEIVED → PARSING`, enqueues
  `parse_artefact_fast` (EVTX is FAST-path, evtx-rs) on `q.parse.fast`.
- `parse_artefact_fast` (`celery_app.py:249-296`) → `execute_parse()`
  (`parsing_orchestration.py:278-489`) streams `TimelineRecord`s from the
  EVTX parser, feeds them through enrichment (if configured) and
  `TimelineIngestionService.ingest_records()`, transitions `PARSING →
  COMPLETE`, chains `finalize_evidence` which emits the `INGEST_COMPLETED`
  audit event (`celery_app.py:355-392`).

Every FSM transition is audited (`AuditLogService.log`/`audit_context`
calls throughout `evidence_intake.py`/`parsing_orchestration.py`), matching
CLAUDE.md §A.2. `EvidenceState._VALID_TRANSITIONS`
(`src/domain/evidence.py:22-39`) enforces the FSM; `ERROR` is a legitimate
re-entry point with two different, correctly-distinct retry endpoints
(`/retry-intake` vs `/retry-parse`, `src/external/routes/evidence.py:225-338`)
depending on which stage failed
(`is_parse_stage_error_reason`/`is_retryable_error_reason`,
`src/domain/evidence.py:54-86`).

**What a real analyst experiences:** upload → finalize returns 202 almost
immediately with state still `UPLOADING` — the frontend's only job from
here is to listen on SSE (`GET /api/sse/cases/{id}/evidence`, CLAUDE.md
§E.2) for the RECEIVED/PARSING/COMPLETE/ERROR transitions. This is
correctly non-blocking and matches the "autonomous after upload" contract.
The one real friction: if `q.intake` is slow/backed up, the analyst sees
evidence sit in `UPLOADING` with no client-visible distinction between
"still validating" and "silently stuck" beyond the SSE stream itself — the
`abort_orphan_uploads` (2h) and `abort_orphan_intake` (30min) beat sweeps
(`celery_app.py:400-492`) are the real backstop, but a 30-minute worst-case
silent stall before an ERROR appears is a long time mid-incident.

### 2. Parallel Wazuh signal — does it reach the same Detection pipeline?

**No — and further, the answer is stronger than "two separate paths": as
currently wired, the Wazuh path in production never reaches the
`Detection` table at all, and neither does the SA-monitor path this task
assumed was the working baseline.**

Trace:

- Wazuh's `wazuh-integratord` POSTs to
  `POST /api/integrations/push/{source_type}`
  (`src/external/routes/integration_source_push.py:48-100`), authenticated
  by `InboundSourceAuthenticator` (API-key, not mTLS —
  `src/external/middleware/integration_source_auth.py`), org/source
  identity coming exclusively from the verified credential
  (`identity = await authenticator.authenticate(request.headers)`,
  line 72), never the request body — correct tenant-isolation invariant,
  confirmed clean by the Gap Audit's own §0.5 security pass.
- The route calls `IntegrationSourceIngestService.ingest_push()`
  (`src/application/integration_source_ingest.py:96-122`), which dedups
  (SHA-256 content hash) and produces the raw event onto a **Redis
  Stream** (`StreamIngestAdapter.produce`, line 236) keyed
  `kronos:stream:{org_id}:{source_id}`. Nothing here creates a
  `Detection`, a `TimelineRecord`, or writes to OpenSearch. This is the
  end of the line for a webhook push by itself.
- For that Redis Stream entry to become a searchable OpenSearch document,
  two more real stages must run: `BatchSealingService.seal_pending()`
  (WORM-manifest + TSA-anchor + Postgres row, D3) and
  `StreamNormalizationService.normalize_batch()`
  (`src/application/stream_normalization.py:103-204`, which builds
  `TimelineRecord`s and calls `TimelineIngestionService.ingest_stream_records`).
  **Neither has any scheduled or route-triggered caller anywhere in
  `src/`.** Confirmed by grep: `normalize_batch(` appears only in its own
  definition, its own docstring, one unit test, and four `poc/*/run_poc.py`
  scripts — zero hits in `src/external/celery_app.py` or any route.
  `get_batch_sealing_service()`'s own docstring
  (`src/external/dependencies.py:449-469`) says this outright: "Real
  scheduled invocation (a beat task calling `seal_pending()` per
  registered (org, source) on an interval) is deliberately not wired
  here." `StreamNormalizationService`'s own module docstring says the same
  for itself (lines 20-24).
- Even if that gap were closed and the Wazuh alert did land as a
  `TimelineRecord` in a stream-sourced OpenSearch index, it still would
  not automatically become a `Detection`: `Detection` rows are created
  exclusively by `DetectionSyncService.sync_org_findings()`
  (`src/application/detection_sync.py:75`), which mirrors real OpenSearch
  Security Analytics **findings** (a separate, SA-monitor-driven
  mechanism) into KronOS's own audited `Detection` table
  (`src/domain/detection.py`). Grepping the whole of `src/` for
  `sync_org_findings(` shows exactly one real call site outside its own
  class and docstrings: `src/external/dependencies.py:1084`, inside
  `get_detection_sync_service()` — a FastAPI dependency **that is never
  imported or referenced by any route file** (confirmed: `grep -rn
  get_detection_sync_service src/external/routes/*.py` returns nothing;
  `celery_app.py`'s six-plus beat tasks contain no detection-sync task
  either). This exact gap is already known and documented — M2's own
  STATUS note in `docs/NEXTGEN_SOC_ROADMAP.md:494-495` calls it out
  verbatim: *"Known, reported (not fixed) gap: no automatic trigger for
  `DetectionSyncService` exists yet (no route or beat task calls it) —
  populating real Detection rows in normal operation... remains open
  follow-up work."* That was written 2026-07-31 and is still true today;
  none of the V-series gap-closing items (V1–V10) touched it.

So the honest answer to the task's own question ("do the Q1–Q4
`IntegrationSource` connectors feed the SAME Detection pipeline SA-monitor
detections use, or are they two structurally separate paths?") is: **they
are two separate paths, and as deployed today, *neither* path
autonomously produces a `Detection` row without a human or a PoC script
manually invoking `seal_pending()` → `normalize_batch()` → (for the SA
path) `sync_org_findings()` in sequence.** `poc/l3_chain_collector_to_detect/`
proves the full chain *works* end to end (35/35 checks) — but proves it by
manually driving each stage, exactly as its own README says: *"nothing
schedules `seal_pending()`/`normalize_batch()`/`sync_org_findings()`
automatically in production yet (no beat task) — this PoC drives each
stage manually, proving the mechanism, not automatic invocation."*

**What a real analyst experiences:** the Wazuh alert is durably and
safely captured (Redis Stream → eventually a WORM-sealed batch, once
sealing runs), which is a genuinely good custody property. But it never
appears as a `Detection` in `GET /api/detections`
(`src/external/routes/detections.py:94-133`, which only ever reads
`DetectionRepository`) and never appears as a searchable timeline event
either, unless an operator has manually run the missing pipeline stages —
which no runbook, admin route, or CLI in this repo currently exposes. An
analyst working a real incident today would see **zero** correlated
signal from Wazuh in the KronOS UI, with no error or indication that
anything is wrong — the pipeline is simply silent, not failed.

### 3. Triage + SOAR response

`DetectionTriageService.transition()`
(`src/application/detection_triage.py:33-93`) is real, correctly-audited
(both success and rejection paths logged,
`AuditEventType.DETECTION_TRIAGE_TRANSITIONED`/`_FAILED`), and reachable
via `POST /api/detections/{id}/triage`
(`src/external/routes/detections.py:154-185`), gated to
org_admin/case_lead/analyst. **This route works correctly** — but per §1.2
above, it can only ever act on a `Detection` that already exists, and
nothing in production creates one autonomously.

For the SOAR step: `SyncDetectionToSiemAction`
(`src/application/sync_detection_to_siem_action.py`) is real, and — per
Milestone V2 (`docs/GAP_AUDIT_2026-08.md` V2 STATUS, item (a)) — is now
correctly registered into a real `PlaybookActionRegistry` via
`get_playbook_action_registry()`/`get_playbook_execution_service()`
(`src/external/dependencies.py`, added in V2). That closed the original
Gap Audit P1-1 finding ("zero callers of `DetectionSinkPushService`").

**However, confirmed by direct grep of this repo right now
(`grep -rn "PlaybookExecutionService" src/external/routes/` and
`grep -rn "playbook" src/external/routes/*.py -i`, both zero hits): there
is still no HTTP route anywhere that calls
`PlaybookExecutionService.execute()`.** `src/external/routes/` contains
exactly 11 route files (`admin.py`, `audit.py`, `auth.py`, `cases.py`,
`collector_ingest.py`, `detections.py`, `evidence.py`,
`integration_source_push.py`, `sse.py`, `step_up.py` — no `playbook.py`),
none of which reference `Playbook`, `PlaybookExecutionService`, or
`PlaybookActionRegistry`. This is exactly what V2's own STATUS note
already stated honestly: *"No new HTTP route was added to actually
dispatch a Playbook from a real request — that gap... is real, larger
than this item's own scope, and not closed here."* That gap remains open
as of this assessment — confirmed live, not just quoted from the doc.

**What a real analyst experiences:** even in a world where a `Detection`
existed to triage, there is no button, API call, or admin action anywhere
in the shipped system that would fire `SyncDetectionToSiemAction` or any
other `PlaybookAction`. The playbook engine, its action registry, and the
Splunk/CEF/Sentinel sinks are all real, individually tested, and wired
into DI — but the whole subsystem is currently reachable only from a test
file or a PoC script that constructs `PlaybookExecutionService` directly.
A real analyst cannot trigger a SOAR response from the KronOS UI or API
today, full stop.

### 4. Report / close-out

`kronos_attest/report.py`'s `AttestationReport.case_report()`
(`kronos_attest/report.py:71-85`) confirmed, by direct read, to still take
`events: list[dict[str, Any]]` — an in-memory list the caller must already
have, not anything `case_report()` fetches itself. The CLI wrapper
(`kronos_attest/cli.py`) exposes this via `click.Path(exists=True)`
options (e.g. `--audit-log-path`, line 25) — i.e., **a local JSON file
that must already exist on disk** before the CLI can be invoked. This
confirms the Gap Audit's P2-5 finding (`docs/GAP_AUDIT_2026-08.md:132`) is
still accurate: no live re-read of MinIO/Postgres/TSA at report time.

Tracing the *actual* friction one level further than the Gap Audit did:
there is also **no export mechanism anywhere in this repo** that produces
the JSON file the CLI needs. `src/external/routes/audit.py` exposes only
`GET /api/cases/{case_id}/verify` (a boolean chain-validity check,
`audit.py:58-71`) and `GET /api/merkle-proof/{event_id}` (a single-event
proof, `audit.py:74-150`) — neither returns the full event list a report
needs. A repo-wide search
(`grep -rln "audit_log_path\|export.*audit" scripts/ docs/`, and a `find`
for any `*export*audit*`/`*audit*export*` file) found no export script,
route, or documented procedure anywhere. The only way to actually produce
the JSON `kronos-attest case-report`/`day-report` require today is a
bespoke, undocumented, ad-hoc query against Postgres — something every
prior verified PoC in this codebase (`poc/chain_of_custody/`, etc.) does
manually inside its own throwaway script, never as a reusable, documented
tool.

**What a real analyst experiences:** at the exact moment they need the
platform's flagship "court-admissible chain of custody" deliverable, there
is no supported path from "case is complete" to "here is the report file."
They (or, more realistically, an engineer they escalate to) would need to
hand-write a Postgres query against the audit-log table, shape it into the
schema `case_report()`/`day_report()` expect (`occurred_at`, `case_id`,
`evidence_id`, `event_type`, `details`, etc. — inferred from
`report.py`'s own field accesses, not documented anywhere as a contract),
save it as JSON, and only then run the CLI. This is a real, significant
gap for a platform whose entire value proposition is legal admissibility.

---

## §2 Findings

| # | Finding | File:line | Severity | What would fix it |
|---|---|---|---|---|
| F1 | **`DetectionSyncService.sync_org_findings()` has zero production callers** — no route, no beat task. `Detection` rows (the entity both the SA-monitor path and, transitively, any stream-sourced signal would need) are never created autonomously. Documented as a known gap since 2026-07-31 (`docs/NEXTGEN_SOC_ROADMAP.md:494-495`), still true today. | `src/application/detection_sync.py:75`; `src/external/dependencies.py:1070-1088`; confirmed via `grep -rn get_detection_sync_service src/external/routes/` (zero hits) | **Blocking** | Add a Celery beat task calling `sync_org_findings()` per org on an interval, mirroring `poll_defender_alerts`'s own recently-added pattern (`celery_app.py:660-704`). |
| F2 | **`BatchSealingService.seal_pending()` and `StreamNormalizationService.normalize_batch()` have zero production callers.** A Wazuh (or any continuous-telemetry) alert accepted via the Q2 push route sits durably in a Redis Stream but never becomes a queryable OpenSearch document, let alone a `Detection`, without manual intervention. Documented in both classes' own docstrings as deliberately out of scope, confirmed still unwired by repo-wide grep. | `src/application/stream_normalization.py:20-24`; `src/external/dependencies.py:449-469`; `poc/l3_chain_collector_to_detect/README.md`'s own "Explicitly flagged, not yet done" section | **Blocking** | Add scheduled beat tasks for `seal_pending()` (per registered org/source, on `SealingTriggerPolicy`'s own interval) and `normalize_batch()` (triggered on seal, or polled), per D5/D6's own named follow-up scope. |
| F3 | **No HTTP route anywhere calls `PlaybookExecutionService.execute()`.** The SOAR action registry, `SyncDetectionToSiemAction`, and the three SIEM sinks are all real and DI-wired (V2), but unreachable from any real request. Confirmed live via `grep -rn "playbook" src/external/routes/*.py -i` (zero hits) and `grep -rn PlaybookExecutionService src/external/routes/` (zero hits), not just quoted from V2's own honest note. | `src/application/playbook_execution.py`; `src/application/sync_detection_to_siem_action.py`; `src/external/routes/` (11 files, none playbook-related) | **Blocking** | Add `POST /api/detections/{id}/playbook/{action_name}` or `POST /api/playbooks/{id}/execute`, gated the same way `/triage` is (org_admin/case_lead/analyst). |
| F4 | **No export mechanism exists to produce the JSON file `kronos-attest case-report`/`day-report` require.** `AttestationReport.case_report()` takes `events: list[dict]`; the only audit routes (`audit.py`) expose a chain-verify boolean and a single-event Merkle proof, not a bulk export. No script under `scripts/` does this either (repo-wide search, zero hits). | `kronos_attest/report.py:71-85`; `kronos_attest/cli.py:21-37`; `src/external/routes/audit.py:1-151` | **Significant** (blocking for the report step specifically, but the rest of the workflow completes without it) | Add `GET /api/audit/cases/{case_id}/export` (or an admin CLI backed by a real repository read) that shapes `AuditLogRepository` rows into the JSON contract `case_report()`/`day_report()` already expect, closing Gap Audit P2-5 for real. |
| F5 | **`docs/ingestion-pipeline.md` is stale** — it still describes `finalize_upload` as running validate→scan→hash→promote synchronously in-request ("Phase 2... synchronous, in-request"). The real code (post the `process_intake` Celery split) has `finalize_upload`/`start_intake` do only a cheap existence check and enqueue `kronos.process_intake`, returning 202 with evidence still `UPLOADING`. An analyst or on-call engineer debugging a stuck upload using this doc as ground truth would look in the wrong place (the request thread) for the actual work (a `q.intake` Celery task). | `docs/ingestion-pipeline.md:86-111` vs. `src/application/evidence_intake.py:208-276`, `src/external/celery_app.py:168-209` | **Minor** (doesn't block the workflow, but actively misleads anyone using the doc as their mental model mid-incident) | Update the doc's Phase 2 section to describe the real `start_intake`/`process_intake` split. |
| F6 | **`StaticApiKeyProvisioning` has no real per-(org, source) provisioning route** — confirmed still true (Gap Audit P1-7, unaddressed by V1–V10). An operator cannot actually issue the Wazuh org in this scenario a real API key for the `/api/integrations/push/{source_type}` route through any admin UI/API. | `src/external/middleware/integration_source_auth.py`; `src/external/startup.py` | **Significant** (blocks step 2 of the scenario at the very first hop, before F1/F2 even matter, for any org that hasn't had a key manually seeded) | Build the admin provisioning route/CLI Gap Audit P1-7 already scoped as needing a design decision first. |
| F7 | **Up to ~30 minutes of silent "stuck" evidence** is possible if `q.intake` backs up — the only backstop is the `abort_orphan_intake` beat sweep (30 min) or `abort_orphan_uploads` (2h). No mid-flight status finer than the FSM state itself is exposed over SSE. | `src/external/celery_app.py:448-492` | **Minor** | Acceptable given CLAUDE.md's own autonomous-pipeline design; a "queued, position N" SSE event would be a nice-to-have, not a correctness gap. |

**W1 STATUS (2026-08-15): F1, F2, and F3 are CLOSED, verified live —
table rows above left unmodified as the original point-in-time findings.**
`docs/ASSESSMENT_SYNTHESIS_2026-08.md`'s W1 (P0-W1) shipped all three
missing pieces this table identified:

- **F1** (`sync_org_findings()` had zero production callers): now called
  autonomously by the `kronos.sync_detection_findings` beat task
  (`src/external/celery_app.py`), iterating every real Keycloak org via
  `KeycloakAdminClient.list_organizations()`
  (`src/external/celery_streaming.py`).
- **F2** (`seal_pending()`/`normalize_batch()` had zero production
  callers): now called autonomously by the `kronos.seal_pending_streams`
  beat task, which `apply_async`s `kronos.normalize_stream_batch`
  event-chained right after a real seal (`src/external/celery_app.py`,
  `src/external/celery_streaming.py`).
- **F3** (no HTTP route called `PlaybookExecutionService.execute()`): now
  reachable via `POST /api/detections/{id}/sync-to-siem/{sink}`
  (`src/external/routes/detections.py`).

Real, live proof (not re-derived from memory): `poc/autonomous_detection_
pipeline/run_poc.py`, run end-to-end against the real dev stack (real
Redis, Postgres, MinIO, OpenSearch 2.11.1, Keycloak 26.2) with a real,
throwaway `celery worker`/`celery beat` process pair — no manual
`seal_pending()`/`normalize_batch()`/`sync_org_findings()` call anywhere
in the script below the initial event injection. 24/24 checks passed
across two full trigger rounds, including provenance linkage
(`Detection.matched_document_ids` → real OpenSearch doc →
`kronos.batch_id` matches the real sealed batch) and idempotency (a
second sync cycle creates zero duplicate `Detection` rows), plus the F3
route itself: `POST /api/detections/{id}/sync-to-siem/splunk` returned
200 with `succeeded: true`, and a real stand-in SIEM receiver observed
the pushed event. See `poc/autonomous_detection_pipeline/` for the PoC
and captured run output.

**What worked correctly, worth stating plainly:** the evidence-intake FSM
(§1.1), its audit trail, and its two distinct retry paths are all real,
correct, and match CLAUDE.md §E's contract exactly on direct code
inspection. `DetectionTriageService` and the read/triage `Detections`
routes are real and correctly tenant-isolated. `SyncDetectionToSiemAction`
and the sink push service correctly delegate all audit responsibility and
never fabricate an acknowledgement. Tenant isolation (`org_id` always from
the verified credential, never request bodies) held everywhere checked —
consistent with the Gap Audit's own §0.5 finding of "no new P0 issues in
the six Q/R connectors."

---

## §3 Overall verdict

**Partial — the workflow is not completable end-to-end today using only
what is built and wired.** Evidence intake (step 1) genuinely works
autonomously and is well-engineered. But the scenario breaks at step 2:
even a perfectly-configured Wazuh connector's alert never becomes a
`Detection` in KronOS without a human manually running the equivalent of
`poc/l3_chain_collector_to_detect/`'s three-stage manual pipeline
(`seal_pending()` → `normalize_batch()` → `sync_org_findings()`) — none of
which has a production trigger (F1, F2). Even setting that aside and
assuming a `Detection` somehow exists (e.g., from a manual sync an
operator ran out-of-band), step 3's SOAR response is also unreachable: no
route calls `PlaybookExecutionService.execute()` (F3). Step 4 (report)
degrades gracefully — chain-of-custody data is real and verifiable via
`GET /api/cases/{id}/verify`, but the actual deliverable artifact
(`case_report()`'s output) requires a manual, undocumented data-export
step with no supported tooling (F4).

**The two exact blocking gaps, in the order a real analyst would hit
them:** (1) nothing in production ever calls
`DetectionSyncService.sync_org_findings()` — no `Detection` rows exist
without manual intervention (F1, compounded by F2 for the streaming-source
case specifically); (2) nothing in production ever calls
`PlaybookExecutionService.execute()` — no SOAR action can be triggered
even once a `Detection` exists (F3). Both are honestly documented as known
gaps elsewhere in this repo (`docs/NEXTGEN_SOC_ROADMAP.md:494-495` for F1;
`docs/GAP_AUDIT_2026-08.md`'s V2 STATUS note for F3) — this assessment's
contribution is confirming both are *still* true by direct, current grep
of `src/`, tracing their concrete downstream effect on one realistic
incident end to end, and surfacing F2 (the streaming-ingest half of the
same class of gap) and F4/F6 as compounding blockers along the same path.
