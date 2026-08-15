# Scale/Reliability Review (Task #14)

**Date:** 2026-08-15
**Scope:** KronOS's real capacity assumptions and failure-recovery behavior
against its own stated design goals, evaluated by reading the current code
on `feat/nextgen-soc-cert-platform` — throughput/backpressure, resource
sizing, and application-layer (not datastore-replication) failure recovery.
Code-reading assessment only; no containers were started, no load test was
run against the shared dev stack.

---

## §0 Method

**`docs/POSTGRES_MINIO_HA_RESEARCH.md` (V10) was read in full before any of
this document was written**, per the task brief's explicit instruction not
to duplicate it. V10's own scope is narrow and clearly stated in its title:
whether Postgres/MinIO should be *replicated* (streaming replication /
distributed erasure-coded mode) to survive node/AZ loss and bitrot. This
document does not re-derive any of V10's failure-mode tables (F1–F4, M1–M4),
topology sizing, or verdicts — where Postgres/MinIO come up below (§3), it
is only to note something V10 did not cover (e.g. connection-pool
construction cost under repeated Celery task invocation, or Keycloak's
shared dependency on the same Postgres instance already flagged by V10
§1.4, restated only where directly relevant to a *different* finding here).

**What else was read**, in order: `docs/assessments/incident_response_walkthrough.md`
(the immediately preceding assessment, landed at `bd42ee3`) in full, since
the task brief flagged its finding — that `DetectionSyncService.sync_org_findings()`,
`BatchSealingService.seal_pending()`, and `StreamNormalizationService.normalize_batch()`
have zero production callers — as directly relevant to how this document's
own throughput/backpressure questions must be framed; `src/config.py` in
full; `src/application/collector_ingest.py` in full; `src/external/celery_app.py`
in full (the real `beat_schedule` and every task body); `src/external/celery_defender.py`
in full; `charts/kronos/values.yaml` in full; `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`
§0 in full (the "verified starting facts" table); `src/external/celery_runtime.py`
in full; `src/external/parsers/archive.py` (container-extraction bounds);
`src/external/integration_sources/defender.py` and `generic_poll.py` in
full; `src/application/integration_source_ingest.py`'s `run_poll_cycle`/
`_produce_batch`; `src/application/quota_gate.py` and `src/application/tenant_usage.py`;
`src/application/timeline_ingest.py` (batch/flush constants); and targeted
greps against `src/adapter/opensearch/*_provisioner.py` for the real SA
monitor / AD detector schedule intervals, and against `docker/docker-compose.*.yml`
for OpenSearch heap/discovery settings and Redis DB-number wiring.

**Honesty framing adopted throughout, per the task brief's own instruction**:
because the incident-response walkthrough found the streaming-ingest → Detection
pipeline (`seal_pending()` → `normalize_batch()` → `sync_org_findings()`) has
no production trigger today, this document's own "what happens under
sustained load" analysis of that pipeline is written as "if/when this gets
wired up," not "as currently deployed" — flagged explicitly at each point
it applies, not just here in §0.

---

## §1 Backpressure/capacity limits — real vs. assumed

### 1.1 The "5 GiB per file vs. 100+ GB design goal" gap — reconciled, not a real inconsistency

`src/config.py:133`: `max_upload_bytes = 5_368_709_120` (5 GiB) is a real,
enforced **per-file** ceiling — checked in `EvidenceIntakeService` before
any bytes are accepted, and independently bounded by clamd's own compiled
`StreamMaxLength` (the comment at `config.py:124-133` documents this was a
real, reproduced failure: a 239 MB E01 upload once exceeded clamd's
*100 MB* default and crashed with `BrokenPipeError` — `poc/clamav/run_poc_large_file.py`).

CLAUDE.md §A.5's "scales to 100+ GB evidence files" is **not** the same
claim as "one file can be 100+ GB" — tracing the real enforcement path
confirms the goal is about **aggregate case/org storage**, not single-file
size:

- `src/application/tenant_usage.py`'s `TenantUsageService.get_current_usage_bytes()`
  computes `SUM(size_bytes)` across all non-purged `Evidence` rows for an
  org — a real, unbounded-by-default aggregate.
- `src/application/quota_gate.py`'s `StorageQuotaGate` enforces this sum
  against `OrgQuota.storage_quota_bytes`, which is `int | None` — **`None`
  means unlimited**, a real, deliberate per-org configuration knob, not a
  hardcoded cap.
- So a case can genuinely accumulate 100+ GB of evidence across many
  ≤5 GiB uploads (a realistic forensic scenario: dozens of EVTX exports,
  E01 images, memory dumps from one incident), and CLAUDE.md's design goal
  is honestly met at the aggregate level. **Severity: none** — this was
  the one open question in the task brief that resolves cleanly once the
  quota-gate code is actually read rather than assumed; flagged here so a
  future reader doesn't re-litigate it.
- **What *is* real and enforced, not advisory:** `StorageQuotaGate.check_upload()`
  fails open on quota-subsystem unavailability (`quota_gate.py` — a
  deliberate choice, documented as "quota is a cost/capacity control, not a
  security control"), and a hard ceiling exists at `HARD_CEILING_MULTIPLIER`
  × the soft quota (`quota_gate.py:21-24`) before ingestion is actually
  held. This is real, tested logic, not a stub.

### 1.2 `CollectorIngestService` backpressure — real and enforced, but arbitrary-default, never load-tested

`src/application/collector_ingest.py:78-92`: before any event in a batch is
processed, `approximate_length()` is checked against `collector_max_stream_length`
(`src/config.py:46`, default `1_000_000`), and the whole batch is rejected
with `BackpressureError` if the stream is already at/over that ceiling.
This **is** real, enforced backpressure — not a paper limit — confirmed by
direct read of the check-then-reject code path, which runs before any
Redis `XADD`.

However: **the `1_000_000` default and the `collector_dedup_ttl_seconds = 3600`
default (`config.py:47`) have no cited load-test, benchmark, or capacity
model anywhere in this repo.** `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0's
own "verified starting facts" table cites `poc/stream_ingest_redis/`
(22/22) and `poc/stream_backpressure_dlq/` (24/24) as the evidence base —
both are **correctness** proofs (a fixed small number of events flow
through the mechanism correctly, redelivery/DLQ semantics work as
documented) not **throughput** proofs (sustained N events/sec against the
1,000,000-entry ceiling to see where real latency/memory degrades). A
repo-wide search for any load/throughput number tied to these two settings
returned nothing — `grep -rn "events/sec\|events per second\|throughput\|sustained" docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`
returns zero hits in that document's body (only in this task's own brief).
**Severity: Significant.** The numbers are plausible defaults, not
validated ones — a real capacity-planning exercise (how many
concurrent orgs × how many events/sec/org before Redis itself, not just
this counter, becomes the bottleneck) has never been run. `EventDedupChecker`'s
own docstring (referenced in `config.py:44-47`) is honest that the 1-hour
TTL is a documented tradeoff (bounded false-negative window on late
retries vs. unbounded storage growth), which is good practice, but a
*documented tradeoff* is still not the same as a *measured* one.

### 1.3 Milestone Q/R connectors: correctness-proven, never throughput-proven — confirmed directly, not inferred

Per the task brief's own steer (and the incident-response walkthrough's
finding), this was checked directly rather than assumed: every PoC cited in
`docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0 for the six new connectors
(Wazuh push, Suricata/Zeek live-tail, Defender poll, Splunk HEC sink, CEF
syslog sink, Sentinel sink) is described in that document's own §2 "layered
proof discipline" as L1/L2/L3 correctness PoCs — "one real event flowing
through," matching the task brief's own framing exactly. No PoC directory
name, README, or `output.txt` reference anywhere in the roadmap doc claims
a sustained/many-event run. `Defender`'s own real, in-code bound
(`_MAX_PAGES_PER_POLL = 50`, `src/external/integration_sources/defender.py:108`)
is a defensive *correctness* guard against an unbounded loop, not evidence
a 50-page real payload was ever actually exercised — its own comment says
it exists to "fail loudly on a malformed/looping stand-in or a real API
misbehaving," language consistent with a never-triggered safety bound, not
a validated capacity ceiling. **Severity: Significant, and it compounds
with §5's finding below** — the honest state is "the mechanism is
correct," not "the mechanism has been shown to keep up."

---

## §2 Failure-recovery behavior — real recovery-time bounds, per safety-net mechanism

All read directly from `src/external/celery_app.py`'s `beat_schedule`
(lines 94-149):

| Beat task | Real cadence | What it recovers | Real worst-case recovery-time bound | Named gap? |
|---|---|---|---|---|
| `abort-orphan-uploads` | hourly, `:00` | Evidence stuck in `UPLOADING` >2h | up to ~3h (2h stuck threshold + up to 1h until next `:00` tick) | No — acceptable for a background sweep against a state an analyst can already see via SSE; not customer-blocking within that window since the upload itself already completed client-side. |
| `abort-orphan-parses` | hourly, `:30` | Evidence stuck in `PARSING` >3h | up to ~4h | Same class as above. |
| `abort-orphan-intake` | hourly, `:45` | Evidence stuck in `SCANNING`/`HASHING` >30min | up to ~1.5h | **Yes, worth naming plainly**: this is the sweep most likely to fire during an active incident (evidence just uploaded, scanner/storage transiently unreachable) — a stuck upload can sit silently un-recovered for up to 1.5h before this task even fires the correction, on top of the incident-response walkthrough's own already-flagged 30-minute *detection* floor (F7 in that document). |
| `auto-dispatch-received` | hourly, `:15` | Evidence stuck in `RECEIVED` (broker unreachable at original dispatch) >5min | up to ~1h5min | The task's own comment calls this a "safety net for cases where the initial auto-dispatch failed" — real and correctly scoped, but a full customer-visible hour of "parsing never started" for a rare-but-real broker blip is a real, undocumented gap; CLAUDE.md §E.4 references this exact task as "no human intervention required," which is true for *eventual* recovery but doesn't name the up-to-1h window. |
| `auto-resume-quota-held` | every 15 min | Evidence held for exceeding an org's soft quota, once usage drops back under the ceiling | up to 15min | Deliberately tighter than the orphan sweeps (own comment: "every minute it stays held is a minute an analyst's timeline data is missing") — the one safety net whose interval was chosen with an explicit recovery-time rationale, not just copied from the others. |
| `poll-defender-alerts` | every 10 min | N/A (not a recovery sweep — it is the *only* trigger for `run_poll_cycle()` on the Defender source at all) | N/A | See §5 — this is a primary trigger, not a backstop, and its own failure mode (pagination-limit exhaustion) has no separate recovery task. |
| `anchor-audit-log` | daily, 02:00 UTC | Merkle-root + TSA-anchor "yesterday's" audit events per org | up to ~24h + processing time before an anchor exists for a given day's activity | Not framed as a customer-visible incident-recovery mechanism (it's a compliance/tamper-evidence anchor, not a live-outage recovery), so a 24h cadence is a different category from the others — correctly out of scope for "stuck state recovery," included here for completeness since it is in the same `beat_schedule`. |

**Overall on §2:** every mechanism named in the task brief is real — none
are stubs or dead code — and each one does genuinely recover the specific
stuck state it targets, confirmed by reading the actual query
(`stream_all_by_state`/`stream_all_quota_held`) and mutation
(`ev.with_error(...)`, `queue.enqueue_dispatch(...)`) each performs, not
just its docstring. The **honest gap is that none of these recovery-time
bounds (30min–4h) is written down anywhere as an SLA, capacity doc, or
even a comment acknowledging "this means a customer could see a stuck
upload for up to N hours."** CLAUDE.md §E.4 states the beat task provides
"automatic recovery — no human intervention required," which is literally
true but reads as stronger than it is without also stating the bound.
**Severity: Significant** (operational-transparency gap, not a
correctness bug).

### 2.1 `celery_defender.py`'s "build fresh every task" pattern — real, and its cost is bounded, checked directly

The task brief asked whether rapid Postgres engine creation/disposal at a
10-minute cadence (`poll_defender_alerts`) could itself become a
bottleneck. Checked directly against how `create_async_engine(..., poolclass=NullPool)`
behaves (`src/external/celery_defender.py:142`, mirroring the identical
pattern already established in `src/external/celery_runtime.py:69-72` for
the evidence-parsing DAG):

- `NullPool` means **no connection is held open between uses** — each
  `engine.dispose()` (called in the `finally` block, `celery_defender.py:203-205`)
  tears down every connection the engine opened, so there is no leaked-pool
  growth across invocations. This is the correct choice given the module's
  own documented reasoning (`celery_defender.py:1-68`): every Celery task
  gets its own fresh `asyncio.run()` event loop, and reusing a pooled
  connection/engine across event loops is a real, previously-hit failure
  class this codebase already worked around once (the module's own
  docstring cites it explicitly for `httpx`/OAuth2 token caching).
- **The real, bounded cost is TCP-handshake + Postgres backend-process-fork
  latency per invocation** (a fresh `asyncpg` connection has to
  authenticate and Postgres has to fork a new backend process for it) —
  at a 10-minute cadence this is a trivial, unmeasurable fraction of the
  10-minute window (single-digit milliseconds against a 600-second budget).
  **This is not a real bottleneck at the current cadence.** It would only
  become one if this same "build fresh every task" pattern were reused for
  a *much* tighter interval (sub-second/sub-minute) — which nothing in
  this repo currently does; the tightest beat cadence is `auto-resume-quota-held`
  at 15 minutes, still well within the same safe margin. **Severity: none
  at current cadences** — flagged as a real, checkable question the task
  brief raised, resolved by reading `NullPool`'s actual behavior rather
  than assumed either way.
- One real, adjacent, honestly-flagged risk **not** the one the brief
  asked about: if a future poll-mode source needed a sub-minute cadence,
  this exact pattern (fresh engine + fresh OAuth2 token fetch every
  invocation) would need to be revisited — `celery_defender.py`'s own
  module docstring already names this itself ("Revisit if a future
  poll-mode source's auth handshake is expensive enough that per-cycle
  re-authentication becomes the bottleneck") — a real, honest,
  self-identified trigger condition, not a gap this review is
  newly discovering.

---

## §3 Other single points of failure — concrete blast radius per component

### 3.1 Redis — the single sharpest SPOF in the platform today, wider blast radius than any one document has stated plainly

Confirmed directly from `docker-compose.prod.yml`: **one Redis container
(`redis:7-alpine`) serves four structurally distinct roles via DB-number
separation, not four separate instances:**

| DB | Role | Config source |
|---|---|---|
| 0 | Step-up (RFC 9470) ticket store, `REDIS_URL` | `docker-compose.prod.yml:268,389`; `src/config.py:137-140` |
| 1 | Celery broker (every evidence-parsing task) | `docker-compose.prod.yml:338,433` |
| 2 | Celery result backend | `docker-compose.prod.yml:339,434` |
| 3 | Stream-ingest backbone (`stream_redis_db`) — the Q/R connectors' own Redis Streams | `src/config.py:38` |

**Concrete blast radius if this one container goes down:**
1. **All evidence processing stops** — `process_intake`/`dispatch_parse`/
   `parse_artefact_*`/`finalize_evidence` are Celery tasks; no broker means
   no task dispatch at all. New uploads accept (`finalize_upload` only
   does a cheap `HEAD` check per the incident-response walkthrough's own
   trace) but sit in `UPLOADING` indefinitely — indistinguishable, from
   the analyst's perspective, from the "silent stall" already named as F7
   in that document, except now caused by total broker unavailability
   rather than queue backlog.
2. **Step-up re-authentication breaks** for any deployment with
   `step_up_ticket_store: redis` (`charts/kronos/values.yaml:193-194` sets
   this whenever `replicaCount > 1`, which is the chart's own default of
   2) — any privileged action gated behind step-up (case deletion, admin
   actions) becomes unavailable, not just slow.
3. **All six Q/R connectors' inbound events stop landing anywhere** —
   `StreamIngestAdapter.produce()` (DB 3) is the sole destination for
   `CollectorIngestService`/`IntegrationSourceIngestService`; a Redis
   outage here means Wazuh/Suricata/Defender events are rejected or lost
   at the source's own retry/backoff ceiling, not just delayed.
4. **Recovery path**: entirely dependent on how Redis itself is deployed —
   `docker-compose.prod.yml` gives it `--appendonly yes` + a named volume
   (durable across a *container* restart), but it is still one process on
   one host with **no replication of any kind** — a host failure, not just
   a container crash, is a real, total, unbounded-duration outage across
   all four roles simultaneously until a human provisions a new Redis and
   restores the AOF file. **This is a materially wider blast radius than
   Postgres or MinIO going down** (each of those affects one guarantee —
   audit-trail durability or evidence-object durability — Redis going down
   breaks *evidence intake dispatch*, *authentication step-up*, and *all
   new detection-relevant telemetry ingestion* simultaneously), yet
   `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md` §0's own research explicitly
   scoped its Redis analysis to the AOF-fsync durability window only (a
   real, but narrower, question than "what happens if the whole thing is
   unreachable"). **Severity: Blocking-class finding** — not
   because Redis needs to become an HA cluster necessarily (that is a
   genuine, separate cost/benefit question this document does not resolve),
   but because no document in this repo currently states the *combined*
   blast radius of "the one shared Redis instance is down" in one place —
   V10 and the Kafka roadmap each looked at one facet of Redis (data-loss
   window, ingest-layer replay), never the full multi-role outage picture.
   **This is new information this pass surfaces, not a restatement of V10
   or the Kafka research.**

### 3.2 OpenSearch — single-node in every compose file, confirmed directly (mirrors V1's own prior finding)

`discovery.type=single-node` is set identically in `docker-compose.dev.yml:85`,
`docker-compose.prod.yml:81`, and `docker-compose.test.yml:57` — confirmed
by direct grep, not assumed from a prior document's summary. **Concrete
blast radius:** every timeline query (`GET /api/timeline/...`), the
Security Analytics monitors and anomaly detectors that drive the
`Detection` pipeline (once wired — see §5), and OpenSearch Dashboards
embeds all become unavailable simultaneously. Recovery path: whatever
external orchestration restarts the container/pod — `charts/kronos/values.yaml`
**does not deploy OpenSearch at all** (no `opensearch:` resources block
beyond `url`/`dashboardsUrl`/`existingSecret`/`securityEnabled`/`securityInit` —
confirmed by reading the full 276-line file; it is referenced purely as an
external endpoint, the identical externally-provisioned pattern V10 already
found for MinIO). **This means the Helm chart in this repo has zero
opinion about OpenSearch's own recovery time** — whatever SLA exists is
entirely a property of infrastructure this repo does not define or own.
Unlike Postgres/evidence data, OpenSearch's indexed timeline is **rebuildable**
from the original evidence in MinIO + Postgres via re-parsing (a real,
if slow, recovery path that neither Postgres nor MinIO have an equivalent
of — losing either of those loses primary data, losing OpenSearch loses a
derived index). **Severity: Significant, narrower than Redis** — the
data is not permanently lost, but the platform's primary analyst-facing
capability (timeline search) is fully down for the outage's duration with
no documented recovery runbook, and detection evaluation (SA monitors)
stops too — which, per §5, is not the platform's only detection gap right
now, but would become the operative one once the pipeline is wired.

### 3.3 Keycloak — restates V10's own finding, not re-derived, cited for completeness of this section's structure

V10 §0.6 already found, and this pass does not re-verify independently,
that `docker-compose.prod.yml` points Keycloak's own `KC_DB_URL` at the
same single Postgres instance the application uses — meaning a Postgres
outage is not scoped to "audit trail unavailable," it takes authentication
down too. **Concrete blast radius if Keycloak itself (not just its DB) is
unreachable, the piece V10 did not explicitly spell out:** every new
session/token-refresh fails (`src/external/middleware/auth.py`'s JWT
validation depends on Keycloak's JWKS endpoint and realm availability) —
existing valid, unexpired JWTs continue to authenticate for API calls that
don't require step-up (JWT validation itself is local, signature-based, not
a live Keycloak round-trip per request), but **any new login, refresh, or
step-up re-authentication fails platform-wide** until Keycloak recovers.
No replication or failover is configured for Keycloak in any compose file
or the Helm chart (a single `keycloak:` service/dependency, no clustering
config). **Severity: Significant** — same class as OpenSearch (single
service, no HA, no documented recovery time), narrower than Redis (doesn't
touch evidence-processing or telemetry ingestion), wider than "just an
auth blip" because step-up-gated actions (admin/case-lead privileged
operations) are unavailable even for already-authenticated users.

---

## §4 Resource-sizing sanity check

Read directly from `charts/kronos/values.yaml` (lines 21-56, 196-256) and
cross-checked against `docker-compose.*.yml`'s OpenSearch heap settings:

| Component | Configured resources | Sanity check against stated workload |
|---|---|---|
| `celeryPlaso` (Plaso heavy-parse) | req `1000m`/`2Gi`, limit `4000m`/`8Gi`, `replicas: 1`, `concurrency: 1` | **Plausible for Plaso specifically** — Plaso is well-documented as memory-hungry on large images, and `concurrency: 1` with a single replica (matching `parse_artefact_heavy`'s own `time_limit=600` in `celery_app.py:309`) means exactly one heavy parse runs at a time platform-wide. This is a real, structural **throughput ceiling**, not just a resource number: a second concurrent Plaso job queues behind the first regardless of cluster size unless `celery.workers.plaso.replicas` is manually raised. For "100+ GB evidence" aggregated across many files needing Plaso (registry hives, prefetch, etc.), a single-worker-at-a-time design means large cases could see multi-hour queuing under real concurrent-case load — plausible for a PoC/early-stage deployment, a real, named scaling limit for anything beyond it. |
| `celeryFast` (evtx-rs/CloudTrail/nginx) | req `500m`/`1Gi`, limit `2000m`/`4Gi`, `replicas: 2`, `concurrency: 4` | Plausible — `evtx-rs` is CPU-light per CLAUDE.md §B.6's own ">5000 records/sec on single core" baseline; 8 real concurrent fast-parse slots (2 replicas × 4 concurrency) is reasonable for a PoC-stage deployment, though (like §1.2/§1.3) no benchmark in this repo actually measures aggregate fast-parse throughput at this replica count against real EVTX file sizes. |
| `celeryIndex` (`q.index`+`q.intake`, includes `process_intake` validate/scan/hash) | req `250m`/`512Mi`, limit `1000m`/`2Gi`, `replicas: 2`, `concurrency: 8` | Reasonable for lightweight orchestration tasks; ClamAV scanning itself runs out-of-process against `clamd_host`/`clamd_port` (not CPU-bound inside this pod), consistent with the low CPU request. |
| `postgresql` (Bitnami subchart) | req `250m`/`512Mi`, limit `1000m`/`2Gi`, `50Gi` PVC | Already characterized in depth by V10 §1.3/§1.4 (not re-derived here) — flagged only for a scale angle V10's HA-specific lens didn't emphasize: **50Gi for a platform whose own design goal is 100+ GB *aggregate* evidence per org is sized for metadata/audit rows only** (Evidence bytes live in MinIO, not Postgres — `audit_log`/`evidence` are metadata tables), which is the correct architecture, but the PVC size itself has no stated relationship to org count/audit-event volume in the chart or its comments — worth a real per-org audit-event-volume estimate before this becomes a production sizing decision, not urgent at current PoC scale. |
| `redis` (Bitnami subchart) | req `100m`/`128Mi`, limit `500m`/`512Mi`, `8Gi` PVC | **The tightest-margin number in the whole file, worth flagging plainly.** Given §3.1's finding that this one instance carries the Celery broker, step-up tickets, AND the stream-ingest backbone for all six new connectors, 128Mi request/512Mi limit is sized for a lightly-loaded broker+cache, not for `collector_max_stream_length = 1_000_000` entries per (org, source) potentially accumulating across many orgs/sources simultaneously if `BatchSealingService.seal_pending()` is ever wired to run on a real cadence (§5) — a stream sitting near its 1M-entry ceiling for a single (org, source) pair, times several concurrent orgs, is a real, plausible way to exceed 512Mi that nothing in this values.yaml file accounts for. **Severity: Significant** — not proven to be wrong (no load test was run, per the task's own instruction not to), but the number shows no evidence of having been chosen with the stream-ingest role in mind, since Redis's role list here (broker/cache) predates the DB-3 stream-ingest addition per `stream_redis_db`'s own comment in `config.py:34-38`. |
| `opensearch` heap | dev/test `512m`/`512m`, **prod `2g`/`2g`** (`docker-compose.prod.yml:82`) | **This is the one number in this section that does not reconcile well with the "100+ GB evidence, ECS-indexed" design goal, worth naming as the most concrete finding in this section.** A 2GB JVM heap is a genuinely small OpenSearch deployment — official OpenSearch sizing guidance (general Elasticsearch-lineage operational convention, not fetched fresh in this pass since it wasn't the task's ask, restated only as informed sanity-check per the task's own "you don't need to load-test, an informed check is the right bar") treats 2GB as suitable for development/small proof-of-concept indices, not for the sustained bulk-indexing + concurrent SA-monitor-query load a 100+ GB aggregate evidence corpus (as ECS-mapped timeline documents, which are considerably more numerous and heavier than raw log lines once every `kronos.*` provenance field is added) would generate. Combined with `discovery.type=single-node` (§3.2) and no Helm-managed OpenSearch deployment at all (values.yaml has no resource request/limit for OpenSearch whatsoever — it is purely `url:`-referenced), **this repo has never actually specified what a production-sized OpenSearch node looks like for its own stated evidence-volume goal.** `TimelineIngestionService`'s own bulk-batch defaults (`_DEFAULT_BATCH_SIZE = 500`, `_FLUSH_INTERVAL_SECONDS = 30`, `src/application/timeline_ingest.py:28-29`) are sensible, conservative bulk-indexing hygiene regardless of heap size — that part of the design is sound — but a 2GB heap will start hitting JVM GC pressure well before ingesting the volume of ECS documents a 100+ GB aggregate-evidence org would eventually produce. **Severity: Significant.** |

---

## §5 New integration layer's own scale story — correctness-proven vs. throughput-proven, named explicitly

**Correctness-proven, confirmed by direct code/PoC-README read:** all six
Q/R connectors (Wazuh push, Suricata/Zeek live-tail, generic webhook,
generic-poll, Defender poll, plus the three outbound sinks) have real
unit tests and at least one real L1/L2 PoC exercising the mechanism against
a real or realistic-stand-in dependency, per `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`
§3's three-stage gate. `CollectorIngestService`'s backpressure check
(§1.2) and `ZipArchiveParser`'s container-extraction bounds
(`MAX_CONTAINER_DEPTH=3`, `MAX_MEMBER_COUNT=50_000`,
`MAX_TOTAL_UNCOMPRESSED_BYTES=4 GiB`, `MAX_PER_FILE_UNCOMPRESSED_BYTES=1 GiB`,
`src/external/parsers/archive.py:74-77`) are real, enforced, and correctly
prevent unbounded resource consumption per request/per file — genuinely
solid defensive engineering, worth stating plainly as a positive finding.

**Never throughput-proven** (§1.3 restates this at the general level; this
section names it per-connector where a concrete, checkable mechanism
exists):

### 5.1 `poll_defender_alerts` — a real, checkable, and currently unmitigated compounding-backlog risk

Traced directly through `src/external/integration_sources/defender.py:148-239`:
`poll()` follows `@odata.nextLink` pagination to exhaustion within one
call, capped at `_MAX_PAGES_PER_POLL = 50` (line 108). If a real backlog
needs more than 50 pages to drain (a real Defender outage/reconnect
scenario, or simply a high-alert-volume tenant whose 10-minute poll window
falls behind), **`poll()` raises `IntegrationSourceError` before returning
any result** — `run_poll_cycle()` (`src/application/integration_source_ingest.py:138-150`)
only persists the advanced `SourceCursor` **after** a successful `source.poll()`
call, so a poll cycle that hits the 50-page ceiling makes **zero forward
progress**: the cursor stays exactly where it was, the audit trail records
`INTEGRATION_SOURCE_POLL_FAILED`, and the Celery task retries once
(`max_retries=1`, `celery_app.py:660`) before surfacing loudly. **The
concrete, real risk this traces to: if the true backlog behind the cursor
never shrinks below 50 pages' worth of alerts** (a sustained high-volume
tenant, or an extended prior Defender-side or KronOS-side outage), **every
subsequent 10-minute poll cycle will re-attempt the identical page range,
fail at the identical page 51, and never advance** — a real, compounding
stuck state with no separate recovery task (unlike the evidence-pipeline's
`abort_orphan_*`/`auto_dispatch_received` safety nets, there is no
"Defender cursor is stuck" beat task). **Severity: Significant** — this is
not a hypothetical "might be a bottleneck," it is a directly-traceable code
path with no mitigation once triggered; the fix (chunking cursor advancement
mid-page-limit, or persisting a partial cursor on hitting the cap rather
than discarding all progress) is a real, scoped follow-up item, not
speculative.

### 5.2 `GenericPollSource` — the second POLL-mode source has *zero* production scheduler at all, a distinct gap from 5.1

Checked directly: `GenericPollSource.poll()` (`src/external/integration_sources/generic_poll.py`)
fetches exactly **one page per call** (no internal pagination loop, unlike
Defender) and advances the cursor by exactly that one page — a genuinely
better-bounded per-cycle design than Defender's (a huge backlog just takes
more scheduled cycles to drain, never fails outright the way 5.1 does).
**But `grep -rn "generic-poll\|GenericPollSource\|run_poll_cycle" src/external/celery_app.py`
returns zero hits** — there is no beat task anywhere that calls
`run_poll_cycle()` for `generic-poll`, in contrast to Defender's dedicated
`poll-defender-alerts` entry. This means `GenericPollSource` — the
Q1 "proves the POLL shape end to end" reference implementation — has
**never run on any schedule in this deployment's production configuration
at all**, the identical "wired but never triggered" shape the
incident-response walkthrough already found for `DetectionSyncService`/
`BatchSealingService`/`StreamNormalizationService`. **This is new
information this pass surfaces** (the incident-response walkthrough did
not check the integration-source poll layer specifically) — confirming the
same structural gap recurs a third/fourth time across this initiative's
newest components. **Severity: Significant**, same class as the previously
documented gaps, worth explicitly cross-referencing rather than treating as
isolated.

### 5.3 The honest overall §5 framing, restated per the task brief's own instruction

Because `seal_pending()`/`normalize_batch()` have no production trigger
(confirmed by the incident-response walkthrough, re-confirmed here by
independent grep against the current tree — no new callers landed since
`bd42ee3`), **the true end-to-end backlog question — "what happens when
Redis Streams accumulates events faster than sealing+normalization can
drain them" — cannot be answered as "current behavior" at all today,
because that drain step does not run in production.** The honest framing
this document adopts, per the task brief: **if/when a beat task is added
for `seal_pending()`/`normalize_batch()`** (the incident-response
walkthrough's own recommended fix, F1/F2 in that document), **that new
task inherits every open question from §1.2 above** (the `1_000_000`-entry
stream ceiling and 3600s dedup TTL are still unvalidated against real
throughput) **plus a new one this document is the first to name**: no
`SealingTriggerPolicy` interval, once wired, has been checked against
whether `collector_max_stream_length` could be reached *between* two
scheduled sealing runs for a genuinely high-volume (org, source) pair —
that is a real, concrete, checkable question for whoever picks up F1/F2,
not resolved here since the mechanism doesn't run today.

---

## §6 Summary of severities

| # | Finding | Severity |
|---|---|---|
| 1 | Redis is a single, shared instance across broker/step-up/stream-ingest roles — combined blast-radius wider than any prior document (V10, Kafka roadmap) stated in one place | **Blocking-class** (documentation/awareness gap; not necessarily "must become HA now," but must be named) |
| 2 | `poll_defender_alerts` can enter a permanently-stuck cursor state once real backlog exceeds 50 pages, with no dedicated recovery task | **Significant** |
| 3 | `GenericPollSource` has zero production scheduler — a third/fourth recurrence of the "wired but never triggered" pattern the incident-response walkthrough already found for the Detection pipeline | **Significant** |
| 4 | OpenSearch prod heap (2GB) and the complete absence of any Helm-managed OpenSearch resource sizing don't reconcile with the "100+ GB evidence, ECS-indexed" design goal | **Significant** |
| 5 | `collector_max_stream_length`/`collector_dedup_ttl_seconds` and the six Q/R connectors generally are correctness-verified, never throughput-verified — no load/benchmark evidence exists anywhere in this repo | **Significant** |
| 6 | `celeryPlaso` is hard-capped at one concurrent job platform-wide by default sizing — a real, structural throughput ceiling for any deployment with concurrent Plaso-needing cases | **Minor–Significant** (a known, sensible-for-PoC default, not a bug, but worth naming as the platform grows) |
| 7 | Beat-task recovery-time bounds (30min–4h) are real and correct but never stated anywhere as an SLA/capacity doc | **Significant** (transparency gap) |
| 8 | 5 GiB per-file vs. "100+ GB" design goal | **Resolved, not a gap** — aggregate quota (`OrgQuota.storage_quota_bytes`, nullable = unlimited) is the real mechanism; confirmed by code read |
| 9 | `celery_defender.py`'s fresh-engine-per-task pattern | **Resolved, not a gap** — `NullPool` + 10-minute cadence means construction cost is negligible; confirmed by understanding `NullPool` semantics |

**Does this broaden or narrow V10's scope?** **Broadens it, in one specific
direction V10 explicitly did not cover**: V10's Redis-adjacent commentary
(via the Kafka roadmap facts it cites) was scoped to the AOF-fsync
durability window for the *stream-ingest* role specifically. This document
finds that the same single Redis instance also carries the Celery broker
(all evidence processing) and step-up ticket store (privileged-action
auth) — meaning a Redis outage's real blast radius is three simultaneous
platform-wide failures, not one narrow data-loss window. This is a
genuinely new finding, not a restatement, and the two documents together
now give a complete picture neither had alone. Everything else in this
document (OpenSearch/Keycloak SPOFs, resource sizing, connector
throughput) is additive to V10's Postgres/MinIO-specific scope, not a
revision of any V10 conclusion.
