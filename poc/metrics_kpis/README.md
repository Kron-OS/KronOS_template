# I2 · Metrics & KPIs -- real computation against the live dev cluster's own historical data

**Roadmap item:** `docs/NEXTGEN_SOC_ROADMAP.md` M8/I2. Proof layer: **L2**
(two-or-more already-real components genuinely linked: `MetricCalculator` →
real `PostgresDetectionRepository`/`PostgresAuditLogRepository`/
`PostgresSealedBatchRepository` → real Postgres; → real `OpenSearchClient`
→ real OpenSearch 2.11.1; → real `RedisStreamIngestAdapter` → real Redis).

## Pinned versions (read from this repo, not assumed)

| Component | Version | Source |
|---|---|---|
| Postgres | 16-alpine (server 16.14, matches `poc/batch_sealing/`) | `docker-compose.dev.yml` |
| OpenSearch | 2.11.1 | `docker-compose.dev.yml`, confirmed live via `GET /` |
| Redis | 7-alpine (server 7.4.9, matches prior D-series PoCs) | `docker-compose.dev.yml` |
| MinIO | `minio/minio:latest` (used for the Scenario 3 live seal only) | `docker-compose.dev.yml` |
| `sqlalchemy` | 2.0.51 | `~/venv` (matches `pyproject.toml`'s `>=2.0` pin) |
| `asyncpg` | 0.31.0 | `~/venv` |
| `redis` (py) | 8.0.1 | `~/venv` |
| `opensearch-py` | 3.2.0 | `~/venv` |
| `boto3` | 1.43.46 | `~/venv` |
| `httpx` | 0.28.1 | `~/venv` |

All real, running containers already up from this session's own H1-I1 PoC
work (confirmed via `docker compose -f docker/docker-compose.dev.yml ps`
before this ran, per the dispatch brief) -- no new containers were started
or stopped for this item.

## Method

1. Read `docs/NEXTGEN_SOC_ROADMAP.md`'s I2 section in full (its own
   orchestrator-added scope note names MTTD/FP-rate/rule-coverage/sealer-lag
   as the 4 strongest candidates out of the 7 named KPIs) and this
   codebase's established ABC+registry extensibility idiom
   (`FieldMapping`/`ECSFieldMappingRegistry`, `CostGateHeuristic`/
   `RuleCostGate`, `PlaybookAction`/`PlaybookActionRegistry`).
2. Queried the real live Postgres directly (`docker exec docker-postgres-1
   psql ...`) to confirm what real historical data already exists from this
   session's own H1-I1 PoC runs *before* writing any calculator, per
   CLAUDE.md §F -- found 796 real `Detection` rows for org `kronos-dev`
   (`482072f5-...`), 10 real `detection.triage_transitioned` audit rows
   across several orgs, and 11 real `sealed_batches` rows (none for
   `kronos-dev` itself).
3. Designed `MetricCalculator` (ABC) + `MetricRegistry` + `MetricsService`
   (`src/application/metric_calculator.py`), then 4 concrete calculators,
   each querying only real, already-existing repositories/clients:
   - `MeanTimeToDetectCalculator` (`src/application/metric_mttd.py`)
   - `FalsePositiveRateCalculator` (`src/application/metric_fp_rate.py`)
   - `RuleCoverageCalculator` (`src/application/metric_rule_coverage.py`)
   - `SealerLagCalculator` (`src/application/metric_sealer_lag.py`)
4. Ran `run_poc.py` for real (`~/venv/bin/python3 poc/metrics_kpis/run_poc.py`)
   against the live stack -- three scenarios, captured verbatim in
   `output.txt`. **No mocks, no synthetic historical data** -- Scenarios 1-2
   are 100% pre-existing real data from this session's own prior work.
   Scenario 3 is clearly-labeled fresh synthetic *stream* traffic (see
   below) produced specifically to demonstrate the live sealer-lag path,
   since Redis itself turned out to have zero surviving stream data (a real
   finding in its own right, see below) -- not a substitute for or
   fabrication of a metric value.

## Real captured numbers (full output: `output.txt`)

### Scenario 1 -- `kronos-dev` (`482072f5-8086-4815-be03-879cc2eaecb5`), the org with the most real historical data

| Metric | Value | Sample size | Notes |
|---|---|---|---|
| `mttd_seconds` | **346.5s mean** (min 80.6s, median 83.0s, max 21,062.7s) | 796 | See "Finding #1" below -- this number is real but structurally biased, and the finding matters more than the number. |
| `false_positive_rate` | **0.5** (1 FALSE_POSITIVE / 2 terminal) | 2 | 5 more transitions are still non-terminal (INVESTIGATING) and correctly excluded from the denominator. |
| `rule_coverage_ratio` | **0.00303** (5 fired / 1650 available) | 796 detections | Per-log-type: windows 3/1580, cloudtrail 1/32, network 1/38. |
| `sealer_lag_pending_messages` | **unavailable** | 0 | Honest: `kronos-dev` has never sealed a batch (0 rows in `sealed_batches` for this org) -- correctly `None`, not a fabricated `0`. |

### Scenario 2 -- a real sparse org (`d98979e9-2151-4da7-a76b-4cc790c8d688`, 1 Detection, 0 triage transitions, 0 sealed batches)

All 4 metrics correctly report `value: null` with a specific, honest
`unavailable_reason` (see `output.txt`) -- **except** `rule_coverage_ratio`,
which correctly reports a real `0.0` (not "unavailable"): a coverage ratio
of exactly zero fired-out-of-1650-available is a meaningful, computable
fact even from a single Detection, unlike MTTD/FP-rate/sealer-lag, which
have no valid sample at all for this org.

### Scenario 3 -- live sealer-lag round-trip (real Redis + real MinIO)

Before: `kronos-dev` has no sealed sources at all (same "unavailable" as
Scenario 1). Then, for real:

1. Produced 3 real messages to a fresh stream (`RedisStreamIngestAdapter.produce`).
2. Ran one real `BatchSealingService.seal_pending()` cycle -- real MinIO
   WORM `put_batch`, real Postgres `sealed_batches` row (`batch_id
   e9c0c069-b022-4836-961b-2a6e0195faa3`, `event_count: 3`), real
   `BATCH_SEALED` audit event. TSA omitted (`timestamp_service=None`) --
   see "What was NOT verified" below.
3. Produced 4 MORE real messages, deliberately left un-consumed (never
   delivered to any consumer of the `kronos-sealer` group).
4. Re-ran `SealerLagCalculator` -- real result:
   `value: 4.0`, `unit: "messages"`, with
   `detail.per_source["kronos-i2-metrics-live-demo"] = {"live_group_found":
   true, "pending_count": 0, "lag": 4, "backlog": 4}`.

**A real, load-bearing bug this run caught in the calculator itself before
it ever left this pass:** the first draft of `SealerLagCalculator` summed
only `pending_count` (delivered-but-unacked) into its headline `value`.
Step 4 above has `pending_count: 0` (nothing was ever delivered to a
consumer) but a real `lag: 4` (4 messages sitting in the stream that no
consumer has ever picked up -- i.e. no sealer process is running at all,
`ConsumerGroupHealth`'s own docstring's *other* named failure mode). The
first draft would have reported `value: 0.0` here -- silently hiding the
exact "sealer isn't running" condition this metric exists to catch. Fixed
to sum `pending_count + lag` per source before this was ever reported as
"done"; this is exactly the kind of bug CLAUDE.md §F/roadmap invariant #8
exist to catch by requiring a real run be read, not assumed correct from
the code alone.

The `kronos-i2-metrics-live-demo` sealed batch and its Postgres row are
deliberately left in place (real, durable data), mirroring C4/C5's own
precedent of leaving real PoC-produced rows rather than deleting them.

## Finding #1 (the important one): MTTD, computed exactly as specified, is structurally incapable of measuring genuine detection latency against historical forensic evidence -- and this generalizes C5's own finding

Roadmap C5 (`poc/chain_detect_from_evidence/README.md`) already discovered
that OpenSearch Security Analytics monitors only evaluate documents whose
own `@timestamp` falls within a *recent wall-clock* execution window --
real forensic evidence (whose genuine event timestamps are always
historical, sometimes by years) structurally can never fire a monitor
unless something re-indexes it with a fresher timestamp first. C5's own
prior passes did exactly that for a handful of demonstration documents.

Building `MeanTimeToDetectCalculator` and running it against this org's
full 796 real Detections makes the *general* implication of that finding
concrete: **every single Detection this platform has ever synced, for any
org, is logically guaranteed to be built from a document whose `@timestamp`
was recent enough for SA to have fired on it in the first place** -- SA
cannot produce a finding any other way. Confirmed directly: fetching one
matched document under an index literally named `...-201508` (a real
August-2015 event month, from the real historical EVTX sample) shows
`_version: 2` and `"@timestamp": "2026-08-07T10:01:44.492Z"` -- re-indexed
once, with today's date, sometime after its original ingest. This is not
an isolated artifact; it is why the observed MTTD distribution (80s–5.8h,
median 83s -- see `detail.median_seconds` in `output.txt`) looks like "an
SA schedule interval plus some sync latency" rather than anything
resembling genuine attacker-dwell-time-to-detection: **that is
mathematically the only shape this number can ever take under the current
SA-monitor-based Detection pipeline**, regardless of how old the real
underlying evidence actually is.

This does not mean the calculator is wrong -- it computes exactly the
formula the roadmap specifies (`Detection.synced_at` minus the matched
document's own real `@timestamp`), and the numbers in `output.txt` are
real, not fabricated. It means the *metric*, as currently pipeline-scoped,
cannot answer the SOC-analyst question "how long between when this actually
happened and when we caught it" for anything that reached KronOS through
the evidence-upload path -- only for the (roadmap D-milestone,
not-yet-built) continuous-stream detection path, where `@timestamp` is
naturally close to real time by construction. Flagged as a real, structural
follow-up limitation of the *pipeline*, not this metric's implementation
-- consistent with C5's own "flagged as follow-up, not solved here"
precedent for the same underlying architectural gap.

## Investigation: MTTR, analyst workload, ingest lag

Per the roadmap's own instruction to investigate rather than assume:

- **MTTR (proper, "time to remediation"): NOT honestly computable today.**
  Two real gaps, both checked directly against live audit rows, not
  guessed: (1) `Detection`'s own triage FSM has no "remediated"/"resolved"
  terminal state -- `TRUE_POSITIVE`/`FALSE_POSITIVE` are triage verdicts,
  not a remediation-complete signal, so there is no real timestamp marking
  "this incident is closed"; (2) `containment.action_executed`/
  `containment.action_attempted` audit events (confirmed via
  `SELECT event_type, details FROM audit_log WHERE event_type LIKE
  'containment.%'`) key on `user_id`/`session_id`, **never** `detection_id`
  -- there is no real join key between a containment action and the
  Detection it was a response to. Building "MTTR" from these would require
  fabricating a correlation this data model does not actually record.
  **Scoped as follow-up**, not built.
- **A weaker, real, honestly-DIFFERENT proxy IS available and worth naming
  explicitly so it isn't conflated with MTTR if built later:** "time to
  first triage engagement" (MTTA, Mean Time To *Acknowledge* -- a distinct,
  smaller SOC KPI from MTTR). `DETECTION_TRIAGE_TRANSITIONED` audit events
  DO carry both `details.detection_id` and a real `occurred_at`
  (confirmed: `SELECT actor_user_id, actor_username, details->>'detection_id',
  occurred_at FROM audit_log WHERE event_type='detection.triage_transitioned'`
  returns real rows for real detection ids) -- `synced_at` minus the
  earliest such event per detection is genuinely computable. Not built in
  this pass (roadmap's own "start small" precedent, already at 4/7 KPIs
  this pass) -- real, low-risk follow-up, distinct from MTTR and must be
  named as MTTA (or similar), never mislabeled as MTTR.
- **Analyst workload: confirmed genuinely computable, not built this pass.**
  The same `DETECTION_TRIAGE_TRANSITIONED` audit rows carry a real
  `actor_user_id` (and usually `actor_username`, though several rows from
  playbook-driven transitions show `"unknown"` -- a real, minor,
  out-of-scope gap in how `PlaybookExecutionService` resolves the acting
  identity for automated transitions, flagged but not fixed here) --
  count of transitions per `actor_user_id` per org over a period is a real,
  honest workload proxy. Deferred, not because it's uncomputable, but to
  keep this pass at the roadmap's own suggested 4 KPIs.
- **Ingest lag: decided, not built.** For the evidence-upload path (the
  only one with real historical data right now), the honest measurement is
  upload-finalized-to-indexed latency (`EVIDENCE_UPLOAD_FINALIZED`'s
  `occurred_at` vs. the resulting documents' own `kronos.ingest_timestamp`,
  both real, both already present) -- genuinely different from
  "event-timestamp-to-index-timestamp" ingest lag, which only becomes
  meaningful once the D-milestone continuous-stream path is live and
  producing real, naturally-recent `@timestamp`s (Redis Stream message ids
  already embed a millisecond producer timestamp for exactly this future
  use). Not built this pass -- named and reasoned about per the roadmap's
  own request, deferred alongside MTTR/workload to keep this pass scoped.

## What was NOT verified

- **TSA/RFC 3161 timestamping in Scenario 3's live seal.** Constructed
  `BatchSealingService` with `timestamp_service=None` (a real, existing,
  supported configuration -- TSA is optional per that class's own
  constructor) rather than standing up `poc/batch_sealing/`'s own
  throwaway `openssl ts` responder again; that mechanism is already
  separately verified there. This item is about the metrics layer reading
  `SealedBatch`/`ConsumerGroupHealth` correctly, not re-proving TSA.
- **Analyst-workload / MTTA / ingest-lag calculators** -- investigated and
  found genuinely computable (see above) but not implemented, per this
  pass's own scope discipline.
- **Rule-coverage denominator** only covers the 3 log types
  `SecurityAnalyticsDetectorProvisioner`/`get_default_log_types()` actually
  provisions detectors for (`windows`, `cloudtrail`, `network`) -- the same
  scope C1 measured under, not all 23 log types Security Analytics
  supports (most of which this deployment has no detector for at all, so a
  denominator including them would silently overstate how much "coverage"
  is even structurally possible right now).
- **mypy/full unit suite regression check** -- see the roadmap STATUS note
  for the exact command and result (run separately from this PoC, per
  CLAUDE.md §B.5's unit-test-suite discipline, not part of this live-cluster
  script).
