# PoC: autonomous continuous-telemetry -> Detection pipeline (Milestone W/W1)

## What this proves

The four convergent findings from the Task #14 multi-scenario assessment
(`docs/assessments/incident_response_walkthrough.md` F1/F2/F3,
`docs/assessments/scale_reliability_review.md`'s `GenericPollSource` note)
all named the same underlying gap: `BatchSealingService.seal_pending()`,
`StreamNormalizationService.normalize_batch()`, and
`DetectionSyncService.sync_org_findings()` were real, already-tested
services with **zero production callers** -- the six Q/R EDR/SIEM
connectors were individually PoC-verified in isolation but structurally
inert end-to-end, because nothing ever scheduled the chain that turns
ingested telemetry into a `Detection` row without a human manually calling
each stage.

This PoC proves the new Celery beat wiring in `src/external/celery_app.py`
(`seal_pending_streams`, `normalize_stream_batch`, `sync_detection_findings`
-- task bodies in `src/external/celery_streaming.py`) makes that chain run
**autonomously**, with no manual service call anywhere in the script past
the point real telemetry is produced onto the stream.

## Versions pinned (per CLAUDE.md SS F.2 step 1)

Read directly from this repo, not assumed:

- Redis: `redis:7-alpine` (`docker/docker-compose.dev.yml`)
- OpenSearch: `opensearchproject/opensearch:2.11.1` (incl. Security
  Analytics plugin, same image used by every prior Q/R/V PoC)
- Keycloak: `quay.io/keycloak/keycloak:26.2` (Organizations Admin REST API)
- Celery: pinned in `pyproject.toml`, `celery beat`/`worker` v5.6.3 (see
  captured `beat.log` banner in earlier debug runs)
- Postgres + MinIO: same dev-stack containers every prior PoC in this repo
  already verified against (`docker-compose.dev.yml`)

All against the real, already-running dev stack -- no new containers, per
CLAUDE.md's host-Docker authorization for this initiative.

## Real docs/examples consulted (per F.2 step 2)

- This repo's own prior verified PoC, `poc/l3_chain_collector_to_detect/`,
  which manually drove the identical chain (collector -> Redis Stream ->
  seal -> normalize -> OpenSearch -> real SA monitor -> `DetectionSyncService`)
  step-by-step by hand. This PoC reuses that chain's own real fixtures
  (Zeek `conn.log` sample event shape, `zeek-conn-log` source_id semantics,
  RDP-trigger Sigma rule) and simply removes the human from every step.
- `SecurityAnalyticsDetectorProvisioner`/`AnomalyDetectorProvisioner`'s own
  real, already-verified detector-naming and scheduling conventions
  (`src/adapter/opensearch/*_provisioner.py`) -- this PoC's own detector
  name and schedule were corrected mid-debugging to match those exactly
  (see "Bugs found" below), confirmed live against real OpenSearch 2.11.1.
- Keycloak 26.2 Admin REST API Organizations endpoints
  (`/admin/realms/{realm}/organizations`, `.../organizations/{id}`) --
  exercised live (create/list/get/delete), same service-account credential
  path `HttpxKeycloakAdminClient` already used for `is_org_member`
  (verified against real Keycloak in the pre-existing
  `poc/containment_approval_gate/`).

## How to run

```
source .venv/bin/activate  # or the repo's real venv
bash poc/autonomous_detection_pipeline/_poc_env.sh   # sets throwaway ports/paths
python poc/autonomous_detection_pipeline/run_poc.py
```

Requires the real dev stack (`docker/docker-compose.dev.yml`) already
running. The script creates its own fresh, ephemeral Keycloak org
(`kronos-poc-w1-<random>`) so it never collides with the shared
`kronos-dev` org's own prior state, starts a throwaway local Celery
worker+beat pointed at the real broker/backend with a shortened beat
schedule (`_beat_schedule_override.py`, 10s/15s instead of 60s/5min, for
faster verification only -- the committed production schedule in
`celery_app.py` is unmodified), and tears down only the resources it
itself created (the ephemeral org; Redis/Postgres/MinIO/OpenSearch data
this run created is deliberately left in place as inspectable proof, same
precedent as `poc/l3_chain_collector_to_detect/`).

## Result (last real run, captured in `output.txt`)

**24/24 real checks passed.** Every seal/normalize/sync step below was
triggered by the real Celery beat schedule alone -- the script never calls
`seal_pending()`/`normalize_batch()`/`sync_org_findings()` directly.

Real wall-clock timestamps from that run:

| Stage | Timestamp (UTC) | Offset |
|---|---|---|
| T0: worker+beat alive, empty backlog | 14:38:02.257 | - |
| T1: round-1 events onto real Redis stream | 14:38:02.322 | - |
| T_sealed1: autonomous seal (beat-triggered) | 14:39:05.476 | +63.2s after T1 |
| T_normalized1: autonomous normalize (event-chained) | 14:39:17.510 | +12.0s after seal |
| T2: round-2 (RDP trigger) event produced | 14:39:17.751 | - |
| T_sealed2: autonomous seal | 14:40:20.884 | +63.1s after T2 |
| T_normalized2: autonomous normalize (event-chained) | 14:40:20.889 | +0.0s after seal |
| T_finding: real SA monitor fires on its own schedule | 14:41:20.973 | - |
| T_detected: autonomous sync -> real `Detection` row | 14:41:25.986 | +5.0s after finding |
| T_end: SOAR route (item d) verified | 14:41:56.270 | - |

**Total wall-clock T0 -> T_detected: 203.7s**, entirely autonomous.

Also verified in the same run (see `output.txt` for full detail):
- Provenance linkage: `Detection.matched_document_ids` -> real OpenSearch
  doc -> real `kronos.batch_id` matches the real sealed batch that produced
  it.
- Idempotency: re-running the sync cycle creates zero duplicate `Detection`
  rows.
- Item (d): `POST /api/detections/{id}/sync-to-siem/splunk` ->
  `PlaybookExecutionService.execute()` -> real HTTP push to a
  HEC-protocol-accurate stand-in receiver, `succeeded: true`, receiver
  actually received the push with the correct `finding_id`.

## Real bugs found and fixed along the way (PoC-harness only, not `src/`)

Three real bugs surfaced during iterative debugging, all in this PoC
script, not in the new `src/` beat-task code:

1. **Stale-watermark collision**: an early version of this script reused
   the shared `kronos-dev` org + `zeek-conn-log` source_id, colliding with
   real `sealed_batches` rows a prior Q3 connector PoC had left in Postgres
   weeks earlier. `BatchSealingService._check_watermark_gap()` correctly
   raised `EvidenceLossDetectedError` -- a real, working safety check, not
   a bug. Fixed by creating a fresh, unique, ephemeral Keycloak org per run.
2. **Round-2 wait budget too tight**: round 2's wait timeout (60s) sat
   right at the edge of `_SEAL_MAX_AGE_SECONDS` (60.0) plus one more beat
   tick, so the script's own assertion could fire before the real seal
   task's own next scheduled tick. Fixed by widening the wait budget.
3. **Detector-naming mismatch**: this script's own throwaway SA detector
   name didn't match `SecurityAnalyticsDetectorProvisioner`'s real
   production naming convention, so `DetectionSyncService`'s real finding
   lookup could never discover it even though the finding genuinely existed
   in OpenSearch. Fixed by renaming to match production exactly.

All three are documented here for auditability; none required any change
to `src/`.
