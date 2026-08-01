# PoC: L3 chain — collector → stream → seal → index → detect (roadmap M3/D6)

## What this item is

`docs/NEXTGEN_SOC_ROADMAP.md`'s D6 entry is deliberately terse (`**Depends
on:** D2, D3, D4, C4.`) because it is the same shape as **C5**
(`poc/chain_detect_from_evidence/`): a verification-only item chaining
already-shipped, already-separately-verified real components together for
the *continuous telemetry* path, the way C5 did for the *evidence-upload*
path. No new subsystem was built — this PoC wires D1–D5/C1/C2/C4's existing
classes together, unmodified, and reports what actually happened.

## Versions (pinned, read from this repo/host, matching every prior PoC in this chain)

- step-ca: `docker-step-ca-1` (real `admin` JWK provisioner — the only one
  actually configured on the live container, per D2's own finding).
- Redis: `docker-redis-1` (`redis:7-alpine`), stream DB 3.
- Postgres: `docker-postgres-1` (`postgres:16-alpine`).
- MinIO: `docker-minio-1` (`minio/minio:latest`).
- OpenSearch: `docker-opensearch-1` (`opensearchproject/opensearch:2.11.1`).
- RFC 3161 TSA: the same real openssl-`ts`-backed substitute used by every
  prior PoC in this chain (the dev-compose `tsa` stub is a non-functional
  empty-body responder, per `poc/rfc3161/README.md`).

## The C5 timestamp pitfall, correctly avoided here

C5's own STATUS note found that OpenSearch Security Analytics monitors
evaluate documents by whether their own `@timestamp` falls within a recent
execution window — real, historically-timestamped forensic evidence
structurally can't fire them. This PoC deliberately uses `ts = time.time()`
(real wall-clock "now") for every synthetic event, **not** the fixed
2025-01-01 constant `poc/stream_normalization/`/`poc/stream_backpressure_dlq/`
use for their own narrower unit-style checks — confirmed in the run itself
(check 4: "real stream entry's payload is genuinely near wall-clock 'now'").

It additionally hedges against a second plausible mechanism (a document-level
monitor baselining a per-shard cursor at monitor-creation time, independent
of `@timestamp`) by running **two rounds**: benign events before the
detector exists (so the index/mapping/detector have something real to
attach to), then a second real mTLS POST — including one event shaped to
trip a specific, already-known-good prepackaged rule — strictly *after* the
detector is created. This satisfies either candidate mechanism rather than
guessing at one.

## Which real rule this targets

Reused directly from C1's own real measurement
(`poc/security_analytics_field_mappings/README.md`): the `network` log
type's one real firing prepackaged rule, `1fc0809e-06bf-4de3-ad52-25e5263b7623`
("Publicly Accessible RDP Service", `attack.t1021.001`) — its Sigma body was
fetched directly from the live cluster before writing this script to
confirm its actual condition (fires for any event whose originator address
is a public/routable IP), not assumed from memory.

## What this actually does (see `output.txt` for the full real run)

1. Issues real step-ca client + server certs, starts D2's real mTLS
   collector listener (`run_dual_listener.py`) as a real subprocess.
2. **Round 1**: real mTLS POST of benign events → confirmed landing on the
   real Redis stream (D1) → real `BatchSealingService.seal_pending()` (D3,
   real WORM manifest + real TSA token + real Postgres row) → real
   `StreamNormalizationService.normalize_batch()` (D4) → real OpenSearch
   `_search` confirms the documents exist.
3. Applies C1's own real `network` log-type field-alias mapping to this
   run's fresh stream index, then creates a real per-org SA detector
   scoped to it (C2).
4. **Round 2** (strictly after the detector exists): a fresh real mTLS
   POST including the RDP-shaped trigger event → sealed → normalized →
   indexed.
5. Polls the real SA monitor's own scheduled execution (every 20s, up to
   60s) until real findings appear — **2 real findings**, both carrying
   the real `attack.t1021.001` ATT&CK tag.
6. Runs the real, unmodified `DetectionSyncService.sync_org_findings()`
   (C4) — creates real `Detection` rows, `org_id` always computed from the
   syncing tenant (never read from the finding), `case_id` correctly
   `None` (stream-sourced, honestly un-triaged).
7. **Honest provenance-linkage check**: follows a real `Detection` row's
   `matched_document_ids` back to the real OpenSearch document, and
   confirms that document's own `kronos.batch_id`/`source_id`/`event_offset`
   match the real sealed batch this chain actually produced — proving the
   full chain is genuinely connected end to end, not just independently
   working in five disconnected pieces.
8. Re-runs the sync and confirms zero new rows (idempotency, same
   precedent as C4/C5).

## Result: `output.txt` — 35/35 real checks passed

No gaps requiring a `src/` fix were found — every hop worked correctly on
the first real run, and the honest provenance-linkage check in step 7
succeeded using `Detection.matched_document_ids` (C4's existing field),
without needing any new linkage field. Real Redis stream entries, sealed
batches, OpenSearch documents, findings, and `Detection`/`audit_log` rows
this run created are deliberately left in place as inspectable proof, same
precedent as C4/C5. The throwaway SA detector itself was cleaned up (not
part of any committed `src/` path).

No `src/` changes were needed for this item — confirmed via `git status`
before committing. No new unit tests were needed for the same reason (no
new `src/` code); the existing 878-test baseline is unaffected.

## Explicitly flagged, not yet done

- Same explicit follow-ups already flagged by D3/D4/D5: nothing schedules
  `seal_pending()`/`normalize_batch()`/`sync_org_findings()` automatically
  in production yet (no beat task) — this PoC drives each stage manually,
  proving the mechanism, not automatic invocation.
- This PoC used one specific already-known-good prepackaged rule
  (`network`/RDP) as its trigger — it does not attempt to measure broader
  rule coverage for continuous-telemetry sources (that would be a C1-style
  measurement exercise for a future item, not D6's job).
