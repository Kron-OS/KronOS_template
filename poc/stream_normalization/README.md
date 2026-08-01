# PoC: StreamNormalizationService — continuous normalization (stream → ECS, roadmap M3/D4)

**Superseded constructor signature, flagged 2026-08-01 (roadmap M3/D5):**
`StreamNormalizationService.__init__` gained two required parameters
(`dead_letter_sink`, `audit_log`) and `normalize_batch()` now returns a
`StreamNormalizationResult` (`indexed_count`/`dead_lettered_count`), not a
bare `int` — see `poc/stream_backpressure_dlq/` for D5's own PoC, which
exercises the current signature for real. This script/output below is left
unmodified as the accurate historical record of what D4 actually verified
at the time; it will raise a `TypeError` if run as-is against the
current `src/`.

## Versions (pinned, read from this repo / this host — not assumed)

- Redis: `docker-redis-1` (`redis:7-alpine`), 7.4.9 (matches `poc/stream_ingest_redis/`, `poc/batch_sealing/`).
- Postgres: `docker-postgres-1` (`postgres:16-alpine`), 16.14.
- MinIO: `docker-minio-1` (`minio/minio:latest`).
- OpenSearch: `docker-opensearch-1` (`opensearchproject/opensearch:2.11.1`),
  `https://localhost:9200`, `admin`/`admin` — confirmed live via
  `curl -k -u admin:admin https://localhost:9200/_cluster/health` (200,
  `docker-cluster`) before writing this PoC.
- RFC 3161 TSA: same real openssl-`ts`-backed substitute as `poc/rfc3161/`
  and `poc/batch_sealing/` (the dev-compose `tsa` stub is an empty-body
  non-responder, per `poc/rfc3161/README.md`'s own finding).
- Zeek `conn.log` field reference: **independently re-verified** (not just
  trusted from the implementation's own docstring) against Zeek's real
  source immediately before writing this PoC —
  `raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek`'s
  `Conn::Info` record: `ts: time`, `duration: interval` (both are
  fractional-second Unix epoch floats in Zeek's default JSON log writer),
  `proto: transport_proto`, `orig_bytes`/`resp_bytes: count`. Matches
  `src/application/stream_source_registry.py`'s `ZeekConnLogNormalizer`.

## What this actually does

Drives the real, unmodified production pipeline end to end against the
already-running real dev stack:

1. Produces 4 real Zeek `conn.log`-shaped JSON events onto a real Redis
   stream (`RedisStreamIngestAdapter`, D1).
2. Seals them into one real `SealedBatch` via the real
   `BatchSealingService` (D3) — a real WORM manifest in MinIO, a real
   openssl-`ts`-issued TSA token, a real Postgres row.
3. Runs the real `StreamNormalizationService.normalize_batch()` (D4, the
   component this item delivers) against that real sealed batch: fetches
   the real WORM manifest, runs each event through the real
   `ZeekConnLogNormalizer`, and bulk-indexes the results via the real
   `TimelineIngestionService`/`OpenSearchClient` into real OpenSearch.
4. **Independently confirms via a real `POST <index>/_search`** (a
   completely separate HTTP round trip, not the service's own return
   value) that the resulting documents have the correct ECS field names
   (`@timestamp`, `source.ip`, `network.transport`, `network.protocol`,
   `event.duration` — correctly unit-converted from Zeek's seconds to
   ECS's nanoseconds) **and** the correct `kronos.*` `StreamProvenance`
   fields (`source_id`, `batch_id` matching the real sealed batch's id,
   `event_offset` 0..3 matching ingestion order, and `case_id` correctly
   absent — a stream event is un-triaged at ingest).

Run:
```
~/venv/bin/python3 poc/stream_normalization/run_poc.py
```

## Result: `output.txt` — 15/15 real checks passed on the first run

No bugs found in the dead subagent's implementation during this
verification pass — `StreamNormalizationService`, `ZeekConnLogNormalizer`,
`StreamSourceNormalizerRegistry`, and the `TimelineRecord.kronos` widening
to the `Provenance` discriminated union all worked correctly against real
infrastructure on the first attempt.

**What I (the orchestrator) found and fixed during verification, before
trusting this as done:**

- **`mypy src/ --ignore-missing-imports` had 18 new errors** introduced by
  widening `TimelineRecord.kronos` to `EvidenceProvenance | StreamProvenance`
  that the dead subagent never ran (it died before reaching that checklist
  item in CLAUDE.md §D). Confirmed the true baseline was 29 pre-existing
  errors (via `git stash -u` — stashing *including* untracked new files,
  not just tracked diffs, which a first careless attempt missed) vs. 47
  with D4's changes applied. Fixed for real, not suppressed wholesale:
  - `src/application/timeline_ingest.py`'s `_fallback_id`/
    `_fallback_stream_id` helpers and `src/external/parsers/archive.py`'s
    `_stamp_source_path` each access one specific provenance subtype's
    fields on what is now a union type — added real `isinstance()`
    assertions (type-narrowing, and a genuine runtime guard: a stream
    record reaching the evidence-only helper, or vice versa, is a real
    caller bug that should fail loudly).
  - `timeline_ingest.py`'s `details_base` dict needed an explicit
    `dict[str, Any]` annotation (dict invariance, not a real bug).
  - `src/application/stream_normalization.py` hits the exact same
    "pydantic v2 without the mypy plugin can't verify `populate_by_name`
    keyword construction" symptom already documented and suppressed in
    `pyproject.toml` for `src.external.parsers.*` — added it to that same
    override (`call-arg`/`arg-type`), not a new one.
  - After these fixes: `mypy` is back to exactly the 29-error pre-existing
    baseline, zero new errors.
- **`black --check` flagged one file** (`timeline_normalization.py`, an
  extra blank line) — reformatted.
- `ruff check` on the touched files: zero new issues (one pre-existing
  E501 in `stream.py` predates D4, confirmed via `git show` on the D3
  commit).
- Independently re-ran the full unit suite (never trusting a subagent's
  self-report) both *before* adding my own new test files (**850 passed**,
  confirming zero regressions from D4's `src/` changes against the D3
  baseline) and *after* adding unit tests for the two files the dead
  subagent hadn't gotten to yet (`stream_source_registry.py`,
  `stream_normalization.py`) — see the roadmap STATUS note for the final
  count.

## Explicitly flagged, not yet done

- **Only one source normalizer exists** (`ZeekConnLogNormalizer`) — this is
  the roadmap's own stated gate ("architectural extensibility, not source
  coverage"), not a gap; a second real source is a natural, low-risk
  follow-up once one is actually needed.
- **`StreamSourceNormalizer.source_id` keys on an exact string match**
  (documented in the ABC's own docstring) — a deployment with many
  per-host collectors of the same *format* under distinct per-host
  `source_id`s (D2's own `edr-vendor-x-host42` example) would need a
  prefix or source-type-field lookup instead. Not needed for this pass's
  one concrete source.
- **Nothing schedules `normalize_batch()` automatically** — no beat task,
  no trigger-on-seal wiring. Mirrors D3's own explicit scope note (sealing
  itself isn't scheduled yet either); this item's job was proving the
  mechanism produces correct ECS documents when invoked, not automatic
  invocation, which is D5/D6's job.
