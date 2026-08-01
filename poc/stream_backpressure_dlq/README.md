# PoC: D5 — backpressure, DLQ, observability (roadmap M3/D5)

## Versions (pinned, read from this repo / this host — not assumed)

- Redis: `docker-redis-1` (`redis:7-alpine`) — confirmed **7.4.9** live via
  `redis.asyncio.Redis.info("server")["redis_version"]` at the top of
  `run_poc.py`'s `main()` (matches `poc/stream_ingest_redis/`,
  `poc/batch_sealing/`, `poc/stream_normalization/`'s own findings).
- `redis` Python client: 8.0.1 (`~/venv`, matches D1's own drift note —
  `pyproject.toml` pins `>=5.0`).
- Postgres: `docker-postgres-1` (`postgres:16-alpine`), 16.14.
- MinIO: `docker-minio-1` (`minio/minio:latest`).
- OpenSearch: `docker-opensearch-1` (`opensearchproject/opensearch:2.11.1`),
  `https://localhost:9200`, `admin`/`admin`.
- RFC 3161 TSA: same real openssl-`ts`-backed substitute as `poc/rfc3161/`,
  `poc/batch_sealing/`, `poc/stream_normalization/` (the dev-compose `tsa`
  service is a non-functional empty-body stub, per `poc/rfc3161/README.md`'s
  own finding — sealing's TSA call is mandatory, not best-effort, per
  `BatchSealingService`'s own docstring, so every scenario below needs a
  real, working TSA responder even though this item isn't primarily about
  timestamping).

## Real docs/examples actually used

- Redis `XPENDING <key> <group>` summary form and `XINFO GROUPS <key>`'s
  own `lag` field: verified directly against the real, live Redis 7.4.9
  container with a small interactive script (not from memory) before
  writing `src/adapter/queue/stream_ingest.py`'s
  `RedisStreamIngestAdapter.consumer_group_health()` — captured shapes:
  ```
  XPENDING summary: {'pending': 3, 'min': b'...-0', 'max': b'...-2',
                      'consumers': [{'name': b'consumer-1', 'pending': 3}]}
  XINFO GROUPS: [{'name': b'g1', 'consumers': 1, 'pending': 3,
                   'last-delivered-id': b'...-2', 'entries-read': 3, 'lag': 2}]
  ```
  Also read `redis-py`'s own installed source
  (`redis/_parsers/helpers.py`'s `parse_xpending`/`parse_list_of_dicts`) to
  confirm exactly which fields are decoded to `str` keys vs. left as raw
  `bytes` values with `decode_responses=False` (this adapter's own
  convention, D1) — `XINFO GROUPS`' dict *keys* are decoded (`pairs_to_dict_with_str_keys`)
  but its *values* (e.g. `name`) are not, which is why
  `consumer_group_health()`'s own `_decode()` helper exists.
  Also independently confirmed both real `NOGROUP` (key/group don't exist)
  and `ERR no such key` (bare `XINFO GROUPS` on a missing key) error text,
  which the implementation's exception handling matches exactly.
- Zeek `conn.log` fields: reused verbatim from D4's own verification
  (`poc/stream_normalization/README.md`) — no new format work in this item.

## What this actually does

Drives the real, unmodified (post-D5) production pipeline for three
independent scenarios against the already-running real dev stack — no
mocks anywhere in this script.

### (a) Dead-letter: one bad event must not sink the batch

Produces 5 real events onto a real Redis stream — 4 well-formed
Zeek-conn-log-shaped JSON events and 1 deliberately malformed
(`b"{{{ not valid json at all"`) at offset 2. Seals them via the real,
unmodified `BatchSealingService` (sealing hashes raw bytes; it has no
opinion on payload content, so the malformed event seals fine — the bug
this item fixes is specifically in *normalization*, not sealing).
Normalizes via the real, **modified** `StreamNormalizationService` with a
real `PostgresDeadLetterSink`. Confirms via an **independent** real
Postgres `SELECT` (a separate round trip, not the in-process return value)
that `dead_letter_events` has exactly one row, at the correct offset, with
the exact original malformed bytes and a real `ParsingError` error_type —
and via an independent real OpenSearch `_search` that exactly the 4 good
events (offsets `[0,1,3,4]`) were indexed, not 5, not 0.

### (b) Consumer-group lag/health: real XPENDING + XINFO GROUPS

Produces 5 real events onto a fresh stream, creates a real consumer group,
consumes 3 without acking. Calls the new
`RedisStreamIngestAdapter.consumer_group_health()` and **independently
cross-checks its answer against raw `XPENDING`/`XINFO GROUPS` calls made
directly in this script** (not trusting the adapter's own parsing/return
value alone) — both agree: `pending_count=3`, `lag=2`. Then acks and drains
everything and confirms both real numbers go to zero. Finally confirms a
consumer group that was never created reports `lag=None` (not `0`) —
"unknown" and "known-zero" are kept distinguishable.

### (c) Sealer fall-behind alert: pages, does not block

`XADD`s a single real event with an **explicitly 1-hour-old message id**
onto a brand-new stream (Redis Streams allows an arbitrary starting id on a
fresh stream/key, so no real sleeping was needed to get a real 1-hour-old
pending event). Runs a real `BatchSealingService.seal_pending()` with
`stall_alert_after_seconds=60.0` (a 1-minute threshold, deliberately far
below the real ~3600s age and far below any sane
`SealingTriggerPolicy` threshold). Confirms via independent real Postgres
`SELECT`s that (1) a real `SEALER_FALL_BEHIND_DETECTED` audit row was
written with `oldest_pending_age_seconds >= 3599`, AND (2) a real
`BATCH_SEALED` row was **also** written in the very same call — proving
the alert is additive (pages) and does not block the seal it accompanies,
per this item's own documented design choice (see
`BatchSealingService`'s module docstring and
`SealerFallBehindDetectedError`'s own docstring in `src/exceptions.py`).

## Real findings during verification (fixed in this script, not hidden)

- **First real run passed 24/24.** A **second** real run (re-verifying
  idempotency) failed 2 checks: scenario (a)'s fixed `org_alias`/fixed Zeek
  event timestamps produce the **same** OpenSearch index name on every run,
  so a `match_all` query counted documents left behind by the prior run
  too (5 instead of 4). Real bug in the PoC's own assertion, not in
  `src/` — fixed by filtering the verification query on `kronos.batch_id`
  (a real `keyword`-mapped ECS field, confirmed against
  `src/adapter/opensearch/index_template.json`) scoped to *this* run's own
  batch, matching how a real operator would actually query per-batch
  anyway.
- A **third** run failed at startup with a real `OSError: [Errno 98]
  Address already in use` on the local TSA responder's port — this
  script's own throwaway `socketserver.ThreadingTCPServer` (not a real
  dev-stack service) defaults `allow_reuse_address` to `False`, so a
  rapid repeat run can catch the previous run's socket still in
  `TIME_WAIT`. Fixed by setting `allow_reuse_address = True` before
  binding. Re-ran afterward: clean 24/24 pass, confirmed idempotent
  across repeated runs — see `output.txt` for the final captured run.

## How to run

```
~/venv/bin/python3 poc/stream_backpressure_dlq/run_poc.py
```

Requires the dev-stack containers already running
(`docker-redis-1`, `docker-postgres-1`, `docker-minio-1`,
`docker-opensearch-1`) and `openssl` on `PATH`. See `output.txt` for the
actual captured output of the last real run: **24/24 checks passed.**

Leaves behind: rows in the real `sealed_batches`/`dead_letter_events`/
`audit_log` Postgres tables, WORM objects in real
`kronos-poc-d5-*` MinIO buckets, and stream-index documents in real
OpenSearch indices under `poc-d5-dlq-org` — all scoped to random `uuid4()`
org ids generated fresh per run, so re-running is always additive/safe,
matching this session's other PoCs' own convention. Not cleaned up
automatically (same precedent as `poc/batch_sealing/`, `poc/stream_normalization/`).
