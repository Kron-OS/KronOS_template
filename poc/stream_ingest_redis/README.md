# D1 · StreamIngestAdapter ABC + Redis Streams implementation

L1 PoC: proves Redis Streams as a durable, replayable, at-least-once,
per-org-isolated telemetry transport, against the real, live dev-stack
Redis instance — before any `src/` code was written, per CLAUDE.md §F.2.

## Versions pinned (re-verified against the real running stack)

- Redis server: `redis:7-alpine` image, real running `docker-redis-1`
  container reports `redis_version: 7.4.9` (`docker exec docker-redis-1
  redis-cli info server`) — confirmed directly, not assumed from the
  image tag.
- Python client: `redis` package, real installed version in
  `~/venv` is **8.0.1**. `pyproject.toml` pins `redis>=5.0`, which 8.0.1
  satisfies — the exact version has drifted since `>=5.0` was written,
  flagged here rather than silently ignored.

## Run

```
source ~/venv/bin/activate
python poc/stream_ingest_redis/run_poc.py
```

Connects to the real, already-running dev-stack Redis on
`localhost:6379`, **DB 3** — deliberately separate from DB 0 (step-up
ticket store), DB 1 (Celery broker), DB 2 (Celery result backend), so
this PoC cannot interfere with the real Celery queue other work depends
on. All keys are additionally namespaced `kronos:stream:poc:...` and
deleted at the end of the run (confirmed via a post-run key scan, not
just trusted).

## Result: 22/22 checks passed (see `output.txt` for the full real run)

## Design decisions this PoC proves out

- **Key formula: `kronos:stream:{org_id}:{source_id}`, org first.**
  Isolation is structural, not filtered: two different orgs with the
  *identical* `source_id` (`poc-auth-log` used deliberately for both,
  Part 1) never share a key. Confirmed the real, physical key set in
  Redis contains exactly the two expected keys, and each key's raw
  `XRANGE` (bypassing any adapter logic) contains only that org's own
  payloads.
- **At-least-once via real consumer groups, not a custom ack layer.**
  `XREADGROUP` + `XPENDING` + `XAUTOCLAIM` (Redis Streams' own real
  redelivery primitive, not `XCLAIM` by explicit id list, which needs the
  caller to already know the stuck ids) is the real mechanism: an
  unacked read genuinely stays in the group's pending-entries list, a
  fresh consumer instance can reclaim it after an idle-time threshold,
  and ownership demonstrably transfers (`XPENDING`'s extended form
  reports the current owning consumer per entry, confirmed changes from
  `consumer-1` to `consumer-2`).
- **Durability is server-side, not client/process memory.** A brand-new
  connection object with a brand-new consumer name, after the original
  connection was fully closed, correctly picks up exactly the backlog
  produced while "no consumer was running" — the group's read cursor
  lives in Redis, not in any Python-side state.
- **Cross-org isolation is structural, confirmed via a real error, not
  an empty result.** Attempting to read org B's key using org A's
  consumer group name raises a real `NOGROUP` error — distinguishing
  "there is no shared subscription state between these keys at all" from
  "there's just no new data," which an empty-list return could not have
  distinguished.
- **No shared bottleneck.** A real 20,000-event burst into org A's key
  (produced via a pipelined `XADD`, completing in 0.349s) does not delay
  an independent blocking read on org B's key, which returned in 0.198s
  — well under its 1.5s block timeout, confirming one noisy tenant
  cannot starve another's consumer at the transport level.
- **Retention via `MAXLEN ~50` (approximate trimming, the efficient
  real-world mode).** 200 real writes were reduced to 100 real retained
  entries (Redis trims in whole macro-nodes for performance, so `~50`
  deliberately does not guarantee exactly 50 — confirmed the real count
  is far below 200, proving trimming genuinely happened, not merely
  assuming the `~` flag "did something").
- **Replay scope, stated honestly, not oversold:** a fresh consumer
  group created at `id=0` replays from the earliest **retained** entry
  (post-trim) — this is genuine replay-from-the-group's-own-start, not
  seek-by-arbitrary-timestamp. Redis Streams has no native timestamp
  index; only ID-ordered range scans exist. If arbitrary historical
  replay is ever needed, that is a real, separate scope this adapter does
  **not** claim to cover — recorded here as a deliberate, bounded design
  choice, not a silently-missing feature.

## What was NOT verified

- Kafka/Redpanda as an alternative backend — not attempted; the ABC is
  designed so a future concrete class can implement it with zero changes
  above the adapter, but that swap itself is unverified (correctly, since
  nothing calls for it yet — "adopted only on measured need" per the
  roadmap objective).
- Consumer-group behavior under real Redis persistence failure/restart
  (e.g. killing the `docker-redis-1` container mid-run) — this PoC
  restarts the *client*, not the *server*; server-side durability
  guarantees (AOF/RDB) are Redis's own concern, out of scope for this
  adapter-level PoC.
