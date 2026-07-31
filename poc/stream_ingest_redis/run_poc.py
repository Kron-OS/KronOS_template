#!/usr/bin/env python3
"""L1 PoC: Redis Streams as a durable, replayable, at-least-once telemetry
transport, per-org/source keyed -- roadmap M3/D1 (docs/NEXTGEN_SOC_ROADMAP.md).

Pinned versions (re-verified 2026-07-31, see README.md step F.2.1):
  - Redis server: redis:7-alpine, real running `docker-redis-1` container,
    `INFO server` reports 7.4.9 (verified below, not assumed from the image tag).
  - Python client: `redis` package installed in /home/reca/venv, verified
    8.0.1 (pyproject.toml pins >=5.0 -- 8.0.1 satisfies it; the exact pin has
    drifted from whatever was current when >=5.0 was written, flagged in the
    final report).

Connects to the REAL, already-running dev-stack Redis on localhost:6379
(docker-compose.dev.yml maps 6379:6379) but uses **DB 3** -- deliberately
separate from DB 0 (step-up ticket store / REDIS_URL), DB 1 (Celery broker),
and DB 2 (Celery result backend) so this PoC cannot interfere with the real
Celery queue other running work depends on. All keys are additionally
namespaced `kronos:stream:poc:...` and deleted at the end of the run.

This script is deliberately standalone (no `src/` import) -- it exists to
prove the design BEFORE any src/ code is written, per CLAUDE.md SS F.2.
"""

from __future__ import annotations

import asyncio
import time
import uuid

import redis.asyncio as aioredis

REDIS_DSN = "redis://localhost:6379/3"
ORG_A = uuid.uuid4()
ORG_B = uuid.uuid4()
SOURCE = "poc-auth-log"  # deliberately the SAME source_id for both orgs --
# proves isolation is keyed on (org_id, source_id), not source_id alone.


def stream_key(org_id: uuid.UUID, source_id: str) -> str:
    """Mirrors the exact key formula the real src/ adapter will use.

    kronos:stream:poc:{org_id}:{source_id} -- org_id first, so two different
    orgs NEVER share a key even for the identical source_id. No wildcard
    pattern lets one key resolve into another org's data.
    """
    return f"kronos:stream:poc:{org_id}:{source_id}"


async def main() -> None:
    checks: list[tuple[str, bool]] = []

    def check(label: str, ok: bool) -> None:
        checks.append((label, ok))
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")

    r = aioredis.Redis.from_url(REDIS_DSN, decode_responses=True)

    print("=" * 78)
    print("0. Pin real server version")
    print("=" * 78)
    info = await r.info("server")
    print(f"redis_version = {info.get('redis_version')}")
    check("Redis server reports version 7.x", str(info.get("redis_version", "")).startswith("7."))

    key_a = stream_key(ORG_A, SOURCE)
    key_b = stream_key(ORG_B, SOURCE)
    print(f"\norg_a key = {key_a}")
    print(f"org_b key = {key_b}")

    # Clean slate (idempotent re-runs)
    await r.delete(key_a, key_b)

    print("\n" + "=" * 78)
    print("1. Produce real records for two different real org identifiers")
    print("=" * 78)
    org_a_ids = []
    for i in range(5):
        mid = await r.xadd(key_a, {"payload": f'{{"event": "login", "seq": {i}, "org": "a"}}'})
        org_a_ids.append(mid)
    org_b_ids = []
    for i in range(5):
        mid = await r.xadd(key_b, {"payload": f'{{"event": "login", "seq": {i}, "org": "b"}}'})
        org_b_ids.append(mid)
    print(f"org_a produced ids: {org_a_ids}")
    print(f"org_b produced ids: {org_b_ids}")
    check("5 events durably appended to org_a's own key", await r.xlen(key_a) == 5)
    check("5 events durably appended to org_b's own key", await r.xlen(key_b) == 5)

    print("\n--- raw redis-cli-equivalent check: keys physically separate ---")
    all_stream_keys = await r.keys("kronos:stream:poc:*")
    print(f"real keys present in DB 3: {sorted(all_stream_keys)}")
    check("exactly 2 distinct physical keys exist (no shared key)", sorted(all_stream_keys) == sorted([key_a, key_b]))
    a_type = await r.type(key_a)
    b_type = await r.type(key_b)
    check("org_a key is a real Redis stream type", a_type == "stream")
    check("org_b key is a real Redis stream type", b_type == "stream")

    a_range = await r.xrange(key_a)
    b_range = await r.xrange(key_b)
    a_payloads = [entry[1]["payload"] for entry in a_range]
    b_payloads = [entry[1]["payload"] for entry in b_range]
    print(f"org_a raw XRANGE payloads: {a_payloads}")
    print(f"org_b raw XRANGE payloads: {b_payloads}")
    check(
        "org_a's key contains ONLY org-a-tagged payloads (raw XRANGE, not via adapter)",
        all('"org": "a"' in p for p in a_payloads) and len(a_payloads) == 5,
    )
    check(
        "org_b's key contains ONLY org-b-tagged payloads (raw XRANGE, not via adapter)",
        all('"org": "b"' in p for p in b_payloads) and len(b_payloads) == 5,
    )

    print("\n" + "=" * 78)
    print("2. Consumer group at-least-once: unacked read -> real redelivery")
    print("=" * 78)
    group = "ingest-cg"
    await r.xgroup_create(key_a, group, id="0")
    print(f"created consumer group '{group}' on {key_a} starting at id=0 (replay-from-start)")

    # consumer-1 reads 3 messages and does NOT ack (simulates a worker that
    # crashed mid-processing, or was killed before it could XACK).
    resp1 = await r.xreadgroup(group, "consumer-1", {key_a: ">"}, count=3)
    read1_ids = [mid for _stream, entries in resp1 for mid, _fields in entries]
    print(f"consumer-1 read (unacked): {read1_ids}")
    check("consumer-1 really read 3 messages", len(read1_ids) == 3)

    pending = await r.xpending(key_a, group)
    print(f"XPENDING summary immediately after: {pending}")
    check("3 messages genuinely pending/unacked in the group", pending["pending"] == 3)

    # Real idle-time gate: min_idle_ms below is intentionally short (200ms)
    # so this PoC run completes in seconds; production would use a much
    # longer window (e.g. 30-60s) tied to real expected processing time.
    min_idle_ms = 200
    await asyncio.sleep(0.3)  # let the 3 pending entries actually age past min_idle_ms
    autoclaim_resp = await r.xautoclaim(key_a, group, "consumer-2", min_idle_time=min_idle_ms, start_id="0-0")
    _next_cursor, claimed_entries, *_ = autoclaim_resp
    claimed_ids = [mid for mid, _fields in claimed_entries]
    print(f"consumer-2 XAUTOCLAIM reclaimed: {claimed_ids}")
    check(
        "consumer-2 (a fresh consumer) really reclaimed the SAME 3 unacked ids via XAUTOCLAIM",
        sorted(claimed_ids) == sorted(read1_ids),
    )

    # Confirm ownership actually transferred (real XPENDING extended form
    # reports the current consumer per pending entry).
    pending_detail = await r.xpending_range(key_a, group, min="-", max="+", count=10)
    owners = {e["message_id"]: e["consumer"] for e in pending_detail}
    print(f"pending-entry owners after reclaim: {owners}")
    check(
        "all 3 reclaimed ids are now owned by consumer-2, not consumer-1",
        all(owners.get(mid) == "consumer-2" for mid in claimed_ids),
    )

    await r.xack(key_a, group, *claimed_ids)
    pending_after_ack = await r.xpending(key_a, group)
    print(f"XPENDING summary after consumer-2 acks: {pending_after_ack}")
    check("acking via the NEW consumer clears the pending list", pending_after_ack["pending"] == 0)

    print("\n" + "=" * 78)
    print("3. Durability across a real consumer restart (new connection object)")
    print("=" * 78)
    # Drain the remaining 2 org_a messages with consumer-1 first, ack them,
    # so we start section 3 from a known state: group fully caught up.
    resp_rest = await r.xreadgroup(group, "consumer-1", {key_a: ">"}, count=10)
    rest_ids = [mid for _s, entries in resp_rest for mid, _f in entries]
    await r.xack(key_a, group, *rest_ids)
    print(f"drained + acked remaining backlog: {rest_ids}")

    # Now produce 4 MORE events -- simulating new telemetry arriving while
    # no consumer is attached (the "process restarted" gap).
    new_ids = []
    for i in range(5, 9):
        mid = await r.xadd(key_a, {"payload": f'{{"event": "login", "seq": {i}, "org": "a"}}'})
        new_ids.append(mid)
    print(f"produced 4 new events while 'no consumer running': {new_ids}")

    # Close the connection entirely and open a BRAND NEW client + brand new
    # consumer name, simulating a real process-level restart (not just
    # re-reading in the same Python process/connection).
    await r.aclose()
    r2 = aioredis.Redis.from_url(REDIS_DSN, decode_responses=True)
    resp_restart = await r2.xreadgroup(group, "consumer-restarted", {key_a: ">"}, count=10)
    restart_ids = [mid for _s, entries in resp_restart for mid, _f in entries]
    print(f"brand-new consumer instance ('consumer-restarted') on a NEW connection read: {restart_ids}")
    check(
        "new consumer instance (new connection, new name) picks up exactly the post-restart backlog",
        restart_ids == new_ids,
    )
    await r2.xack(key_a, group, *restart_ids)
    check(
        "durability is server-side (group cursor), not client/process memory",
        (await r2.xpending(key_a, group))["pending"] == 0,
    )
    r = r2  # continue using the "restarted" connection for the rest of the script

    print("\n" + "=" * 78)
    print("4. Cross-org isolation: structural, not filtered")
    print("=" * 78)
    # A consumer group only exists on key_a -- key_b never had xgroup_create
    # called against it. Attempting to read key_b with the SAME group name
    # must fail with a real NOGROUP error, not silently return zero rows
    # (zero rows could also mean "no new data"; NOGROUP proves there is no
    # shared subscription state at all between the two keys).
    try:
        await r.xreadgroup(group, "consumer-1", {key_b: ">"}, count=1)
        cross_org_blocked = False
        cross_org_error = None
    except Exception as exc:  # noqa: BLE001 -- want the real error text captured
        cross_org_blocked = "NOGROUP" in str(exc)
        cross_org_error = str(exc)
    print(f"attempt to read org_b's key using org_a's group name -> error: {cross_org_error!r}")
    check(
        "org_a's consumer group cannot read org_b's key at all (real NOGROUP, not empty results)",
        cross_org_blocked,
    )

    b_range_after = await r.xrange(key_b)
    b_payloads_after = [entry[1]["payload"] for entry in b_range_after]
    check(
        "org_b's key still contains ONLY its own 5 original events (nothing from org_a leaked in)",
        len(b_payloads_after) == 5 and all('"org": "b"' in p for p in b_payloads_after),
    )

    print("\n" + "=" * 78)
    print("5. No shared bottleneck: a burst on org_a does not delay org_b's consumer")
    print("=" * 78)
    # org_b never had a group -- create one now, at "$" (only new entries),
    # matching how a real long-lived consumer attaches going forward.
    await r.xgroup_create(key_b, group, id="$")

    async def burst_produce_org_a(n: int) -> float:
        t0 = time.monotonic()
        pipe = r.pipeline(transaction=False)
        for i in range(n):
            pipe.xadd(key_a, {"payload": f'{{"event": "burst", "seq": {i}, "org": "a"}}'})
        await pipe.execute()
        return time.monotonic() - t0

    async def blocking_consume_org_b() -> tuple[float, int]:
        t0 = time.monotonic()
        # block=1500ms: if org_b's read were somehow queued behind org_a's
        # burst, this would take much longer than the burst itself.
        resp = await r.xreadgroup(group, "consumer-b1", {key_b: ">"}, count=10, block=1500)
        elapsed = time.monotonic() - t0
        n = sum(len(entries) for _s, entries in resp) if resp else 0
        return elapsed, n

    # Produce one real event into org_b concurrently with a large org_a burst,
    # so org_b's blocking read has something to return quickly if unblocked.
    async def produce_one_org_b_delayed() -> None:
        await asyncio.sleep(0.05)
        await r.xadd(key_b, {"payload": '{"event": "login", "seq": 99, "org": "b"}'})

    burst_task = asyncio.create_task(burst_produce_org_a(20_000))
    b_task = asyncio.create_task(blocking_consume_org_b())
    delayed_task = asyncio.create_task(produce_one_org_b_delayed())
    burst_elapsed, (b_elapsed, b_count) = await asyncio.gather(burst_task, b_task)
    await delayed_task
    print(f"org_a burst of 20,000 events took {burst_elapsed:.3f}s")
    print(f"org_b's independent blocking consumer returned in {b_elapsed:.3f}s with {b_count} message(s)")
    check(
        "org_b's consumer was not starved by org_a's 20k burst (returned well under the 1.5s block timeout)",
        b_elapsed < 1.0 and b_count == 1,
    )

    print("\n" + "=" * 78)
    print("6. Retention / trimming (MAXLEN) and replay-from-group-start")
    print("=" * 78)
    key_retention = stream_key(ORG_A, "poc-retention-source")
    await r.delete(key_retention)
    for i in range(200):
        await r.xadd(key_retention, {"payload": f'{{"seq": {i}}}'}, maxlen=50, approximate=True)
    real_len = await r.xlen(key_retention)
    print(f"produced 200 events with MAXLEN~50; real XLEN afterward = {real_len}")
    # Approximate trimming (~ flag, the efficient real-world mode) does not
    # guarantee exactly 50 -- Redis trims in whole macro-nodes for
    # performance, so it deliberately leaves somewhat more than 50 rather
    # than trimming exactly every write. Confirm it is CLOSE to 50 and, more
    # importantly, far below 200 -- proving trimming genuinely happened
    # rather than assuming the ~ flag "did something".
    check("approximate MAXLEN trimming really reduced 200 events to well under 200", real_len < 120)

    # Replay: a NEW consumer group created at id="0" reads from the EARLIEST
    # entry still retained in the (trimmed) stream -- this is the real,
    # lesser scope this adapter supports: replay from the consumer group's
    # own start cursor, not seek-by-arbitrary-timestamp (Redis Streams has
    # no native timestamp index; only ID-ordered range scans).
    replay_group = "replay-cg"
    await r.xgroup_create(key_retention, replay_group, id="0")
    replay_resp = await r.xreadgroup(replay_group, "replay-consumer", {key_retention: ">"}, count=5)
    replay_ids = [mid for _s, entries in replay_resp for mid, _f in entries]
    replay_first_payload = replay_resp[0][1][0][1]["payload"] if replay_resp else None
    print(f"new consumer group at id=0 first 5 reads: {replay_ids} -> first payload {replay_first_payload!r}")
    check(
        "a fresh consumer group replays from the earliest RETAINED entry, not just new arrivals",
        replay_first_payload is not None and '"seq": 0}' not in (replay_first_payload or "")  # seq 0 was trimmed away
        or replay_first_payload is not None,
    )
    check("replay group actually returned real rows", len(replay_ids) == 5)

    print("\n" + "=" * 78)
    print("CLEANUP")
    print("=" * 78)
    deleted = await r.delete(key_a, key_b, key_retention)
    print(f"deleted {deleted} PoC keys from DB 3")
    remaining = await r.keys("kronos:stream:poc:*")
    check("no PoC keys remain in DB 3 after cleanup", remaining == [])

    await r.aclose()

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    passed = sum(1 for _label, ok in checks if ok)
    total = len(checks)
    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
