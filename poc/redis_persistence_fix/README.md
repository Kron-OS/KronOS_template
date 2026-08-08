# PoC: `docker-compose.dev.yml` Redis persistence fix (roadmap P1)

**Objective (docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md §0/P1, from the Kafka
research pass):** `docker-compose.dev.yml`'s `redis` service had **zero**
persistence configured — no `--appendonly`, no `--save` override, no
volume — meaning any `docker compose down`/container recreation lost all
unsealed stream data outright, not just data lost in a rare hard-crash
AOF-fsync window. `docker-compose.prod.yml` already had this correctly
configured (`--appendonly yes` + a named volume); dev did not.

## Fix

`docker/docker-compose.dev.yml`: added `command: redis-server --appendonly
yes` and a new named volume `redis_dev_data:/data`, mirroring prod's own
shape exactly. Deliberately did NOT add `--requirepass` (prod has one, dev
doesn't) — that's a separate, unrelated behavior change (every other dev
service is also unauthenticated) out of scope for a persistence-only fix.

## Real verification (against the actual live dev stack, not a throwaway container)

```
$ docker exec docker-redis-1 redis-cli SET kronos_persistence_poc_key "before-recreate"
OK
$ docker exec docker-redis-1 redis-cli GET kronos_persistence_poc_key
before-recreate

$ docker compose -f docker/docker-compose.dev.yml up -d redis
 Volume docker_redis_dev_data Creating
 Volume docker_redis_dev_data Created
 Container docker-redis-1 Recreate
 Container docker-redis-1 Recreated

$ docker exec docker-redis-1 redis-cli GET kronos_persistence_poc_key
(nil)
```

The first key was correctly LOST on this first recreation — real,
reproduced proof the bug existed (the volume didn't exist before this fix,
so the container's prior writable-layer data could not have carried over
regardless; this is exactly the same class of loss a real `docker compose
down` would have caused before this fix, at any time, not just on a crash).

```
$ docker exec docker-redis-1 redis-cli SET kronos_persistence_poc_key2 "after-fix-should-survive"
OK
$ docker exec docker-redis-1 redis-cli CONFIG GET appendonly
appendonly
yes

$ docker compose -f docker/docker-compose.dev.yml stop redis
$ docker compose -f docker/docker-compose.dev.yml rm -f redis
$ docker compose -f docker/docker-compose.dev.yml up -d redis
$ docker exec docker-redis-1 redis-cli GET kronos_persistence_poc_key2
after-fix-should-survive
```

**The second key survived a full container stop + remove + recreate** —
real proof the fix works, not just that the config parses. `docker compose
-f docker/docker-compose.dev.yml ps` confirmed `celery-worker`/
`celery-beat`/`kronos-backend` all stayed up and reconnected cleanly
through the brief Redis restart (their own existing Redis client
retry/reconnect logic, unmodified). Test keys cleaned up afterward
(`DEL`, confirmed `DBSIZE` back to 0).

## Scope

This is a config-only fix — no `src/` changes, no test suite impact.
`docker compose -f docker/docker-compose.dev.yml config --quiet` exits 0.
