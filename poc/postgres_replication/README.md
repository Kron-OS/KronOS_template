# PoC: real Postgres 16 streaming replication (primary + synchronous standby)

## Context

Gap Audit `docs/GAP_AUDIT_2026-08-17.md` §X2a: `docs/POSTGRES_MINIO_HA_RESEARCH.md`
(Milestone V10) §1.5 already concluded, with reasoning, "adopt Postgres
streaming replication now — 1 primary + 1 synchronous standby, no automatic
failover." That verdict was never implemented. This PoC is the real,
run-and-observed verification required by `CLAUDE.md` §F before touching
`docker-compose.prod.yml` or `charts/kronos/values.yaml`.

## Versions pinned

- `postgres:16-alpine` — the exact image tag already used by this repo's
  `docker/docker-compose.prod.yml` `postgres:` service (confirmed by
  reading that file directly, not assumed).
- Real docs fetched live for Postgres 16 specifically (not "latest"):
  - <https://www.postgresql.org/docs/16/auth-pg-hba-conf.html>
  - <https://www.postgresql.org/docs/16/runtime-config-replication.html>
  - <https://www.postgresql.org/docs/16/runtime-config-wal.html>
  - <https://www.postgresql.org/docs/16/app-pgbasebackup.html>
- Real docker-library `postgres` entrypoint script extracted directly from
  the pulled `postgres:16-alpine` image (`docker run --rm postgres:16-alpine
  cat /usr/local/bin/docker-entrypoint.sh`) — not assumed from a GitHub
  branch that may not match the pulled image.

## What this actually does

Two real `postgres:16-alpine` containers on their own throwaway
`kronos-poc-pgrepl-net` network (`kronos-poc-pg-primary`,
`kronos-poc-pg-replica`, `kronos-poc-pg-replication-init`), wired for real
physical streaming replication — no mocks, no simulated output.

- **Primary** (`postgres-primary`): boots with `wal_level=replica`,
  `max_wal_senders=10`, `max_replication_slots=10` (all `context=postmaster`
  GUCs, so they must be set at cold boot). `/docker-entrypoint-initdb.d`
  creates a dedicated `replicator` role (`REPLICATION LOGIN`) and appends a
  real `pg_hba.conf` entry for the `replication` pseudo-database (see "real
  finding" below for why this line is required at all).
- **Replica** (`postgres-replica`): a custom `replica-entrypoint.sh` that,
  on an empty `$PGDATA`, waits for the primary, then runs a real
  `pg_basebackup -D "$PGDATA" -Fp -Xs -P -R -d "host=... application_name=kronos_poc_replica"`
  against it — the real, current Postgres-16-documented way to bootstrap a
  streaming standby (`-R` writes `standby.signal` + `primary_conninfo` into
  `postgresql.auto.conf`, confirmed by direct inspection of the file after
  the run, not assumed).
- **`postgres-replication-init`** (one-shot, `restart: "no"`, same pattern
  already used in this repo's `docker-compose.prod.yml` for `keycloak-init`):
  flips the primary into synchronous mode via
  `ALTER SYSTEM SET synchronous_standby_names = 'kronos_poc_replica'; SELECT pg_reload_conf();`
  once the replica is confirmed streaming. See "real finding" below for why
  this can't happen at cold boot.

`run_poc.sh` orchestrates the whole thing end-to-end: start primary + replica
→ wait for both healthchecks → inspect the replica's `standby.signal` /
`postgresql.auto.conf` directly → confirm `pg_is_in_recovery()` → confirm
`pg_stat_replication` shows async streaming → run the sync-flip init job →
confirm `pg_stat_replication.sync_state = sync` → write real rows to the
primary → read them back from the replica directly → compare row counts →
confirm `pg_last_wal_receive_lsn()`/`pg_last_wal_replay_lsn()` on the
replica → confirm the replica rejects a direct write → tear the whole stack
down (`docker compose down -v`).

## How to run

```bash
cd poc/postgres_replication
bash run_poc.sh   # ~30s; tears itself down on exit (trap), even on failure
```

## Real finding #1: `pg_hba.conf`'s `all` database value does not cover replication connections

Confirmed via the official Postgres 16 docs (`auth-pg-hba-conf.html`):

> "The value `replication` specifies that the record matches if a physical
> replication connection is requested... Note that physical replication
> connections do not specify any particular database."

— stated as a *distinct* value from `all`. The official `postgres:16-alpine`
image's own entrypoint (extracted and read directly, see above) only ever
appends `host all all all $POSTGRES_HOST_AUTH_METHOD` to `pg_hba.conf` — it
never adds a `replication`-specific line. Without
`primary-init/02-replication-hba.sh` adding
`host replication replicator all scram-sha-256` explicitly, the replica's
`pg_basebackup` is rejected with "no pg_hba.conf entry for replication
connection" (a well-known real-world gotcha — see
`docker-library/postgres#1132`).

## Real finding #2: synchronous replication cannot be configured at cold boot without deadlocking the primary's own bootstrap

This was found the hard way — the first version of this PoC set
`synchronous_standby_names=kronos_poc_replica` + `synchronous_commit=on`
directly in the primary's startup `command:`, matching V10's verdict text
literally. It deadlocked: full transcript in `output.txt` PART 1.

Root cause: the `postgres:16-alpine` entrypoint creates the `POSTGRES_DB`
database (`kronos`) via a completely ordinary client transaction
(`CREATE DATABASE`) during its own `/docker-entrypoint-initdb.d` bootstrap —
*before* any replica can possibly exist. `synchronous_commit` defaults to
`on` in vanilla Postgres 16 (confirmed via `SELECT name, context FROM
pg_settings` against the real pinned image, not assumed), so with
`synchronous_standby_names` already naming a standby that has never
connected, that `CREATE DATABASE` blocks forever waiting for an
acknowledgment that can never arrive. The primary never finishes bootstrap,
never starts listening for real TCP connections (confirmed:
`pg_isready -h 127.0.0.1` returned "no response" while stuck), so the
replica can never connect either — a genuine deadlock, not a timing
flake.

**Real fix, confirmed reload-safe (not restart-required) via a direct query
against the pinned image:**

```
$ docker exec ... psql -U postgres -tAc \
    "SELECT name, context FROM pg_settings WHERE name = 'synchronous_standby_names';"
synchronous_standby_names|sighup
```

`context=sighup` means `synchronous_standby_names` can be changed via
`ALTER SYSTEM` + `pg_reload_conf()` with **no restart**. So the primary now
boots async-only; the `postgres-replication-init` one-shot job flips it to
synchronous mode only after the replica is confirmed healthy and streaming.
This is the sequence a competent operator would actually use, and it is what
`docker-compose.prod.yml` now implements (see below) — **this real finding
changed the shape of the production compose change from what a naive
reading of V10's verdict text alone would have produced.**

## Result: PASS — real streaming replication, real synchronous state, real data confirmed on the replica

See `output.txt` for the full, unedited transcript of both the deadlock
reproduction (PART 1) and the successful run after the fix (PART 2). Key
lines:

- `pg_stat_replication` on the primary, after the sync-flip:
  `sync_state=sync, sync_priority=1` for `application_name=kronos_poc_replica`.
- 3 real rows (`kronos-poc-real-write-1/2/3`) written to the primary appear,
  byte-identical, on a **direct query against the replica** (not the
  primary) — `primary count=3 replica count=3`.
- `pg_is_in_recovery()` = `t` on the replica throughout.
- `pg_last_wal_receive_lsn()` / `pg_last_wal_replay_lsn()` on the replica
  both advance to `0/3028078`, matching the primary's write LSN.
- Direct `INSERT` against the replica is rejected:
  `ERROR: cannot execute INSERT in a read-only transaction`.

## Real finding #3: this PoC's design was also validated against the actual committed `docker-compose.prod.yml`

After `docker/docker-compose.prod.yml` and `docker/postgres/{primary-init/*,replica-entrypoint.sh,replication-init.sh}`
were written (informed by findings #1/#2 above), those exact real files
were run as real containers too, not just this standalone PoC copy — see
`output.txt` PART 3. Only the `secrets:` `external: true` flag was swapped
for a `file:` secret (plain non-swarm `docker compose` can't resolve Swarm
external secrets); no service/volume/command definition was changed for
the test. Result: identical to PART 2 — async bootstrap, sync-mode flip,
real primary write visible on the replica.

## What this PoC does NOT cover (honest scope limits)

- **No automatic failover** — out of scope per V10 §1.5's own verdict
  ("adopt replication now, defer Patroni/etcd"). `pg_ctl promote` /
  manual promotion is a documented runbook step, not exercised here since
  no failover was requested.
- **No real Kubernetes cluster** — the Helm side of this work (`charts/kronos/values.yaml`)
  is verified via real `helm lint` / `helm template` output showing the
  read-replica manifests render correctly (see the item's own final report),
  which is the honestly-reachable subset of "verified" without a real
  cluster to `helm install` against. It was not deployed to a live cluster.
- **TLS between primary and replica** — not configured (matches this repo's
  existing internal-network trust model for Postgres in
  `docker-compose.prod.yml` today; the pinned `primary_conninfo` shows
  `sslmode=prefer`, i.e. opportunistic, same as the rest of this compose
  file's internal service-to-service traffic).

## Teardown

`run_poc.sh` tears itself down unconditionally via a `trap ... EXIT`
(`docker compose -f docker-compose.poc.yml down -v`), even on failure.
Confirmed post-run: `docker ps -a` / `docker network ls` show no
`kronos-poc-pg-*` / `kronos-poc-pgrepl-net` resources left behind.
