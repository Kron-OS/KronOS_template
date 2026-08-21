# PoC: what happens to primary writes when the synchronous standby dies

## Context

Scoped by a scale/reliability review of everything landed since Task #14
(`docs/assessments/scale_reliability_review.md`, 2026-08-15). X2a
(`docs/GAP_AUDIT_2026-08-17.md` / commit `8c06662`) added real Postgres 16
streaming replication: 1 primary + 1 synchronous standby
(`synchronous_standby_names='<replica app name>'`, `synchronous_commit=on`
i.e. `numSynchronousReplicas=1`), no automatic failover. That work already
found and fixed a real cold-boot deadlock (baking `synchronous_standby_names`
in at first boot deadlocks the primary's own database-creation bootstrap —
`poc/postgres_replication/README.md` "real finding #2"). This PoC does not
re-find that; it asks the next, still-undocumented question: **once the
cluster is past cold start and steady-state in sync mode, what happens if
the synchronous standby dies or falls behind?**

## Versions pinned

Identical to `poc/postgres_replication/`: `postgres:16-alpine` (matches
`docker/docker-compose.prod.yml`'s pinned `postgres:` image tag exactly),
same GUCs, same sync-mode-flip sequencing
(`synchronous_standby_names` has `context=sighup`, flipped post-bootstrap
via a one-shot init job — reusing the already-verified pattern rather than
re-deriving it).

## What this actually does

Own throwaway `kronos-poc-pgsf-*` containers on their own
`kronos-poc-pgsyncfail-net` network (never touches `docker-postgres-1` or
any other real dev-stack container):

1. Boots primary + replica, confirms `pg_stat_replication.sync_state=sync`.
2. Runs a baseline `INSERT` while the replica is healthy (control case).
3. `docker stop`s our own replica container (simulating the replica dying).
4. Confirms `pg_stat_replication` on the primary is now empty (zero WAL
   receivers).
5. Attempts a real `INSERT` against the primary, client-bounded by a 12s
   `timeout`.
6. Confirms, from a second concurrent connection, that the row is not
   visible (i.e. the `COMMIT` itself is blocked server-side, not just the
   one client hanging).
7. Starts a second `INSERT` in the background, then brings the replica back
   up, and waits to see whether the blocked commit ever completes.

## Real, observed result (see `output.txt` for the full captured transcript)

- Baseline `INSERT` while replica is healthy: **0.24s**.
- With the sync standby dead, `pg_stat_replication` shows **zero rows** —
  the primary has no WAL receiver at all.
- The `INSERT` attempted while the standby was dead **did not return within
  the 12s client timeout** (`timeout` exit code 124 — process killed, query
  never returned "INSERT 0 1").
- A concurrent read (`SELECT count(*) FROM t WHERE v='after-replica-death'`)
  returned `0` while the standby was down — confirming the `COMMIT` really
  is blocked server-side, not merely a slow client round-trip.
- A second `INSERT`, backgrounded and left running while the standby was
  down, was still alive after 2s (still blocked).
- Once the replica container was restarted and reconnected as a streaming
  standby, **both previously-blocked inserts completed** — the final table
  contents show all three rows (`baseline-row`, `after-replica-death`,
  `recovery-test-row`), in commit order, once the sync ack became available
  again.

**Conclusion, directly observed, not inferred:** with
`synchronous_standby_names` naming the one read replica and
`synchronous_commit=on` (this repo's actual production configuration —
`charts/kronos/values.yaml`'s `postgresql.replication.numSynchronousReplicas: 1`
/ `docker-compose.prod.yml`'s `postgres-replication-init` service), **a dead
or unreachable synchronous standby does not degrade primary write
throughput — it stops primary writes entirely**, for as long as the standby
stays down, with no configured timeout that would make Postgres give up and
commit locally instead. This is standard, correctly-implemented Postgres
synchronous-replication behavior (not a bug in this repo's config), but it
means X2a traded one risk (losing committed data if the primary dies with
unreplicated WAL) for a different one (a **replica** outage now takes down
all evidence-processing writes on the **primary**, platform-wide) — and nothing
in `docs/deployment.md`, `docs/POSTGRES_MINIO_HA_RESEARCH.md`, or
`charts/kronos/values.yaml`'s comments currently states this steady-state
consequence; only the cold-start caveat is documented.

## How to run

```bash
cd poc/postgres_sync_replica_failure
bash run_poc.sh   # ~35s; tears itself down on exit (trap), even on failure
```
