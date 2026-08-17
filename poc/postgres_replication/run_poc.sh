#!/usr/bin/env bash
# Real PoC run: stand up a real postgres:16-alpine primary + real
# postgres:16-alpine streaming replica (own kronos-poc-* containers/network,
# per CLAUDE.md §F.3), write real data to the primary, confirm it
# real-replicates to the replica, and capture real pg_stat_replication /
# pg_is_in_recovery / pg_last_wal_replay_lsn output. Tears itself down at
# the end regardless of outcome.
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE="docker compose -f docker-compose.poc.yml"

cleanup() {
	echo
	echo "=== Tearing down PoC stack ==="
	$COMPOSE down -v
}
trap cleanup EXIT

echo "=== docker compose version ==="
docker compose version

echo
echo "=== Starting real primary + real replica + replication-init ==="
$COMPOSE up -d postgres-primary postgres-replica

echo
echo "=== Waiting for primary healthcheck ==="
for i in $(seq 1 30); do
	status=$(docker inspect --format '{{.State.Health.Status}}' kronos-poc-pg-primary 2>/dev/null || echo "starting")
	echo "  primary health: $status"
	[ "$status" = "healthy" ] && break
	sleep 2
done
[ "$status" = "healthy" ] || { echo "FAIL: primary never became healthy"; docker logs kronos-poc-pg-primary; exit 1; }

echo
echo "=== Waiting for replica healthcheck (pg_basebackup + streaming start) ==="
for i in $(seq 1 60); do
	status=$(docker inspect --format '{{.State.Health.Status}}' kronos-poc-pg-replica 2>/dev/null || echo "starting")
	echo "  replica health: $status ($((i*2))s)"
	[ "$status" = "healthy" ] && break
	sleep 2
done
[ "$status" = "healthy" ] || { echo "FAIL: replica never became healthy"; docker logs kronos-poc-pg-replica; exit 1; }

echo
echo "=== Replica container logs (bootstrap evidence: pg_basebackup + standby.signal) ==="
docker logs kronos-poc-pg-replica 2>&1 | tail -40

echo
echo "=== Confirm standby.signal + primary_conninfo really exist on the replica ==="
docker exec kronos-poc-pg-replica sh -c 'ls -la $PGDATA/standby.signal && grep -E "primary_conninfo|primary_slot_name" $PGDATA/postgresql.auto.conf'

echo
echo "=== pg_is_in_recovery() on the replica (must be true) ==="
docker exec kronos-poc-pg-replica psql -U kronos -d kronos -tAc "SELECT pg_is_in_recovery();"

echo
echo "=== pg_stat_replication on the PRIMARY (async, pre-sync-flip) ==="
docker exec kronos-poc-pg-primary psql -U kronos -d kronos -c \
	"SELECT application_name, client_addr, state, sync_state, sync_priority FROM pg_stat_replication;"

echo
echo "=== Running postgres-replication-init (flips primary to synchronous mode -- see"
echo "    docker-compose.poc.yml comments for why this can't happen at cold boot) ==="
$COMPOSE up postgres-replication-init
docker logs kronos-poc-pg-replication-init 2>&1

echo
echo "=== pg_stat_replication on the PRIMARY (after sync flip -- expect sync_state=sync) ==="
sleep 2
docker exec kronos-poc-pg-primary psql -U kronos -d kronos -c \
	"SELECT application_name, client_addr, state, sync_state, sync_priority, write_lsn, flush_lsn, replay_lsn FROM pg_stat_replication;"

echo
echo "=== Write real data to the PRIMARY (now under synchronous replication) ==="
docker exec kronos-poc-pg-primary psql -U kronos -d kronos -c \
	"CREATE TABLE IF NOT EXISTS replication_poc (id serial PRIMARY KEY, note text, written_at timestamptz DEFAULT now());"
docker exec kronos-poc-pg-primary psql -U kronos -d kronos -c \
	"INSERT INTO replication_poc (note) VALUES ('kronos-poc-real-write-1'), ('kronos-poc-real-write-2'), ('kronos-poc-real-write-3');"

echo
echo "=== Waiting a moment for streaming to catch up ==="
sleep 3

echo
echo "=== Query the REPLICA directly -- does the real data appear? ==="
docker exec kronos-poc-pg-replica psql -U kronos -d kronos -c \
	"SELECT id, note, written_at FROM replication_poc ORDER BY id;"

echo
echo "=== Row count comparison (must match) ==="
PRIMARY_COUNT=$(docker exec kronos-poc-pg-primary psql -U kronos -d kronos -tAc "SELECT count(*) FROM replication_poc;")
REPLICA_COUNT=$(docker exec kronos-poc-pg-replica psql -U kronos -d kronos -tAc "SELECT count(*) FROM replication_poc;")
echo "primary count=$PRIMARY_COUNT replica count=$REPLICA_COUNT"
if [ "$PRIMARY_COUNT" = "$REPLICA_COUNT" ] && [ "$PRIMARY_COUNT" = "3" ]; then
	echo "PASS: replica has the same 3 real rows written to the primary"
else
	echo "FAIL: row counts diverged"
	exit 1
fi

echo
echo "=== pg_last_wal_receive_lsn() / pg_last_wal_replay_lsn() / pg_is_in_recovery() on the REPLICA ==="
docker exec kronos-poc-pg-replica psql -U kronos -d kronos -c \
	"SELECT pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn(), pg_is_in_recovery();"

echo
echo "=== Confirm the write was truly synchronous (sync_state=sync on primary) ==="
SYNC_STATE=$(docker exec kronos-poc-pg-primary psql -U kronos -d kronos -tAc \
	"SELECT sync_state FROM pg_stat_replication WHERE application_name = 'kronos_poc_replica';")
echo "sync_state=$SYNC_STATE"
if [ "$(echo "$SYNC_STATE" | tr -d '[:space:]')" = "sync" ]; then
	echo "PASS: replica is a real synchronous standby"
else
	echo "FAIL: replica is not synchronous (got '$SYNC_STATE')"
	exit 1
fi

echo
echo "=== Attempt a write directly against the REPLICA (must be rejected -- read-only standby) ==="
docker exec kronos-poc-pg-replica psql -U kronos -d kronos -c \
	"INSERT INTO replication_poc (note) VALUES ('should-fail-read-only-standby');" || echo "  (rejected as expected -- see error above)"

echo
echo "=== PoC complete: real streaming replication, sync-state confirmed, real data confirmed on replica ==="
