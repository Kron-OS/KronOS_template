#!/usr/bin/env bash
# Real PoC: what happens to primary WRITES when the synchronous standby
# named in synchronous_standby_names dies, using the exact same
# postgres:16-alpine image, GUCs, and sync-mode-flip sequence
# docker-compose.prod.yml / charts/kronos/values.yaml actually configure
# (synchronous_standby_names='<replica_app_name>', synchronous_commit
# default "on" i.e. numSynchronousReplicas=1 semantics). Own throwaway
# kronos-poc-pgsf-* containers/network, torn down on exit even on failure.
#
# This does NOT touch docker-postgres-1 or any shared dev-stack container.
set -uo pipefail

cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.poc.yml"
OUT="output.txt"
: > "$OUT"

log() { echo "$@" | tee -a "$OUT"; }

cleanup() {
	log ""
	log "=== TEARDOWN ==="
	$COMPOSE down -v --remove-orphans >>"$OUT" 2>&1
}
trap cleanup EXIT

log "=== PART 0: bring up primary + replica, flip to synchronous mode ==="
$COMPOSE up -d postgres-primary >>"$OUT" 2>&1
log "waiting for primary healthy..."
for i in $(seq 1 30); do
	state=$(docker inspect -f '{{.State.Health.Status}}' kronos-poc-pgsf-primary 2>/dev/null)
	[ "$state" = "healthy" ] && break
	sleep 2
done
log "primary health: $state"

$COMPOSE up -d postgres-replica >>"$OUT" 2>&1
log "waiting for replica healthy..."
for i in $(seq 1 40); do
	state=$(docker inspect -f '{{.State.Health.Status}}' kronos-poc-pgsf-replica 2>/dev/null)
	[ "$state" = "healthy" ] && break
	sleep 2
done
log "replica health: $state"

$COMPOSE up postgres-replication-init >>"$OUT" 2>&1

log ""
log "=== confirm sync_state=sync on primary ==="
docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"SELECT application_name, state, sync_state, sync_priority FROM pg_stat_replication;" 2>&1 | tee -a "$OUT"

log ""
log "=== PART 1: baseline write latency, replica healthy ==="
BASELINE_START=$(date +%s.%N)
docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"CREATE TABLE IF NOT EXISTS t(id serial primary key, v text); INSERT INTO t(v) VALUES ('baseline-row');" 2>&1 | tee -a "$OUT"
BASELINE_END=$(date +%s.%N)
log "baseline INSERT wall time: $(echo "$BASELINE_END - $BASELINE_START" | bc) seconds"

log ""
log "=== PART 2: kill the synchronous standby (our own container) ==="
docker stop kronos-poc-pgsf-replica >>"$OUT" 2>&1
log "replica stopped. Confirm primary sees it as gone:"
docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"SELECT application_name, state, sync_state FROM pg_stat_replication;" 2>&1 | tee -a "$OUT"
log "(empty result set above = primary has zero WAL receivers connected -- the named sync standby is gone)"

log ""
log "=== PART 3: attempt a real write against the primary with the sync standby DEAD, bounded by a 12s client-side timeout ==="
log "(current effective synchronous_standby_names + synchronous_commit, for the record:)"
docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"SHOW synchronous_standby_names; SHOW synchronous_commit;" 2>&1 | tee -a "$OUT"

WRITE_START=$(date +%s.%N)
timeout 12s docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"INSERT INTO t(v) VALUES ('after-replica-death');" 2>&1 | tee -a "$OUT"
WRITE_RC=$?
WRITE_END=$(date +%s.%N)
log "INSERT attempt exit code: $WRITE_RC (124 = timed out / did not return within 12s)"
log "INSERT attempt wall time before timeout/return: $(echo "$WRITE_END - $WRITE_START" | bc) seconds"

log ""
log "=== confirm the row is NOT visible yet from a separate, concurrent read connection (proves COMMIT itself is what's blocked, not just this client) ==="
timeout 5s docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"SELECT count(*) FROM t WHERE v='after-replica-death';" 2>&1 | tee -a "$OUT"

log ""
log "=== PART 4: does the ORIGINAL blocked backend eventually complete once we bring the replica back? ==="
log "(re-issuing the same insert in the background, then restarting the replica, then waiting)"
docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"INSERT INTO t(v) VALUES ('recovery-test-row');" > /tmp/kronos_poc_pgsf_bg_insert.log 2>&1 &
BG_PID=$!
sleep 2
log "backgrounded INSERT still running after 2s (expected -- still blocked waiting for sync ack): $(kill -0 $BG_PID 2>/dev/null && echo yes || echo no)"

$COMPOSE up -d postgres-replica >>"$OUT" 2>&1
log "restarting replica container (same volume, should reconnect as streaming replica)..."
for i in $(seq 1 40); do
	state=$(docker inspect -f '{{.State.Health.Status}}' kronos-poc-pgsf-replica 2>/dev/null)
	[ "$state" = "healthy" ] && break
	sleep 2
done
log "replica health after restart: $state"

wait $BG_PID
BG_RC=$?
log "backgrounded INSERT (started while replica was dead) finished with rc=$BG_RC once replica reconnected:"
cat /tmp/kronos_poc_pgsf_bg_insert.log | tee -a "$OUT"

log ""
log "=== final replication state ==="
docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"SELECT application_name, state, sync_state FROM pg_stat_replication;" 2>&1 | tee -a "$OUT"
docker exec kronos-poc-pgsf-primary psql -U kronos -d kronos -c \
	"SELECT id, v FROM t ORDER BY id;" 2>&1 | tee -a "$OUT"

log ""
log "=== DONE ==="
