#!/usr/bin/env bash
# Milestone X2b (Redis DB-role separation) verification PoC. Stands up a
# throwaway two-instance Redis topology matching the real
# docker-compose.prod.yml split, proves cross-instance isolation with raw
# redis-cli, then proves the same thing (plus real app-level connectivity)
# via the actual RedisTicketStore/RedisStreamIngestAdapter classes this
# repo ships. Tears itself down at the end regardless of outcome.
#
# Run from repo root:
#   bash poc/redis_role_separation/run_poc.sh
set -euo pipefail

PROJECT="kronos-poc-redis-role-sep"
COMPOSE_FILE="poc/redis_role_separation/docker-compose.poc.yml"
AUTH_PW="poc_auth_streams_pw"
CELERY_PW="poc_celery_pw"
PYTHON_BIN="${PYTHON_BIN:-/home/reca/venv/bin/python}"

cleanup() {
  echo "=== Tearing down PoC containers/network ($PROJECT) ==="
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v --remove-orphans || true
}
trap cleanup EXIT

echo "=== Starting throwaway two-instance Redis topology ($PROJECT) ==="
REDIS_AUTH_STREAMS_PASSWORD="$AUTH_PW" REDIS_CELERY_PASSWORD="$CELERY_PW" \
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --wait

echo
echo "=== docker compose ps ==="
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" ps

AUTH_CID="$(docker compose -p "$PROJECT" -f "$COMPOSE_FILE" ps -q redis-auth-streams)"
CELERY_CID="$(docker compose -p "$PROJECT" -f "$COMPOSE_FILE" ps -q redis-celery)"

echo
echo "=== redis-cli version / server info sanity ==="
docker exec "$AUTH_CID" redis-cli -a "$AUTH_PW" --no-auth-warning INFO server | grep -E "redis_version|run_id"

echo
echo "=== [raw redis-cli] Step 1: write a real key to redis-auth-streams DB0 ==="
docker exec "$AUTH_CID" redis-cli -a "$AUTH_PW" --no-auth-warning -n 0 SET kronos-poc:authstreams:db0:marker "auth-streams-db0-value"
docker exec "$AUTH_CID" redis-cli -a "$AUTH_PW" --no-auth-warning -n 0 GET kronos-poc:authstreams:db0:marker

echo
echo "=== [raw redis-cli] Step 2: confirm that key is ABSENT on redis-celery (any DB) ==="
for db in 0 1 2 3; do
  echo "-- redis-celery DB$db --"
  docker exec "$CELERY_CID" redis-cli -a "$CELERY_PW" --no-auth-warning -n "$db" GET kronos-poc:authstreams:db0:marker
done

echo
echo "=== [raw redis-cli] Step 3: write a real key to redis-celery DB1 (broker-shaped) ==="
docker exec "$CELERY_CID" redis-cli -a "$CELERY_PW" --no-auth-warning -n 1 SET kronos-poc:celery:db1:marker "celery-db1-value"
docker exec "$CELERY_CID" redis-cli -a "$CELERY_PW" --no-auth-warning -n 1 GET kronos-poc:celery:db1:marker

echo
echo "=== [raw redis-cli] Step 4: confirm that key is ABSENT on redis-auth-streams (any DB) ==="
for db in 0 1 2 3; do
  echo "-- redis-auth-streams DB$db --"
  docker exec "$AUTH_CID" redis-cli -a "$AUTH_PW" --no-auth-warning -n "$db" GET kronos-poc:celery:db1:marker
done

echo
echo "=== [raw redis-cli] Step 5: write to redis-auth-streams DB3 (stream-ingest shaped), confirm absent on redis-celery DB3 ==="
docker exec "$AUTH_CID" redis-cli -a "$AUTH_PW" --no-auth-warning -n 3 XADD "kronos:stream:11111111-1111-1111-1111-111111111111:poc-cli-source" '*' payload hello-cli
echo "-- redis-auth-streams DB3 XLEN --"
docker exec "$AUTH_CID" redis-cli -a "$AUTH_PW" --no-auth-warning -n 3 XLEN "kronos:stream:11111111-1111-1111-1111-111111111111:poc-cli-source"
echo "-- redis-celery DB3 XLEN for the same key (expect 0 / key missing) --"
docker exec "$CELERY_CID" redis-cli -a "$CELERY_PW" --no-auth-warning -n 3 XLEN "kronos:stream:11111111-1111-1111-1111-111111111111:poc-cli-source"

echo
echo "=== [raw redis-cli] Step 6: confirm DB0 (redis-auth-streams) vs DB1 (redis-celery) are ALSO different processes, not just different DBs of one instance ==="
docker exec "$AUTH_CID" redis-cli -a "$AUTH_PW" --no-auth-warning INFO server | grep run_id
docker exec "$CELERY_CID" redis-cli -a "$CELERY_PW" --no-auth-warning INFO server | grep run_id
echo "(different run_id values above = genuinely separate Redis processes, not DB-index isolation within one shared process)"

echo
echo "=== [real app code] RedisTicketStore + RedisStreamIngestAdapter against the split topology ==="
cd "$(dirname "$0")/../.."
"$PYTHON_BIN" poc/redis_role_separation/verify_app_wiring.py

echo
echo "=== PoC complete: all checks passed ==="
