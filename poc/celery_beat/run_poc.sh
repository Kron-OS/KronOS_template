#!/usr/bin/env bash
# PoC: real Celery beat task BODIES (abort_orphan_uploads, abort_orphan_parses,
# auto_dispatch_received, anchor_audit_log from src/external/celery_app.py)
# against real seeded-stale Postgres rows. These tasks are scheduled hourly/
# daily via crontab -- no existing PoC or test has ever actually run them
# against real data old enough to trigger their timeout logic; unit tests
# (if any) would need to fake the clock, which is not the same as a real
# row genuinely older than the cutoff in a real database.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

PG_PORT=15540
REDIS_PORT=16390

docker rm -f kronos-poc-beat-postgres kronos-poc-beat-redis >/dev/null 2>&1 || true

docker run -d --name kronos-poc-beat-postgres \
  -e POSTGRES_DB=kronos -e POSTGRES_USER=kronos -e POSTGRES_PASSWORD=kronos_poc_pw \
  -p ${PG_PORT}:5432 \
  postgres:16-alpine
docker run -d --name kronos-poc-beat-redis -p ${REDIS_PORT}:6379 redis:7-alpine

until docker exec kronos-poc-beat-postgres pg_isready -U kronos >/dev/null 2>&1; do sleep 2; done
until docker exec kronos-poc-beat-redis redis-cli ping 2>/dev/null | grep -q PONG; do sleep 2; done
echo "Postgres + Redis ready"

# Full Settings() env -- only DATABASE_URL/REDIS_URL/CELERY_* point at real
# services these tasks actually touch; MinIO/Keycloak/Vault/OpenSearch are
# required fields but never called by these four tasks (OpenSearchClient
# performs no network I/O at construction, confirmed in
# tests/unit/adapter/test_opensearch_client.py's own fixture comment), so
# dummy unreachable values are honest here, not a shortcut around anything
# these tasks actually do.
export DATABASE_URL="postgresql+asyncpg://kronos:kronos_poc_pw@localhost:${PG_PORT}/kronos"
export REDIS_URL="redis://localhost:${REDIS_PORT}/0"
export CELERY_BROKER_URL="redis://localhost:${REDIS_PORT}/0"
export CELERY_RESULT_BACKEND="redis://localhost:${REDIS_PORT}/1"
export MINIO_ENDPOINT="localhost:1"
export MINIO_ACCESS_KEY="unused"
export MINIO_SECRET_KEY="unused"
export OPENSEARCH_URL="http://localhost:1"
export OPENSEARCH_USERNAME="unused"
export OPENSEARCH_PASSWORD="unused"
export KEYCLOAK_URL="http://localhost:1"
export KEYCLOAK_CLIENT_SECRET="unused"
export VAULT_URL="http://localhost:1"
export VAULT_TOKEN="unused"
export TSA_URL="http://127.0.0.1:20318/"

echo "Environment configured. Running run_poc.py..."
source ~/venv/bin/activate 2>/dev/null || true
python3 "$SCRIPT_DIR/run_poc.py"
