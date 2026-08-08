#!/usr/bin/env bash
# PoC: real tenant storage usage/quota enforcement (docs/TENANT_USAGE_QUOTA.md)
# against real Postgres 16 + real Redis 7 + real MinIO, using the REAL,
# unmodified src/ classes (StorageQuotaGate, TenantUsageService,
# EvidenceIntakeService, ParsingOrchestrationService) and the REAL Celery
# task functions (auto_resume_quota_held, dispatch_parse, parse_artefact_fast)
# from src/external/celery_app.py -- mirrors poc/celery_beat/run_poc.sh's
# established pattern exactly (throwaway kronos-poc-* Postgres/Redis, plain
# sync top-level calls to the real task functions, no broker roundtrip
# needed to exercise task BODY logic).
#
# OpenSearch is the one dependency reused from the already-running shared
# dev stack (docker-compose.dev.yml's opensearch-1, https://localhost:9200)
# rather than a fresh throwaway container: execute_parse() (via the real,
# unmodified celery_runtime.py::_build_task_resources()) unconditionally
# builds a real TimelineIngestionService and calls ingest_records() on
# success, so reaching a real COMPLETE state requires a REACHABLE
# OpenSearch -- a dummy/unreachable one (as poc/celery_beat uses for the
# four tasks that never touch OpenSearch) would turn the final "resume to
# COMPLETE" step into a real StorageError -> ERROR instead. Read-only
# credentials are not touched; this only adds a new kronos-poc-quota-* org's
# indices, never modifying any other org's data.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

PG_PORT=15541
REDIS_PORT=16391
MINIO_PORT=19100
MINIO_CONSOLE_PORT=19101

docker rm -f kronos-poc-quota-postgres kronos-poc-quota-redis kronos-poc-quota-minio >/dev/null 2>&1 || true

docker run -d --name kronos-poc-quota-postgres \
  -e POSTGRES_DB=kronos -e POSTGRES_USER=kronos -e POSTGRES_PASSWORD=kronos_poc_pw \
  -p ${PG_PORT}:5432 \
  postgres:16-alpine

docker run -d --name kronos-poc-quota-redis -p ${REDIS_PORT}:6379 redis:7-alpine

docker run -d --name kronos-poc-quota-minio \
  -e MINIO_ROOT_USER=kronos_poc_minio -e MINIO_ROOT_PASSWORD=kronos_poc_minio_pw \
  -p ${MINIO_PORT}:9000 -p ${MINIO_CONSOLE_PORT}:9001 \
  minio/minio:latest server /data --console-address ":9001"

until docker exec kronos-poc-quota-postgres pg_isready -U kronos >/dev/null 2>&1; do sleep 2; done
until docker exec kronos-poc-quota-redis redis-cli ping 2>/dev/null | grep -q PONG; do sleep 2; done
until curl -sf "http://localhost:${MINIO_PORT}/minio/health/live" >/dev/null 2>&1; do sleep 2; done
echo "Postgres + Redis + MinIO ready"

# Full Settings() env. DATABASE_URL/REDIS_URL/CELERY_*/MINIO_* point at the
# real throwaway containers above. OPENSEARCH_* points at the already-
# running shared dev-stack OpenSearch (see header comment). KEYCLOAK_*/
# VAULT_* are required Settings fields this feature's code paths never
# touch (no Keycloak/Vault calls anywhere in EvidenceIntakeService/
# ParsingOrchestrationService/the quota classes) -- dummy unreachable
# values are honest here, matching poc/celery_beat's own precedent for the
# fields ITS tasks never touch.
export DATABASE_URL="postgresql+asyncpg://kronos:kronos_poc_pw@localhost:${PG_PORT}/kronos"
export REDIS_URL="redis://localhost:${REDIS_PORT}/0"
export CELERY_BROKER_URL="redis://localhost:${REDIS_PORT}/1"
export CELERY_RESULT_BACKEND="redis://localhost:${REDIS_PORT}/2"
export MINIO_ENDPOINT="localhost:${MINIO_PORT}"
export MINIO_ACCESS_KEY="kronos_poc_minio"
export MINIO_SECRET_KEY="kronos_poc_minio_pw"
export MINIO_USE_TLS="false"
export OPENSEARCH_URL="https://localhost:9200"
export OPENSEARCH_USERNAME="admin"
export OPENSEARCH_PASSWORD="admin"
export OPENSEARCH_SECURITY_ENABLED="true"
export KEYCLOAK_URL="http://localhost:1"
export KEYCLOAK_CLIENT_SECRET="unused"
export VAULT_URL="http://localhost:1"
export VAULT_TOKEN="unused"

echo "Environment configured. Running run_poc.py..."
"${PYTHON_BIN:-/home/reca/venv/bin/python3}" "$SCRIPT_DIR/run_poc.py"
EXIT_CODE=$?

if [ "${KRONOS_POC_KEEP_CONTAINERS:-0}" != "1" ]; then
  echo "Tearing down kronos-poc-quota-* containers..."
  docker rm -f kronos-poc-quota-postgres kronos-poc-quota-redis kronos-poc-quota-minio >/dev/null 2>&1 || true
fi

exit $EXIT_CODE
