#!/bin/sh
# Real, reproducible verification that:
#   (a) `alembic upgrade head` from an EMPTY Postgres database produces
#       every one of the 14 repositories' real tables, and
#   (b) the resulting schema is IDENTICAL (columns/types/nullability/
#       defaults/PKs/unique constraints/indexes) to the schema produced by
#       today's `create_tables()` classmethods.
#
# Uses throwaway, PoC-only containers/network per CLAUDE.md's Docker rules
# -- never touches the shared dev stack's `docker-postgres-1` or its data.
#
# Run from the repo root:
#   sh poc/alembic_migration_baseline/run_poc.sh
#
# Requires: docker, network access to pull postgres:16-alpine and
# cgr.dev/chainguard/python:latest-dev (the same base image
# docker/Dockerfile's builder stage uses -- see that file for why).

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NETWORK=kronos-poc-alembic-net
PG_CONTAINER=kronos-poc-alembic-pg
PG_PASSWORD=kronos_poc_password
IMAGE=cgr.dev/chainguard/python:latest-dev

cleanup() {
  echo "--- tearing down throwaway PoC containers/network ---"
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "--- (re)creating throwaway network + Postgres ---"
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create "$NETWORK"
docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$PG_CONTAINER" --network "$NETWORK" \
  -e POSTGRES_DB=kronos -e POSTGRES_USER=kronos -e POSTGRES_PASSWORD="$PG_PASSWORD" \
  postgres:16-alpine >/dev/null

echo "--- waiting for Postgres ---"
i=0
while ! docker exec "$PG_CONTAINER" pg_isready -U kronos >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then echo "Postgres never became ready" >&2; exit 1; fi
  sleep 1
done

docker exec "$PG_CONTAINER" psql -U kronos -d kronos -c "CREATE DATABASE alembic_target;"
docker exec "$PG_CONTAINER" psql -U kronos -d kronos -c "CREATE DATABASE createall_target;"

echo "--- alembic revision --autogenerate (against the empty alembic_target db) ---"
docker run --rm -u root --network "$NETWORK" \
  -v "$REPO_ROOT:/app" -w /app \
  -e DATABASE_URL="postgresql+asyncpg://kronos:${PG_PASSWORD}@${PG_CONTAINER}:5432/alembic_target" \
  --entrypoint /bin/sh "$IMAGE" \
  -c "pip install --quiet -e . && python -m alembic revision --autogenerate -m 'baseline schema'"

echo "--- alembic upgrade head ---"
docker run --rm -u root --network "$NETWORK" \
  -v "$REPO_ROOT:/app" -w /app \
  -e DATABASE_URL="postgresql+asyncpg://kronos:${PG_PASSWORD}@${PG_CONTAINER}:5432/alembic_target" \
  --entrypoint /bin/sh "$IMAGE" \
  -c "pip install --quiet -e . && python -m alembic upgrade head"

echo "--- create_tables() (all 14 repositories, same call sequence startup.py used) ---"
docker run --rm -u root --network "$NETWORK" \
  -v "$REPO_ROOT:/app" \
  -v "$REPO_ROOT/poc/alembic_migration_baseline/run_create_tables.py:/tmp/run_create_tables.py" \
  -w /app \
  -e DATABASE_URL="postgresql+asyncpg://kronos:${PG_PASSWORD}@${PG_CONTAINER}:5432/createall_target" \
  --entrypoint /bin/sh "$IMAGE" \
  -c "pip install --quiet -e . && python /tmp/run_create_tables.py"

echo "--- pg_dump --schema-only (both databases, for human inspection) ---"
docker exec "$PG_CONTAINER" pg_dump -U kronos -d alembic_target --schema-only --no-owner --no-privileges \
  > "$REPO_ROOT/poc/alembic_migration_baseline/alembic_produced_schema.sql"
docker exec "$PG_CONTAINER" pg_dump -U kronos -d createall_target --schema-only --no-owner --no-privileges \
  > "$REPO_ROOT/poc/alembic_migration_baseline/create_tables_produced_schema.sql"

echo "--- programmatic column/type/constraint/index diff (the real pass/fail check) ---"
docker run --rm -u root --network "$NETWORK" \
  -v "$REPO_ROOT:/app" \
  -v "$REPO_ROOT/poc/alembic_migration_baseline/compare_schemas.py:/tmp/compare_schemas.py" \
  -w /app \
  -e ALEMBIC_DB_URL="postgresql+asyncpg://kronos:${PG_PASSWORD}@${PG_CONTAINER}:5432/alembic_target" \
  -e CREATEALL_DB_URL="postgresql+asyncpg://kronos:${PG_PASSWORD}@${PG_CONTAINER}:5432/createall_target" \
  --entrypoint /bin/sh "$IMAGE" \
  -c "pip install --quiet -e . && python /tmp/compare_schemas.py" | tee "$REPO_ROOT/poc/alembic_migration_baseline/schema_comparison_output.txt"

echo "--- idempotency + downgrade sanity check ---"
docker run --rm -u root --network "$NETWORK" \
  -v "$REPO_ROOT:/app" -w /app \
  -e DATABASE_URL="postgresql+asyncpg://kronos:${PG_PASSWORD}@${PG_CONTAINER}:5432/alembic_target" \
  --entrypoint /bin/sh "$IMAGE" \
  -c "pip install --quiet -e . && \
      echo '-- upgrade head again (idempotent no-op) --' && python -m alembic upgrade head && \
      echo '-- downgrade base --' && python -m alembic downgrade base && \
      echo '-- upgrade head again from empty --' && python -m alembic upgrade head" \
  | tee "$REPO_ROOT/poc/alembic_migration_baseline/idempotency_and_downgrade_output.txt"

echo "--- done. See README.md for the verified conclusion. ---"
