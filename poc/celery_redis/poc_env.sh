#!/usr/bin/env bash
# Shared env vars for the celery_redis PoC — real Redis (kronos-poc-celery-redis,
# host port 16379) as broker/backend, real Postgres (kronos-poc-celery-postgres,
# host port 15432) so worker_init's wire_dependencies_sync() can genuinely
# create tables instead of skipping the real dependency wiring. Every other
# Settings field is a required SecretStr/str with no default (see src/config.py)
# so it must be present for `Settings()` to construct at all, even though this
# PoC does not exercise MinIO/OpenSearch/Keycloak/Vault.
export DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:15432/postgres"
export REDIS_URL="redis://localhost:16379/0"
export CELERY_BROKER_URL="redis://localhost:16379/1"
export CELERY_RESULT_BACKEND="redis://localhost:16379/2"
export MINIO_ENDPOINT="localhost:19999"
export MINIO_ACCESS_KEY="poc-access-key"
export MINIO_SECRET_KEY="poc-secret-key"
export OPENSEARCH_URL="http://localhost:19998"
export OPENSEARCH_USERNAME="poc-user"
export OPENSEARCH_PASSWORD="poc-pass"
export KEYCLOAK_URL="http://localhost:19997"
export KEYCLOAK_CLIENT_SECRET="poc-secret"
export VAULT_URL="http://localhost:19996"
export VAULT_TOKEN="poc-token"
export ENVIRONMENT="test"
