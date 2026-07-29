#!/usr/bin/env bash
# Bring up the full real stack this PoC needs (Postgres, Redis, MinIO,
# OpenSearch, Keycloak), provision two Keycloak orgs + three users via the
# repo's own scripts/provision_keycloak_org.sh, mint real tokens, then run
# run_poc.py against the real FastAPI app. See README.md for findings.
#
# This is a record of the exact steps actually run for this PoC -- kept as
# documentation/reproduction, not necessarily idempotent re-run automation.
set -euo pipefail
cd "$(dirname "$0")/../.."

docker network create kronos-poc-mt-net 2>/dev/null || true

docker run -d --name kronos-poc-mt-postgres --network kronos-poc-mt-net \
  -e POSTGRES_PASSWORD=kronos_dev_password -e POSTGRES_USER=kronos -e POSTGRES_DB=kronos \
  -p 15433:5432 postgres:16-alpine

docker run -d --name kronos-poc-mt-redis --network kronos-poc-mt-net \
  -p 16380:6379 redis:7-alpine

docker run -d --name kronos-poc-mt-minio --network kronos-poc-mt-net \
  -e MINIO_ROOT_USER=kronos_minio -e MINIO_ROOT_PASSWORD=kronos_minio_dev_password \
  -p 19200:9000 -p 19201:9001 \
  minio/minio:latest server /data --console-address ":9001"

docker run -d --name kronos-poc-mt-opensearch --network kronos-poc-mt-net \
  -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p 19300:9200 -p 19301:9600 \
  opensearchproject/opensearch:2.11.1

docker run -d --name kronos-poc-mt-keycloak --network kronos-poc-mt-net \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -p 18081:8080 \
  quay.io/keycloak/keycloak:26.2 start-dev --hostname-strict=false

echo "Wait for all services healthy, then:"
echo "  1. Import docker/keycloak/kronos-realm.json via Admin API"
echo "  2. scripts/provision_keycloak_org.sh twice (ORG_ALIAS=acme, ORG_ALIAS=beta)"
echo "  3. Create + role-assign + org-link a 'case-lead-acme' user (analyst/case-lead"
echo "     are pre-seeded but land in different orgs by default)"
echo "  4. Mint tokens for analyst, case-lead, case-lead-acme -> /tmp/*_token.txt"
echo "  5. source the env vars below and run: python poc/multi_tenancy/run_poc.py"
echo ""
echo "export DATABASE_URL=postgresql+asyncpg://kronos:kronos_dev_password@localhost:15433/kronos"
echo "export REDIS_URL=redis://localhost:16380/0"
echo "export MINIO_ENDPOINT=localhost:19200"
echo "export MINIO_ACCESS_KEY=kronos_minio"
echo "export MINIO_SECRET_KEY=kronos_minio_dev_password"
echo "export MINIO_USE_TLS=false"
echo "export OPENSEARCH_URL=http://localhost:19300"
echo "export OPENSEARCH_USERNAME=admin"
echo "export OPENSEARCH_PASSWORD=admin"
echo "export OPENSEARCH_SECURITY_ENABLED=false"
echo "export KEYCLOAK_URL=http://localhost:18081"
echo "export KEYCLOAK_REALM=kronos"
echo "export KEYCLOAK_CLIENT_ID=kronos-backend"
echo "export KEYCLOAK_CLIENT_SECRET=dev-backend-secret-poc"
echo "export VAULT_URL=http://localhost:18200"
echo "export VAULT_TOKEN=root"
echo "export CELERY_BROKER_URL=redis://localhost:16380/1"
echo "export CELERY_RESULT_BACKEND=redis://localhost:16380/2"
echo "export ENVIRONMENT=development"

echo "Teardown: docker rm -f kronos-poc-mt-postgres kronos-poc-mt-redis kronos-poc-mt-minio kronos-poc-mt-opensearch kronos-poc-mt-keycloak && docker network rm kronos-poc-mt-net"
