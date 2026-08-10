#!/usr/bin/env bash
# Real, end-to-end verification of the now-security-enabled
# docker/docker-compose.test.yml (Gap Audit P1-14 / V3): brings up the real
# file (via a LOCAL-ONLY port-remap override -- see docker-compose.override.yml
# in this directory -- to avoid colliding with this host's already-running
# docker-compose.dev.yml stack), lets the real opensearch-init/keycloak-init
# one-shot services run to completion, provisions a second org for the
# isolation proof, then runs the real verification script.
#
# Project name kronos-poc-cisec keeps every container/network/volume this
# creates fully separate from the shared dev stack's own "docker_*"-prefixed
# resources (CLAUDE.md: never touch containers/volumes this agent didn't
# create). Torn down at the end unless KEEP_STACK=1 is set.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT=kronos-poc-cisec
COMPOSE=(docker compose -p "$PROJECT" -f "$REPO_ROOT/docker/docker-compose.test.yml" -f "$SCRIPT_DIR/docker-compose.override.yml")
PY="${CISEC_PY:-$HOME/venv/bin/python3}"

export CISEC_KC_PORT=18080
export CISEC_OS_PORT=19200

cleanup() {
  if [ "${KEEP_STACK:-0}" != "1" ]; then
    echo "--- tearing down $PROJECT (own containers/volumes only) ---"
    "${COMPOSE[@]}" down -v --remove-orphans || true
  else
    echo "--- KEEP_STACK=1: leaving $PROJECT up for inspection ---"
  fi
}
trap cleanup EXIT

echo "--- boot timing: start $(date -u +%Y-%m-%dT%H:%M:%SZ) ---"
BOOT_START=$(date +%s)

echo "--- bringing up postgres/redis/minio/opensearch/keycloak (security genuinely enabled) ---"
"${COMPOSE[@]}" up -d postgres redis minio opensearch keycloak

echo "--- waiting for base services to report healthy ---"
"${COMPOSE[@]}" up -d --wait postgres redis minio opensearch keycloak

BASE_HEALTHY=$(date +%s)
echo "--- base services healthy after $((BASE_HEALTHY - BOOT_START))s ---"

echo "--- running opensearch-init + keycloak-init (real production provisioning scripts) ---"
"${COMPOSE[@]}" up opensearch-init keycloak-init
"${COMPOSE[@]}" ps opensearch-init keycloak-init

INIT_DONE=$(date +%s)
echo "--- provisioning complete after $((INIT_DONE - BASE_HEALTHY))s (total $((INIT_DONE - BOOT_START))s) ---"

echo "--- provisioning second org (kronos-ci-org-b) for the isolation proof (poc-local, not shipped) ---"
KC_BASE="http://localhost:${CISEC_KC_PORT}" "$PY" "$SCRIPT_DIR/provision_ci_org_b.py"

echo "--- running real verification (KeycloakTokenValidator + OpenSearchClient DLS isolation) ---"
"$PY" "$SCRIPT_DIR/verify_security_stack.py"
VERIFY_STATUS=$?

TOTAL=$(( $(date +%s) - BOOT_START ))
echo "--- total wall time (cold local run, images already pulled on this host): ${TOTAL}s ---"

exit $VERIFY_STATUS
