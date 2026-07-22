#!/usr/bin/env bash
# P1 fix verification: does adding a "level 1" conditional subflow (which
# unconditionally establishes the baseline aal1 LoA before the existing
# level-2/OTP condition runs) make step-up MFA genuinely conditional on the
# requested acr_values, instead of always forcing TOTP (poc/auth_flow's
# real finding #1)? Real Keycloak 26.2, real scripted PKCE logins, no
# password grant, no hand-minted tokens.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

KC_PORT=18082

docker rm -f kronos-poc-stepupfix-keycloak >/dev/null 2>&1 || true

docker run -d --name kronos-poc-stepupfix-keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -p ${KC_PORT}:8080 \
  -v "$SCRIPT_DIR/kronos-realm-poc.json:/opt/keycloak/data/import/kronos-realm.json:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --import-realm --hostname-strict=false
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:${KC_PORT}/realms/kronos/.well-known/openid-configuration" && break
  sleep 3
done
echo "Keycloak ready with the candidate FIXED realm (level-1 + level-2 conditional subflows)."

source ~/venv/bin/activate 2>/dev/null || true
python3 "$SCRIPT_DIR/run_poc.py"
