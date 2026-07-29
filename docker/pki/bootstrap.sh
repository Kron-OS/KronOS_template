#!/bin/bash
# Initialise step-ca with root CA, intermediate CA, and provisioners.
# Idempotent — safe to re-run; existing state is preserved.
set -euo pipefail

CA_PASSWORD="${CA_PASSWORD:-kronos-ca-password}"

# step-ca auto-initialises from DOCKER_STEPCA_INIT_* env vars on first boot.
# This script adds additional provisioners after the CA is running.

wait_for_ca() {
  local retries=20
  while [ $retries -gt 0 ]; do
    step ca health --ca-url https://localhost:9000 2>/dev/null && return 0
    retries=$((retries - 1))
    sleep 3
  done
  echo "step-ca did not become healthy" >&2
  return 1
}

# Start the CA server in the background so we can configure it
/usr/local/bin/step-ca /home/step/config/ca.json &
CA_PID=$!

wait_for_ca

# Add ACME provisioner (for automatic cert renewal by services)
step ca provisioner add acme --type ACME \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt \
  2>/dev/null || true

# Add JWK provisioner for service account tokens
step ca provisioner add kronos-sa --type JWK \
  --create \
  --password-file <(echo "$CA_PASSWORD") \
  --ca-url https://localhost:9000 \
  --root /home/step/certs/root_ca.crt \
  2>/dev/null || true

echo "step-ca bootstrap complete."
wait $CA_PID
