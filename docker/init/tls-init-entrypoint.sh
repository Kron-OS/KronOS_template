#!/bin/sh
# Issues one multi-SAN leaf certificate from the real, already-running
# step-ca dev instance (via its live "admin" JWK provisioner -- see
# docker/init/Dockerfile.tls-init for why not the unwired docker/pki/
# bootstrap.sh provisioners) and writes it + the root CA into a shared
# volume nginx mounts read-only.
#
# STEP_CA_URL must point at step-ca's REAL internal listen port. Verified
# directly against the running dev container: ca.json's "address" is
# ":9000", not ":9443" -- the compose file's "9443:9443" port mapping was
# dead (nothing inside the container listens on 9443; its healthcheck's
# "|| exit 0" was silently masking the resulting connection-refused). This
# script targets step-ca:9000 regardless of that mapping bug, which is
# fixed separately in docker-compose.dev.yml (host port stays 9443, now
# correctly mapped to container port 9000, to avoid colliding with MinIO's
# own host port 9000).
set -eu

: "${STEP_CA_URL:?}"
: "${STEP_CA_PASSWORD:?}"
: "${TLS_SAN_PRIMARY:?}"
: "${TLS_CERT_DIR:?}"

# First-trust bootstrap: no pre-known fingerprint exists yet, so fetch the
# root over TLS without verification (step-ca is reached over the trusted
# internal Docker network -- this is the dev stack's own throwaway CA).
# `step ca root` has no --insecure flag in this CLI version (confirmed via
# --help); it requires --fingerprint, which we don't have until after this
# first fetch. Re-fetch via `step ca root --fingerprint` afterward as a
# real verification round-trip, not just trust-and-move-on.
echo "tls-init: fetching root CA from ${STEP_CA_URL}"
curl -sk "${STEP_CA_URL}/roots.pem" -o "${TLS_CERT_DIR}/root_ca.crt"
ROOT_FINGERPRINT=$(step certificate fingerprint "${TLS_CERT_DIR}/root_ca.crt")
step ca root "${TLS_CERT_DIR}/root_ca.crt" \
  --ca-url "${STEP_CA_URL}" \
  --fingerprint "${ROOT_FINGERPRINT}" \
  --force
echo "tls-init: root CA verified, fingerprint ${ROOT_FINGERPRINT}"

# kronos.local is the sole authorized domain (docs/lan-dev-access.md) --
# no localhost/127.0.0.1 SANs. Every client, on the same machine or on
# the LAN, uses this one name; see frontend/src/keycloak.ts's
# resolveKeycloakUrl() for why a per-client localhost special case is
# actively wrong, not just redundant (a real, reproduced Keycloak
# session-cookie bug, poc/tls_lan_https/README.md).
echo "tls-init: requesting leaf certificate for ${TLS_SAN_PRIMARY}"
step ca certificate "${TLS_SAN_PRIMARY}" \
  "${TLS_CERT_DIR}/server.crt" "${TLS_CERT_DIR}/server.key" \
  --san "${TLS_SAN_PRIMARY}" \
  --provisioner admin \
  --password-file <(printf '%s' "${STEP_CA_PASSWORD}") \
  --ca-url "${STEP_CA_URL}" \
  --root "${TLS_CERT_DIR}/root_ca.crt" \
  --force

chmod 0644 "${TLS_CERT_DIR}/server.crt" "${TLS_CERT_DIR}/root_ca.crt" "${TLS_CERT_DIR}/server.key"

echo "tls-init: complete -- ${TLS_CERT_DIR}/server.crt, server.key, root_ca.crt"
