#!/bin/bash
# Provision KronOS MinIO buckets with SSE-KMS and Object Lock.
# Run once after MinIO + KES are healthy.
# Usage: ORG_ALIAS=acme ./scripts/provision_buckets.sh
set -euo pipefail

MINIO_ALIAS="${MINIO_ALIAS:-local}"
MINIO_URL="${MINIO_URL:-http://minio:9000}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-kronos_minio}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-CHANGE_ME}"
ORG_ALIAS="${ORG_ALIAS:-dev}"
KMS_KEY="${KMS_KEY:-kronos-evidence}"

echo "Provisioning buckets for org: ${ORG_ALIAS}"

mc alias set "$MINIO_ALIAS" "$MINIO_URL" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"

# Canonical bucket names per Project_Specifications.md §2:
#   quarantine: kronos-evidence-<org>-quarantine   (no Object Lock)
#   evidence:   kronos-evidence-<org>              (WORM, Object Lock Compliance)
# These MUST match src/adapter/storage/s3.py and config.py (prefix "kronos-evidence").
BUCKET_PREFIX="${BUCKET_PREFIX:-kronos-evidence}"

# Quarantine bucket — staging area before ClamAV scan, no Object Lock
mc mb "${MINIO_ALIAS}/${BUCKET_PREFIX}-${ORG_ALIAS}-quarantine" 2>/dev/null || echo "quarantine bucket already exists"
mc encrypt set sse-kms "$KMS_KEY" "${MINIO_ALIAS}/${BUCKET_PREFIX}-${ORG_ALIAS}-quarantine" 2>/dev/null || true

# Evidence bucket — WORM + SSE-KMS (encrypted WORM, spec §2 + §5)
mc mb --with-lock "${MINIO_ALIAS}/${BUCKET_PREFIX}-${ORG_ALIAS}" 2>/dev/null || echo "evidence bucket already exists"
mc encrypt set sse-kms "$KMS_KEY" "${MINIO_ALIAS}/${BUCKET_PREFIX}-${ORG_ALIAS}" 2>/dev/null || true
mc retention set --default COMPLIANCE 365d "${MINIO_ALIAS}/${BUCKET_PREFIX}-${ORG_ALIAS}" 2>/dev/null || true

# SIEM cold archive — 7-year compliance retention (SEC 17a-4)
mc mb --with-lock "${MINIO_ALIAS}/kronos-siem-archive" 2>/dev/null || echo "siem-archive bucket already exists"
mc encrypt set sse-kms "$KMS_KEY" "${MINIO_ALIAS}/kronos-siem-archive" 2>/dev/null || true
mc retention set --default COMPLIANCE 2555d "${MINIO_ALIAS}/kronos-siem-archive" 2>/dev/null || true

echo "Done. Buckets provisioned for org: ${ORG_ALIAS}"
