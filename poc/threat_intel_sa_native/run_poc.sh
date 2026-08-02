#!/usr/bin/env bash
# PoC: does OpenSearch Security Analytics' native threat-intel feature exist
# on the OpenSearch version(s) this repo actually pins? (roadmap M5/F2)
#
# Pinned versions (CLAUDE.md SS F.2 step 1):
#   docker/docker-compose.dev.yml   -> opensearchproject/opensearch:2.11.1  (live dev cluster)
#   docker/docker-compose.test.yml,
#   docker-compose.prod.yml         -> opensearchproject/opensearch:2.13.0
#
# Run against the REAL, already-running dev cluster (docker-opensearch-1).
set -euo pipefail

OS_BASE="https://localhost:9200"
AUTH="admin:admin"

echo "=== 1. Real cluster version (confirms which build we're actually testing) ==="
curl -sk -u "$AUTH" "$OS_BASE/"
echo

echo "=== 2. Real installed plugin list (confirms security-analytics IS present, at 2.11.1.0) ==="
curl -sk -u "$AUTH" "$OS_BASE/_cat/plugins?v"
echo

echo "=== 3. Real probe: does the threat-intel REST namespace exist at all? ==="
echo "--- GET /_plugins/_security_analytics/threat_intel/sources ---"
curl -sk -u "$AUTH" -w "\nHTTP_STATUS:%{http_code}\n" \
  "$OS_BASE/_plugins/_security_analytics/threat_intel/sources"
echo
echo "--- GET /_plugins/_security_analytics/threatintel/sources (alt spelling) ---"
curl -sk -u "$AUTH" -w "\nHTTP_STATUS:%{http_code}\n" \
  "$OS_BASE/_plugins/_security_analytics/threatintel/sources"
echo

echo "=== 4. Control: a REAL, KNOWN-GOOD SA endpoint on this same cluster, for contrast ==="
echo "--- GET /_plugins/_security_analytics/detectors/_search (known to exist, per detector_provisioner.py) ---"
curl -sk -u "$AUTH" -w "\nHTTP_STATUS:%{http_code}\n" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"match_all":{}}}' \
  "$OS_BASE/_plugins/_security_analytics/detectors/_search"
echo
