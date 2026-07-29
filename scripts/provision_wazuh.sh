#!/bin/bash
# Create Wazuh index template and DLS writer role on the shared OpenSearch cluster.
# Run once after OpenSearch is healthy.
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-http://opensearch:9200}"
OPENSEARCH_USER="${OPENSEARCH_USERNAME:-admin}"
OPENSEARCH_PASS="${OPENSEARCH_PASSWORD:-admin}"

echo "Provisioning Wazuh OpenSearch resources at ${OPENSEARCH_URL}"

# Index template for wazuh-alerts-*
curl -fsk -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
  -X PUT "${OPENSEARCH_URL}/_index_template/wazuh-alerts" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["wazuh-alerts-*"],
    "priority": 200,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 1,
        "index.lifecycle.name": "wazuh-alerts-policy"
      },
      "mappings": {
        "properties": {
          "timestamp":        {"type": "date"},
          "rule.id":          {"type": "keyword"},
          "rule.level":       {"type": "integer"},
          "rule.description": {"type": "text"},
          "rule.groups":      {"type": "keyword"},
          "agent.name":       {"type": "keyword"},
          "user_id":          {"type": "keyword"},
          "org_id":           {"type": "keyword"},
          "event_type":       {"type": "keyword"}
        }
      }
    }
  }' && echo "Wazuh index template created."

# OpenSearch role: write-only access to wazuh-alerts-* (DLS enforced)
curl -fsk -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
  -X PUT "${OPENSEARCH_URL}/_plugins/_security/api/roles/kronos_wazuh_writer" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster_permissions": ["indices:data/write/bulk"],
    "index_permissions": [{
      "index_patterns": ["wazuh-alerts-*"],
      "allowed_actions": [
        "indices:data/write/index",
        "indices:data/write/bulk",
        "indices:admin/create"
      ]
    }]
  }' && echo "Wazuh writer role created."

echo "Wazuh OpenSearch provisioning complete."
