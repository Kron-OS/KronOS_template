#!/usr/bin/env bash
# New-construction PoC (like poc/opensearch_jwt/): this repo runs OpenSearch
# Dashboards with DISABLE_SECURITY_DASHBOARDS_PLUGIN=true in dev
# (docker/docker-compose.dev.yml) -- Dashboards multi-tenancy (the OTHER
# "multi-tenancy" concept from the docs page the user linked, distinct from
# the DLS work in poc/opensearch_jwt/ and poc/keycloak_opensearch_dls/) has
# never been built or tested here. This does that: real OpenSearch 2.11.1 +
# real Dashboards 2.11.1, security genuinely enabled on both, two real
# per-org Dashboards tenants, two real users, real saved-object isolation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

OS_PORT=19950
OS_PORT2=19951
DASH_PORT=15601

docker rm -f kronos-poc-dash-opensearch kronos-poc-dash-dashboards >/dev/null 2>&1 || true
docker network rm kronos-poc-dash-net >/dev/null 2>&1 || true
docker network create kronos-poc-dash-net >/dev/null

# --- Real OpenSearch 2.11.1, security enabled (bundled demo config: admin:admin) ---
docker run -d --name kronos-poc-dash-opensearch --network kronos-poc-dash-net \
  -e discovery.type=single-node \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p ${OS_PORT}:9200 -p ${OS_PORT2}:9600 \
  opensearchproject/opensearch:2.11.1
until curl -sk -o /dev/null -u admin:admin https://localhost:${OS_PORT}/_cluster/health; do sleep 3; done
echo "OpenSearch ready"

# --- Real OpenSearch Dashboards 2.11.1, security-dashboards plugin enabled
# (i.e. NOT setting DISABLE_SECURITY_DASHBOARDS_PLUGIN, unlike
# docker-compose.dev.yml), multitenancy explicitly turned on. Must reach
# OpenSearch by container DNS name over the shared docker network, not
# localhost -- each container needs its OWN published ports. ---
docker run -d --name kronos-poc-dash-dashboards --network kronos-poc-dash-net \
  -e OPENSEARCH_HOSTS='["https://kronos-poc-dash-opensearch:9200"]' \
  -e OPENSEARCH_USERNAME=kibanaserver \
  -e OPENSEARCH_PASSWORD=kibanaserver \
  -e OPENSEARCH_SSL_VERIFICATIONMODE=none \
  -e OPENSEARCH_SECURITY_MULTITENANCY_ENABLED=true \
  -e OPENSEARCH_SECURITY_MULTITENANCY_TENANTS_PREFERRED='["Private","Global"]' \
  -p ${DASH_PORT}:5601 \
  opensearchproject/opensearch-dashboards:2.11.1
until curl -s -o /dev/null http://localhost:${DASH_PORT}/api/status --max-time 5; do sleep 3; done
echo "Dashboards ready"

# --- Two real, org-scoped Dashboards tenants + two roles, each granted
# kibana_all_write on ONLY its own tenant -- the actual isolation boundary
# under test. ---
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/tenants/kronos-org-a \
  -H "Content-Type: application/json" -d '{"description":"KronOS org A Dashboards tenant"}'
echo
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/tenants/kronos-org-b \
  -H "Content-Type: application/json" -d '{"description":"KronOS org B Dashboards tenant"}'
echo

curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/roles/kronos-dash-org-a \
  -H "Content-Type: application/json" -d '{
    "cluster_permissions": [],
    "tenant_permissions": [{"tenant_patterns": ["kronos-org-a"], "allowed_actions": ["kibana_all_write"]}]
  }'
echo
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/roles/kronos-dash-org-b \
  -H "Content-Type: application/json" -d '{
    "cluster_permissions": [],
    "tenant_permissions": [{"tenant_patterns": ["kronos-org-b"], "allowed_actions": ["kibana_all_write"]}]
  }'
echo

# Internal (basic-auth) users -- deliberately NOT wired to Keycloak OIDC here.
# Real Keycloak<->Dashboards SSO is poc/dashboards_embed's separate concern
# (cases.py embed-URL route); this PoC isolates the tenant/saved-object
# mechanism itself, same "verify the mechanism before wiring the SSO" split
# used in poc/opensearch_jwt/option_a_flat_claim/ for DLS.
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/internalusers/dash-user-a \
  -H "Content-Type: application/json" -d '{"password":"DashUserA#2026"}'
echo
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/internalusers/dash-user-b \
  -H "Content-Type: application/json" -d '{"password":"DashUserB#2026"}'
echo
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/rolesmapping/kronos-dash-org-a \
  -H "Content-Type: application/json" -d '{"users":["dash-user-a"]}'
echo
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/rolesmapping/kronos-dash-org-b \
  -H "Content-Type: application/json" -d '{"users":["dash-user-b"]}'
echo

echo "OpenSearch + Dashboards ready, tenants/roles/users provisioned. Running run_poc.py..."
source ~/venv/bin/activate 2>/dev/null || true
KCDASH_OS_PORT="${OS_PORT}" KCDASH_DASH_PORT="${DASH_PORT}" python3 "$SCRIPT_DIR/run_poc.py"
