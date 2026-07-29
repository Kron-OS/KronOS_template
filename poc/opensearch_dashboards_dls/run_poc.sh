#!/usr/bin/env bash
# Does the "combined dashboard_roles claim" fix actually let a real
# OpenSearch-Dashboards-shaped Keycloak token satisfy BOTH the per-org
# tenant rolesmapping (backend_roles=[org_id]) AND the DLS-granting
# kronos-generic-tenant rolesmapping (backend_roles=[realm role names])
# simultaneously -- and does cross-org DOCUMENT isolation still hold?
#
# Real Keycloak 26.2 + real OpenSearch 2.11.1 (pinned versions match
# docker/keycloak/*, docker/docker-compose.dev.yml). No mocks: real token
# issuance, real OpenSearch security plugin, real seeded documents.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

KC_PORT=18086
OS_PORT=19930
OS_PORT2=19931

# Bounded wait with progress/failure output -- an earlier run of this script
# hung silently for 33+ minutes because its wait loops had no retry limit:
# Keycloak crashed in ~11s (a too-long client-scope description over
# Keycloak's own VARCHAR(255) column limit -- the exact bug class already
# hit once before in this repo's history) and the unbounded `until curl`
# loop just kept polling a dead container forever with zero output. Fails
# fast and prints the container's own logs instead.
wait_for() {
  local url="$1" container="$2" max="${3:-40}"
  local i=0
  until curl -sk -o /dev/null -u admin:admin "$url"; do
    i=$((i + 1))
    if [ "$i" -ge "$max" ]; then
      echo "ERROR: $url not reachable after $((max * 3))s -- $container's status:" >&2
      docker ps -a --filter "name=$container" --format "{{.Names}}: {{.Status}}" >&2
      echo "--- $container logs (tail) ---" >&2
      docker logs --tail 60 "$container" >&2
      exit 1
    fi
    if [ $((i % 5)) -eq 0 ]; then
      echo "  still waiting for $url ($i/$max, $((i * 3))s)..."
    fi
    sleep 3
  done
}

docker rm -f kronos-poc-osddls-opensearch kronos-poc-osddls-keycloak >/dev/null 2>&1 || true

echo "=== Real OpenSearch 2.11.1, security enabled ==="
docker run -d --name kronos-poc-osddls-opensearch \
  -e discovery.type=single-node \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p ${OS_PORT}:9200 -p ${OS_PORT2}:9600 \
  opensearchproject/opensearch:2.11.1
wait_for "https://localhost:${OS_PORT}/_cluster/health" kronos-poc-osddls-opensearch

docker exec kronos-poc-osddls-opensearch bash -c \
  "echo 'plugins.security.unsupported.restapi.allow_securityconfig_modification: true' >> /usr/share/opensearch/config/opensearch.yml"
docker restart kronos-poc-osddls-opensearch
sleep 3
wait_for "https://localhost:${OS_PORT}/_cluster/health" kronos-poc-osddls-opensearch

echo "=== Real Keycloak 26.2 with the combined-claim realm ==="
docker run -d --name kronos-poc-osddls-keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -p ${KC_PORT}:8080 \
  -v "$SCRIPT_DIR/kronos-realm-poc.json:/opt/keycloak/data/import/kronos-realm.json:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --hostname-strict=false --import-realm
wait_for "http://localhost:${KC_PORT}/realms/kronos/.well-known/openid-configuration" kronos-poc-osddls-keycloak

KC_ADMIN_TOKEN=$(curl -s -X POST "http://localhost:${KC_PORT}/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=admin" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# Same real gotcha as poc/keycloak_opensearch_dls/: org_id must be declared
# in the realm's Declarative User Profile BEFORE any provisioning PUT, or it
# silently fails to persist (and can even clear other fields -- see that
# PoC's run_poc.sh for the full account).
curl -s -X PUT "http://localhost:${KC_PORT}/admin/realms/kronos/users/profile" \
  -H "Authorization: Bearer $KC_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "attributes": [
      {"name":"username","permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},
      {"name":"email","required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false,"validations":{"email":{},"length":{"max":255}}},
      {"name":"firstName","required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},
      {"name":"lastName","required":{"roles":["user"]},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},
      {"name":"org_id","displayName":"KronOS Organization ID","permissions":{"view":["admin"],"edit":["admin"]},"multivalued":false}
    ]
  }' > /dev/null
echo "Declared org_id as an admin-managed User Profile attribute."

echo "=== Provisioning two real orgs (org A: 2 analysts, org B: 1 case-lead) ==="
docker run --rm --network host \
  -v "$SCRIPT_DIR/provision_keycloak_org.sh:/provision_keycloak_org.sh:ro" \
  -e KC_BASE="http://localhost:${KC_PORT}" -e KC_REALM=kronos \
  -e KC_ADMIN_USER=admin -e KC_ADMIN_PASSWORD=admin \
  -e ORG_ALIAS=kronos-osddls-a -e ORG_NAME="KronOS OSDDLS Org A" -e ORG_DOMAIN=kronos-osddls-a.example \
  -e ORG_MEMBER_IDS="20000000-0000-4000-8000-000000000001 20000000-0000-4000-8000-000000000002" \
  curlimages/curl:latest sh /provision_keycloak_org.sh

docker run --rm --network host \
  -v "$SCRIPT_DIR/provision_keycloak_org.sh:/provision_keycloak_org.sh:ro" \
  -e KC_BASE="http://localhost:${KC_PORT}" -e KC_REALM=kronos \
  -e KC_ADMIN_USER=admin -e KC_ADMIN_PASSWORD=admin \
  -e ORG_ALIAS=kronos-osddls-b -e ORG_NAME="KronOS OSDDLS Org B" -e ORG_DOMAIN=kronos-osddls-b.example \
  -e ORG_MEMBER_IDS="20000000-0000-4000-8000-000000000003" \
  curlimages/curl:latest sh /provision_keycloak_org.sh

echo "=== Wiring OpenSearch: JWT authc domain (roles_key=dashboard_roles) + both real rolesmappings ==="
python3 - << PYEOF
import json, urllib.request, subprocess

data = json.load(urllib.request.urlopen("http://localhost:${KC_PORT}/realms/kronos/protocol/openid-connect/certs"))
sig_key = next(k for k in data["keys"] if k["use"] == "sig")
x5c = sig_key["x5c"][0]
cert_pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(x5c[i:i+64] for i in range(0, len(x5c), 64)) + "\n-----END CERTIFICATE-----\n"
pubkey_pem = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=cert_pem, capture_output=True, text=True, check=True).stdout
raw_b64 = "".join(l for l in pubkey_pem.splitlines() if l and "BEGIN" not in l and "END" not in l)

full = json.loads(subprocess.run(
    ["curl", "-sk", "-u", "admin:admin", "https://localhost:${OS_PORT}/_plugins/_security/api/securityconfig"],
    capture_output=True, text=True, check=True,
).stdout)
jwt = full["config"]["dynamic"]["authc"]["jwt_auth_domain"]
jwt["http_enabled"] = True
jwt["http_authenticator"]["config"] = {
    "signing_key": raw_b64,
    "jwt_header": "Authorization",
    "jwt_clock_skew_tolerance_seconds": 30,
    # THE FIX UNDER TEST: roles_key points at the new combined claim instead
    # of bare org_id. subject_key stays sub, matching the real shipped
    # opensearch_security_openid.yml config.
    "roles_key": "dashboard_roles",
    "subject_key": "sub",
}
with open("/tmp/osddls_config_body.json", "w") as f:
    json.dump(full["config"], f)
PYEOF

curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/securityconfig/config \
  -H "Content-Type: application/json" --data-binary @/tmp/osddls_config_body.json
echo ""

# The REAL kronos-generic-tenant role+mapping, byte-for-byte matching
# src/adapter/opensearch/client.py's ensure_generic_tenant_role() /
# scripts/provision_opensearch_security.py -- unchanged by this fix.
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/roles/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{
    "cluster_permissions": [],
    "index_permissions": [{
      "index_patterns": ["kronos-*"],
      "dls": "{\"term\": {\"kronos.org_id\": \"${attr.jwt.org_id}\"}}",
      "allowed_actions": ["read", "indices:data/read/search"]
    }],
    "tenant_permissions": []
  }' > /dev/null
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/rolesmapping/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{"backend_roles": ["org-admin", "case-lead", "analyst", "read-only"]}' > /dev/null
echo "kronos-generic-tenant role + mapping ensured (unchanged from production)."

# Real per-org kronos-dash-* tenant roles, byte-for-byte matching
# scripts/provision_dashboards_tenant.sh -- unchanged by this fix. Need the
# real org ids, so fetch them by alias.
KC_ADMIN_TOKEN=$(curl -s -X POST "http://localhost:${KC_PORT}/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=admin" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
ORG_A_ID=$(curl -s -H "Authorization: Bearer $KC_ADMIN_TOKEN" "http://localhost:${KC_PORT}/admin/realms/kronos/organizations?first=0&max=1000" \
  | python3 -c "import json,sys; orgs=json.load(sys.stdin); print(next(o['id'] for o in orgs if o['alias']=='kronos-osddls-a'))")
ORG_B_ID=$(curl -s -H "Authorization: Bearer $KC_ADMIN_TOKEN" "http://localhost:${KC_PORT}/admin/realms/kronos/organizations?first=0&max=1000" \
  | python3 -c "import json,sys; orgs=json.load(sys.stdin); print(next(o['id'] for o in orgs if o['alias']=='kronos-osddls-b'))")
echo "org A id=$ORG_A_ID  org B id=$ORG_B_ID"

for ORG in "kronos-osddls-a:$ORG_A_ID" "kronos-osddls-b:$ORG_B_ID"; do
  ALIAS="${ORG%%:*}"; OID="${ORG##*:}"
  TENANT_NAME="kronos-$ALIAS"
  ROLE_NAME="kronos-dash-$ALIAS"
  curl -sk -u admin:admin -X PUT "https://localhost:${OS_PORT}/_plugins/_security/api/tenants/$TENANT_NAME" \
    -H "Content-Type: application/json" -d "{\"description\":\"tenant for $ALIAS\"}" > /dev/null
  curl -sk -u admin:admin -X PUT "https://localhost:${OS_PORT}/_plugins/_security/api/roles/$ROLE_NAME" \
    -H "Content-Type: application/json" \
    -d "{\"cluster_permissions\":[],\"tenant_permissions\":[{\"tenant_patterns\":[\"$TENANT_NAME\"],\"allowed_actions\":[\"kibana_all_write\"]}]}" > /dev/null
  curl -sk -u admin:admin -X PUT "https://localhost:${OS_PORT}/_plugins/_security/api/rolesmapping/$ROLE_NAME" \
    -H "Content-Type: application/json" -d "{\"backend_roles\":[\"$OID\"]}" > /dev/null
  echo "$ROLE_NAME ensured (tenant=$TENANT_NAME, backend_role=$OID)."
done

echo "=== Seeding two real documents, one per org, into a kronos-* test index ==="
# Explicit keyword mapping for kronos.org_id BEFORE indexing -- without this,
# OpenSearch's dynamic mapping makes it a `text` field (+ .keyword subfield),
# and the DLS role's `term` filter (an exact-match query) matches nothing at
# all, even for an admin bypassing DLS entirely (confirmed: reproduced this
# exact empty-result failure in this PoC's first real run, root-caused via
# GET .../_mapping). Production doesn't hit this because
# TimelineIngestionService.ensure_index_template() already maps kronos.org_id
# as keyword for real -- this throwaway index just never had that template
# applied, so it needs it set explicitly here to test the real DLS behavior
# faithfully rather than an artifact of skipping index setup.
curl -sk -u admin:admin -X PUT "https://localhost:${OS_PORT}/kronos-osddls-test-case-000001" \
  -H "Content-Type: application/json" -d '{
    "mappings": {"properties": {"kronos": {"properties": {"org_id": {"type": "keyword"}, "case_id": {"type": "keyword"}}}}}
  }' > /dev/null
curl -sk -u admin:admin -X POST "https://localhost:${OS_PORT}/kronos-osddls-test-case-000001/_doc" \
  -H "Content-Type: application/json" -d "{\"kronos\":{\"org_id\":\"$ORG_A_ID\",\"case_id\":\"case-a\"},\"message\":\"org A secret event\"}" > /dev/null
curl -sk -u admin:admin -X POST "https://localhost:${OS_PORT}/kronos-osddls-test-case-000001/_doc" \
  -H "Content-Type: application/json" -d "{\"kronos\":{\"org_id\":\"$ORG_B_ID\",\"case_id\":\"case-b\"},\"message\":\"org B secret event\"}" > /dev/null
curl -sk -u admin:admin -X POST "https://localhost:${OS_PORT}/kronos-osddls-test-case-000001/_refresh" > /dev/null
echo "Seeded."

echo ""
echo "Keycloak + OpenSearch ready. Running run_poc.py..."
source ~/venv/bin/activate 2>/dev/null || true
OSDDLS_KC_PORT="${KC_PORT}" OSDDLS_OS_PORT="${OS_PORT}" \
  ORG_A_ID="$ORG_A_ID" ORG_B_ID="$ORG_B_ID" \
  python3 "$SCRIPT_DIR/run_poc.py"
