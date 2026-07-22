#!/usr/bin/env bash
# Step 4: does a BRAND-NEW org member, added AFTER the OpenSearch role/DLS/
# mapping is already set up, get correctly isolated access automatically --
# with literally zero further OpenSearch-side calls? (Step 3 proved the
# claim mechanism end-to-end but provisioned all users up-front, before
# OpenSearch was even configured; this isolates the actual scaling claim.)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

KC_PORT=18085
OS_PORT=19930
OS_PORT2=19931

docker rm -f kronos-poc-kcosdls4-opensearch kronos-poc-kcosdls4-keycloak >/dev/null 2>&1 || true

# --- Real OpenSearch 2.11.1, security enabled ---
docker run -d --name kronos-poc-kcosdls4-opensearch \
  -e discovery.type=single-node \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p ${OS_PORT}:9200 -p ${OS_PORT2}:9600 \
  opensearchproject/opensearch:2.11.1
until curl -sk -o /dev/null -u admin:admin https://localhost:${OS_PORT}/_cluster/health; do sleep 3; done

docker exec kronos-poc-kcosdls4-opensearch bash -c \
  "echo 'plugins.security.unsupported.restapi.allow_securityconfig_modification: true' >> /usr/share/opensearch/config/opensearch.yml"
docker restart kronos-poc-kcosdls4-opensearch
sleep 3
until curl -sk -o /dev/null -u admin:admin https://localhost:${OS_PORT}/_cluster/health; do sleep 3; done

# --- Real Keycloak, reusing the step-3 realm (kronos-org-id scope + 3 pre-defined users) ---
docker run -d --name kronos-poc-kcosdls4-keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -p ${KC_PORT}:8080 \
  -v "$PARENT_DIR/kronos-realm-poc.json:/opt/keycloak/data/import/kronos-realm.json:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --hostname-strict=false --import-realm
until curl -s -o /dev/null "http://localhost:${KC_PORT}/realms/kronos/.well-known/openid-configuration"; do sleep 3; done

KC_ADMIN_TOKEN=$(curl -s -X POST "http://localhost:${KC_PORT}/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=admin" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
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

# --- Provision org A with ONLY user-a1 as the initial member ---
docker run --rm --network host \
  -v "$PARENT_DIR/provision_keycloak_org.sh:/provision_keycloak_org.sh:ro" \
  -e KC_BASE="http://localhost:${KC_PORT}" -e KC_REALM=kronos \
  -e KC_ADMIN_USER=admin -e KC_ADMIN_PASSWORD=admin \
  -e ORG_ALIAS=kronos-dls-a -e ORG_NAME="KronOS DLS Org A" -e ORG_DOMAIN=kronos-dls-a.example \
  -e ORG_MEMBER_IDS="20000000-0000-4000-8000-000000000001" \
  curlimages/curl:latest sh /provision_keycloak_org.sh

# --- Configure OpenSearch: JWT authc trusting Keycloak's real key, ONE generic
# DLS role, ONE static mapping. THIS IS THE LAST TIME run_poc.sh TOUCHES ANY
# _plugins/_security ENDPOINT -- everything after the marker below is
# Keycloak-only, simulating "time passes, a new analyst joins the org". ---
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
    "roles_key": "roles",
    "subject_key": "sub",
}
with open("/tmp/kcosdls4_config_body.json", "w") as f:
    json.dump(full["config"], f)
PYEOF

curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/securityconfig/config \
  -H "Content-Type: application/json" --data-binary @/tmp/kcosdls4_config_body.json
echo ""

curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/roles/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{
    "cluster_permissions": [],
    "index_permissions": [{
      "index_patterns": ["kronos-*"],
      "dls": "{\"term\": {\"kronos.org_id\": \"${attr.jwt.org_id}\"}}",
      "allowed_actions": ["read", "indices:data/read/search"]
    }]
  }' > /dev/null

curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/rolesmapping/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{"backend_roles": ["analyst"]}' > /dev/null

echo ""
echo "############################################################"
echo "# MARKER: OpenSearch is now fully configured. Everything    #"
echo "# below this line touches Keycloak ONLY -- no further calls #"
echo "# to any /_plugins/_security/* endpoint happen in this run. #"
echo "############################################################"
echo ""

source ~/venv/bin/activate 2>/dev/null || true
KCOSDLS4_KC_PORT="${KC_PORT}" KCOSDLS4_OS_PORT="${OS_PORT}" python3 "$SCRIPT_DIR/run_poc.py"
