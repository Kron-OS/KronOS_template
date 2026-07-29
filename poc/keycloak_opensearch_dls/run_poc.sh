#!/usr/bin/env bash
# Step 3: does the flat org_id claim mechanism researched in
# ../opensearch_jwt/option_a_flat_claim/keycloak_mapper_research.md actually
# work end-to-end against a REAL Keycloak 26.2 (not hand-signed test JWTs),
# and does OpenSearch's DLS templating correctly isolate real users across
# two real Organizations using it?
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

KC_PORT=18084
OS_PORT=19920
OS_PORT2=19921

docker rm -f kronos-poc-kcosdls-opensearch kronos-poc-kcosdls-keycloak >/dev/null 2>&1 || true

# --- Real OpenSearch 2.11.1, security enabled ---
docker run -d --name kronos-poc-kcosdls-opensearch \
  -e discovery.type=single-node \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p ${OS_PORT}:9200 -p ${OS_PORT2}:9600 \
  opensearchproject/opensearch:2.11.1
until curl -sk -o /dev/null -u admin:admin https://localhost:${OS_PORT}/_cluster/health; do sleep 3; done

docker exec kronos-poc-kcosdls-opensearch bash -c \
  "echo 'plugins.security.unsupported.restapi.allow_securityconfig_modification: true' >> /usr/share/opensearch/config/opensearch.yml"
docker restart kronos-poc-kcosdls-opensearch
sleep 3
until curl -sk -o /dev/null -u admin:admin https://localhost:${OS_PORT}/_cluster/health; do sleep 3; done

# --- Real Keycloak 26.2 with this PoC's realm (kronos-org-id scope + 3 users) ---
docker run -d --name kronos-poc-kcosdls-keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -p ${KC_PORT}:8080 \
  -v "$SCRIPT_DIR/kronos-realm-poc.json:/opt/keycloak/data/import/kronos-realm.json:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --hostname-strict=false --import-realm
until curl -s -o /dev/null "http://localhost:${KC_PORT}/realms/kronos/.well-known/openid-configuration"; do sleep 3; done

# --- Real finding (not anticipated from source-reading alone): Keycloak 26.2's
# Declarative User Profile only declares username/email/firstName/lastName by
# default. A PUT .../users/{id} with an undeclared "org_id" attribute is
# silently accepted (204) but the attribute never actually persists -- and,
# worse, the same call strips the user's existing "email" field entirely
# (confirmed: subsequent GET shows no "email" key at all), which then makes
# password-grant login fail with "Account is not fully set up". Fix: declare
# org_id as an admin-only-editable User Profile attribute FIRST, before any
# provisioning PUT ever runs.
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

# --- Provision TWO real orgs via the (step-3-extended) real provisioning script ---
# org A: user-a1 + user-a2 (two members -- proves a second org member also
# gets correctly isolated via the same flat-claim mechanism, real Keycloak this time)
docker run --rm --network host \
  -v "$SCRIPT_DIR/provision_keycloak_org.sh:/provision_keycloak_org.sh:ro" \
  -e KC_BASE="http://localhost:${KC_PORT}" -e KC_REALM=kronos \
  -e KC_ADMIN_USER=admin -e KC_ADMIN_PASSWORD=admin \
  -e ORG_ALIAS=kronos-dls-a -e ORG_NAME="KronOS DLS Org A" -e ORG_DOMAIN=kronos-dls-a.example \
  -e ORG_MEMBER_IDS="20000000-0000-4000-8000-000000000001 20000000-0000-4000-8000-000000000002" \
  curlimages/curl:latest sh /provision_keycloak_org.sh

# org B: user-b1 only
docker run --rm --network host \
  -v "$SCRIPT_DIR/provision_keycloak_org.sh:/provision_keycloak_org.sh:ro" \
  -e KC_BASE="http://localhost:${KC_PORT}" -e KC_REALM=kronos \
  -e KC_ADMIN_USER=admin -e KC_ADMIN_PASSWORD=admin \
  -e ORG_ALIAS=kronos-dls-b -e ORG_NAME="KronOS DLS Org B" -e ORG_DOMAIN=kronos-dls-b.example \
  -e ORG_MEMBER_IDS="20000000-0000-4000-8000-000000000003" \
  curlimages/curl:latest sh /provision_keycloak_org.sh

# --- Extract Keycloak's real signing public key, raw base64 (same technique
# already verified in ../opensearch_jwt/run_poc.sh) ---
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
with open("/tmp/kcosdls_config_body.json", "w") as f:
    json.dump(full["config"], f)
PYEOF

curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/securityconfig/config \
  -H "Content-Type: application/json" --data-binary @/tmp/kcosdls_config_body.json
echo ""

# --- ONE generic, org-agnostic DLS role + ONE static mapping (same as option_a_flat_claim) ---
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

echo "Keycloak + OpenSearch ready. Running run_poc.py..."
source ~/venv/bin/activate 2>/dev/null || true
KCOSDLS_KC_PORT="${KC_PORT}" KCOSDLS_OS_PORT="${OS_PORT}" python3 "$SCRIPT_DIR/run_poc.py"
