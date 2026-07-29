#!/usr/bin/env bash
# Bootstrap: real OpenSearch 2.11.1 with security genuinely enabled + a real
# JWT auth domain trusting a real Keycloak, then run run_poc.py.
set -euo pipefail
cd "$(dirname "$0")/../.."

docker rm -f kronos-poc-osjwt-opensearch kronos-poc-osjwt-keycloak >/dev/null 2>&1 || true

docker run -d --name kronos-poc-osjwt-opensearch \
  -e discovery.type=single-node \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p 19800:9200 -p 19801:9600 \
  opensearchproject/opensearch:2.11.1
until curl -sk -o /dev/null -u admin:admin https://localhost:19800/_cluster/health; do sleep 3; done

# OpenSearch's securityconfig REST endpoint refuses writes unless this flag
# is set in opensearch.yml -- it's not settable via env var or REST itself.
docker exec kronos-poc-osjwt-opensearch bash -c \
  "echo 'plugins.security.unsupported.restapi.allow_securityconfig_modification: true' >> /usr/share/opensearch/config/opensearch.yml"
docker restart kronos-poc-osjwt-opensearch
sleep 3
until curl -sk -o /dev/null -u admin:admin https://localhost:19800/_cluster/health; do sleep 3; done

docker run -d --name kronos-poc-osjwt-keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -p 18083:8080 \
  quay.io/keycloak/keycloak:26.2 start-dev --hostname-strict=false
until curl -s -o /dev/null http://localhost:18083/realms/master; do sleep 3; done

KC_ADMIN=$(curl -s -X POST "http://localhost:18083/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" -d "username=admin" -d "password=admin" -d "grant_type=password" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -X POST "http://localhost:18083/admin/realms" \
  -H "Authorization: Bearer $KC_ADMIN" -H "Content-Type: application/json" \
  --data-binary @docker/keycloak/kronos-realm.json > /dev/null

CLIENT_UUID=$(curl -s -H "Authorization: Bearer $KC_ADMIN" \
  "http://localhost:18083/admin/realms/kronos/clients?clientId=kronos-frontend" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['id'])")
curl -s -X PUT "http://localhost:18083/admin/realms/kronos/clients/$CLIENT_UUID" \
  -H "Authorization: Bearer $KC_ADMIN" -H "Content-Type: application/json" \
  -d '{"directAccessGrantsEnabled": true}' > /dev/null

curl -s -X POST "http://localhost:18083/admin/realms/kronos/organizations" \
  -H "Authorization: Bearer $KC_ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"osjwt","alias":"osjwt","domains":[{"name":"osjwt.example","verified":false}]}' > /dev/null
ORG_ID=$(curl -s -H "Authorization: Bearer $KC_ADMIN" "http://localhost:18083/admin/realms/kronos/organizations?search=osjwt" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['id'])")
curl -s -X POST "http://localhost:18083/admin/realms/kronos/organizations/$ORG_ID/members" \
  -H "Authorization: Bearer $KC_ADMIN" -H "Content-Type: application/json" \
  -d '"10000000-0000-4000-8000-000000000002"' > /dev/null
echo "Provisioned org osjwt: $ORG_ID"

# Extract Keycloak's real signing public key, raw base64 (no PEM headers,
# no newlines -- OpenSearch's HTTPJwtAuthenticator Base64-decodes the
# config value directly; PEM headers/newlines make it throw
# io.jsonwebtoken.io.DecodingException at startup. See README.
python3 - "$ORG_ID" << 'PYEOF'
import json, urllib.request, subprocess, sys, base64

data = json.load(urllib.request.urlopen("http://localhost:18083/realms/kronos/protocol/openid-connect/certs"))
sig_key = next(k for k in data["keys"] if k["use"] == "sig")
x5c = sig_key["x5c"][0]
cert_pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(x5c[i:i+64] for i in range(0, len(x5c), 64)) + "\n-----END CERTIFICATE-----\n"
pubkey_pem = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=cert_pem, capture_output=True, text=True, check=True).stdout
raw_b64 = "".join(l for l in pubkey_pem.splitlines() if l and "BEGIN" not in l and "END" not in l)

full = json.loads(subprocess.run(
    ["curl", "-sk", "-u", "admin:admin", "https://localhost:19800/_plugins/_security/api/securityconfig"],
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
with open("/tmp/osjwt_config_body.json", "w") as f:
    json.dump(full["config"], f)
PYEOF

curl -sk -u admin:admin -X PUT https://localhost:19800/_plugins/_security/api/securityconfig/config \
  -H "Content-Type: application/json" --data-binary @/tmp/osjwt_config_body.json
echo ""
echo "JWT auth domain configured. Running run_poc.py..."

source ~/venv/bin/activate 2>/dev/null || true
OSJWT_ORG_ID="$ORG_ID" python poc/opensearch_jwt/run_poc.py
