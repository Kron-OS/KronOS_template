#!/usr/bin/env bash
# Bootstrap: real OpenSearch 2.11.1, security enabled, JWT authc configured
# against this PoC's own throwaway RSA test key (no Keycloak -- this step
# is deliberately testing the OpenSearch DLS-templating mechanism in
# isolation, per the plan: "verify this works at all before touching
# Keycloak"). Then runs run_poc.py.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f test_key.pem ]; then
  openssl genrsa -out test_key.pem 2048 2>/dev/null
  openssl rsa -in test_key.pem -pubout -out test_pub.pem 2>/dev/null
fi

docker rm -f kronos-poc-osjwt2-opensearch >/dev/null 2>&1 || true
docker run -d --name kronos-poc-osjwt2-opensearch \
  -e discovery.type=single-node \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -p 19900:9200 -p 19901:9600 \
  opensearchproject/opensearch:2.11.1
until curl -sk -o /dev/null -u admin:admin https://localhost:19900/_cluster/health 2>/dev/null; do sleep 3; done

docker exec kronos-poc-osjwt2-opensearch bash -c \
  "echo 'plugins.security.unsupported.restapi.allow_securityconfig_modification: true' >> /usr/share/opensearch/config/opensearch.yml"
docker restart kronos-poc-osjwt2-opensearch
sleep 3
until curl -sk -o /dev/null -u admin:admin https://localhost:19900/_cluster/health 2>/dev/null; do sleep 3; done

python3 - << 'PYEOF'
import json, subprocess

pem = open("test_pub.pem").read()
raw_b64 = "".join(l for l in pem.splitlines() if l and "BEGIN" not in l and "END" not in l)

full = json.loads(subprocess.run(
    ["curl", "-sk", "-u", "admin:admin", "https://localhost:19900/_plugins/_security/api/securityconfig"],
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
with open("/tmp/osjwt2_config_body.json", "w") as f:
    json.dump(full["config"], f)
PYEOF

curl -sk -u admin:admin -X PUT https://localhost:19900/_plugins/_security/api/securityconfig/config \
  -H "Content-Type: application/json" --data-binary @/tmp/osjwt2_config_body.json
echo ""

# ONE generic, org-agnostic role -- the whole point of this PoC: no
# per-org role, DLS is templated from the token itself.
curl -sk -u admin:admin -X PUT https://localhost:19900/_plugins/_security/api/roles/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{
    "cluster_permissions": [],
    "index_permissions": [{
      "index_patterns": ["kronos-*"],
      "dls": "{\"term\": {\"kronos.org_id\": \"${attr.jwt.org_id}\"}}",
      "allowed_actions": ["read", "indices:data/read/search"]
    }]
  }' > /dev/null

# ONE static mapping, ever -- broad backend_role, not per-org/per-user.
curl -sk -u admin:admin -X PUT https://localhost:19900/_plugins/_security/api/rolesmapping/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{"backend_roles": ["analyst"]}' > /dev/null

echo "OpenSearch ready with generic templated-DLS role. Running run_poc.py..."
source ~/venv/bin/activate 2>/dev/null || true
cd "$SCRIPT_DIR/../../.."
python poc/opensearch_jwt/option_a_flat_claim/run_poc.py
