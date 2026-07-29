#!/usr/bin/env bash
# PoC: real Keycloak OIDC SSO into real OpenSearch Dashboards, plus
# automated per-org Dashboards tenant provisioning driven by the same flat
# org_id JWT claim already used for DLS (poc/opensearch_jwt/,
# poc/keycloak_opensearch_dls/). This is the missing piece flagged in
# poc/opensearch_dashboards_tenancy/README.md ("deliberately NOT wired to
# Keycloak OIDC ... real Keycloak<->Dashboards SSO is a separate concern")
# and access-management-review.md's [C-1] finding.
#
# Real OpenSearch/Dashboards 2.11.1 (pinned, matches docker-compose.dev.yml)
# + real Keycloak 26.2 (matches docker-compose.dev.yml, standardized this
# session), imports the ACTUAL production docker/keycloak/kronos-realm.json
# unmodified -- reuses the existing opensearch-dashboards client and the
# kronos-org-id client scope, no realm changes needed for this PoC.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

KC=kronos-poc-dashsso-keycloak
OS=kronos-poc-dashsso-opensearch
DASH=kronos-poc-dashsso-dashboards

# --network host for all three (not a custom bridge network), each on its
# real default port -- not an arbitrary choice. Real, reproduced finding:
# Dashboards computes its openid redirect Location SERVER-SIDE from its own
# openid.connect_url config, and (with Keycloak's --hostname-strict=false)
# Keycloak's discovery doc mirrors back whatever hostname *Dashboards*
# reached it by -- so that Location header, sent to this script's "browser"
# (run_poc.py, host-side), literally is Keycloak's container-DNS name.
# Fixing only Dashboards' own base_redirect_url (self-referential
# redirect_uri) was NOT enough; Keycloak's own advertised endpoint must
# *also* be reachable identically from both Dashboards (server-side) and
# this script (browser-side) -- exactly the single-hostname-for-both-legs
# problem already solved for poc/auth_flow/step_up_conditional_fix/ and
# others this session, here via --network host instead of a bridge network
# (this PoC has 3 services needing mutual + host reachability, not 1).
KC_PORT=8080
OS_PORT=9200
# Must be 5601 exactly, not an arbitrary remap: the real production
# opensearch-dashboards Keycloak client's redirectUris is
# ["http://localhost:5601/*"] only (docker/keycloak/kronos-realm.json,
# unmodified). Dashboards' own base_redirect_url (below) must match this
# registered value, and this script's "browser" (run_poc.py, run directly
# on the host per the same reasoning) reaches it the same way a real
# browser would in dev -- via localhost:5601.
DASH_PORT=5601

docker rm -f "$KC" "$OS" "$DASH" >/dev/null 2>&1 || true

# --- Real Keycloak 26.2, real production realm (unmodified), imported the
# SAME way docker-compose.dev.yml actually does it: --import-realm at
# container startup with the file volume-mounted, not POST /admin/realms.
# Real, reproduced finding: these two import paths are NOT equivalent --
# POST /admin/realms silently produced a realm missing Keycloak's built-in
# "profile"/"email"/"address"/"phone"/"roles"/"web-origins" client scopes
# (confirmed via GET .../client-scopes: only the 6 explicitly-listed custom
# ones existed), which made Dashboards' own default openid scope request
# ("openid profile email address phone") fail with a real
# invalid_scope error from Keycloak. --import-realm (this block) is what
# production actually uses, so it's what this PoC must verify against.
docker run -d --name "$KC" --network host \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HTTP_PORT=${KC_PORT} \
  -v "$REPO_ROOT/docker/keycloak/kronos-realm.json:/opt/keycloak/data/import/kronos-realm.json:ro" \
  quay.io/keycloak/keycloak:26.2 start-dev --import-realm --hostname-strict=false
until curl -s -o /dev/null "http://localhost:${KC_PORT}/realms/kronos/.well-known/openid-configuration"; do sleep 3; done
echo "Keycloak up, real production realm imported via --import-realm (matching docker-compose.dev.yml)."

KC_ADMIN=$(curl -s -X POST "http://localhost:${KC_PORT}/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" -d "username=admin" -d "password=admin" -d "grant_type=password" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# --- Real OpenSearch 2.11.1, security genuinely enabled (bundled demo certs) ---
docker run -d --name "$OS" --network host \
  -e discovery.type=single-node \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -e http.port=${OS_PORT} \
  opensearchproject/opensearch:2.11.1
until curl -sk -o /dev/null -u admin:admin https://localhost:${OS_PORT}/_cluster/health; do sleep 3; done

# securityconfig REST writes are refused unless this unsupported flag is set
# in opensearch.yml -- confirmed in poc/opensearch_jwt/run_poc.sh, not
# settable via env var or the REST API itself.
docker exec "$OS" bash -c \
  "echo 'plugins.security.unsupported.restapi.allow_securityconfig_modification: true' >> /usr/share/opensearch/config/opensearch.yml"
docker restart "$OS" >/dev/null
sleep 3
until curl -sk -o /dev/null -u admin:admin https://localhost:${OS_PORT}/_cluster/health; do sleep 3; done
echo "OpenSearch up, securityconfig modification enabled."

# --- Add a real openid authc domain trusting the real Keycloak above,
# alongside the existing (order=4) basic_internal_auth_domain (kept for
# admin:admin provisioning calls in this script, and kibanaserver's own
# internal calls from Dashboards). subject_key/roles_key per the real
# OpenSearch 2.11 docs (authentication-backends/openid-connect.md) and real
# source read at opensearch-project/security@2.11
# (AbstractHTTPJwtAuthenticator.java): HTTPJwtKeyByOpenIdConnectAuthenticator
# extends the SAME class the plain "jwt" authenticator uses, so
# roles_key/subject_key/attr.jwt.* all behave identically for openid as for
# the backend's own bearer-JWT domain in poc/opensearch_jwt/ -- confirmed by
# reading the class hierarchy directly, not assumed. roles_key=org_id reuses
# the EXACT SAME flat claim DLS already templates via ${attr.jwt.org_id}, so
# a Dashboards openid session gets DLS enforcement for free with zero extra
# Keycloak-side claim/mapper work.
#
# challenge=false (matching the real doc's own example, not guessed) and
# order=10 (after basic's order=4) are both load-bearing, confirmed by
# reading the real BackendRegistry.java auth-domain loop: a domain with
# challenge=true that fails to extract credentials (e.g. a plain Basic-Auth
# curl request, which has no JWT) immediately short-circuits with ITS OWN
# 401 and returns without ever trying later domains -- this broke admin:admin
# access entirely on the first attempt (challenge=true, order=1, evaluated
# before basic's order=4). challenge=false lets extraction simply fall
# through to the next domain instead.
python3 - << 'PYEOF'
import json, subprocess

full = json.loads(subprocess.run(
    ["curl", "-sk", "-u", "admin:admin", "https://localhost:9200/_plugins/_security/api/securityconfig"],
    capture_output=True, text=True, check=True,
).stdout)
authc = full["config"]["dynamic"]["authc"]
# The bundled demo basic_internal_auth_domain ALSO has challenge=true by
# default (confirmed by inspecting a fresh, unmodified 2.11.1 container's
# own securityconfig) -- with it evaluated first (order=4) and a
# Bearer-only request having no Basic-Auth header, IT short-circuits with
# its own 401 before openid_auth_domain (order=10) ever gets a turn, the
# exact same class of bug as the openid-domain-first case, just mirrored.
# Real BackendRegistry.java loop: ANY domain with challenge=true that fails
# to extract credentials terminates the whole chain immediately -- so at
# most the LAST-evaluated domain may safely keep challenge=true; every
# domain that requests/admin calls need to "fall through" from must be false.
authc["basic_internal_auth_domain"]["http_authenticator"]["challenge"] = False
authc["openid_auth_domain"] = {
    "http_enabled": True,
    "transport_enabled": False,
    "order": 10,
    "http_authenticator": {
        "type": "openid",
        "challenge": False,
        "config": {
            # subject_key=sub (not preferred_username, despite the real doc's
            # own generic example): this realm's actual ROPC-granted token
            # (decoded and inspected directly, not assumed) has no
            # preferred_username claim at all -- confirmed empirically.
            # subject_key=sub matches the already-proven, working choice in
            # poc/opensearch_jwt/jwt_auth_domain.json for the exact same reason.
            "subject_key": "sub",
            "roles_key": "org_id",
            "openid_connect_url": "http://localhost:8080/realms/kronos/.well-known/openid-configuration",
        },
    },
    "authentication_backend": {"type": "noop", "config": {}},
}
with open("/tmp/dashsso_config_body.json", "w") as f:
    json.dump(full["config"], f)
PYEOF
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/securityconfig/config \
  -H "Content-Type: application/json" --data-binary @/tmp/dashsso_config_body.json
echo ""
echo "openid authc domain configured."

# --- The real, already-shipped generic DLS role (src/adapter/opensearch/client.py
# ensure_generic_tenant_role) -- reproduced here verbatim so this PoC also
# confirms DLS keeps working for openid-authenticated sessions, not just the
# backend's own bearer-JWT domain. ---
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/roles/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{
    "cluster_permissions": [],
    "index_permissions": [{
      "index_patterns": ["kronos-*"],
      "dls": "{\"term\":{\"kronos.org_id\":\"${attr.jwt.org_id}\"}}",
      "allowed_actions": ["read", "indices:data/read/search"]
    }],
    "tenant_permissions": []
  }'
echo
curl -sk -u admin:admin -X PUT https://localhost:${OS_PORT}/_plugins/_security/api/rolesmapping/kronos-generic-tenant \
  -H "Content-Type: application/json" -d '{"backend_roles": ["org-admin","case-lead","analyst","read-only"]}'
echo

# --- Real OpenSearch Dashboards 2.11.1, security-dashboards plugin genuinely
# enabled, openid auth type per the real 2.11 docs
# (authentication-backends/openid-connect.md "OpenSearch Dashboards
# configuration" section). ---
#
# OPENSEARCH_SECURITY_AUTH_TYPE / OPENSEARCH_SECURITY_OPENID_* env vars do
# NOT work -- confirmed by reading the real
# opensearch-dashboards-docker-entrypoint.sh inside the pinned 2.11.1 image:
# its opensearch_dashboards_vars allowlist (the only env vars the entrypoint
# translates into --longopts) has ZERO opensearch_security.* entries at all.
# opensearch_security.multitenancy.enabled/tenants.preferred only APPEARED
# to work in poc/opensearch_dashboards_tenancy/ because they're already the
# image's own baked-in defaults (confirmed: a fresh, unmodified container's
# own config file already has them) -- a false positive never actually
# exercised before.
#
# Real fix, and NOT exec+restart into an already-started container (an
# earlier version of this script did that and hit a real, reproduced bug:
# the first boot's saved-objects migration had already started creating
# .kibana_1 by the time the restart landed, and the second boot's own
# migration then collided with it -- "resource_already_exists_exception",
# Dashboards stuck permanently 503). Bind-mount the extra openid config
# lines and append them to the real config file *before* the dashboards
# process itself starts, in the same single container boot, via a command
# override that wraps the image's own real entrypoint script.
# scope="openid" (not the plugin's own default "openid profile email
# address phone"): real, reproduced finding, confirmed via
# GET .../admin/realms/kronos/client-scopes against a real Keycloak import
# of the ACTUAL production kronos-realm.json (both via --import-realm, as
# here/production, and via POST /admin/realms) -- this realm genuinely has
# no "profile"/"email"/"address"/"phone" client-scope objects at all, only
# the custom ones it explicitly defines (kronos-roles, kronos-sub,
# organization, acr, kronos-org-id) plus the always-auto-created
# offline_access. Dashboards' default scope request included those
# nonexistent scopes and Keycloak correctly rejected the whole request with
# a real invalid_scope error -- not a bug in the realm (nothing else has
# ever requested those scopes; KronOS's own flat-claim design never needed
# them), but Dashboards' own openid config does need to ask for less than
# its own out-of-the-box default. "openid" alone is Keycloak's built-in
# implicit scope, always valid regardless of registered client scopes.
cat > /tmp/dashsso_openid_extra.yml << EOF
opensearch_security.auth.type: "openid"
opensearch_security.openid.connect_url: "http://localhost:${KC_PORT}/realms/kronos/.well-known/openid-configuration"
opensearch_security.openid.client_id: "opensearch-dashboards"
opensearch_security.openid.client_secret: "opensearch-dashboards-secret"
opensearch_security.openid.base_redirect_url: "http://localhost:${DASH_PORT}"
opensearch_security.openid.scope: "openid"
EOF
# base_redirect_url is load-bearing: without it, Dashboards computes its
# own self-referential redirect_uri from server.host (0.0.0.0 in this
# image's default config), producing
# redirect_uri=http://0.0.0.0:5601/auth/openid/login -- confirmed by
# directly observing that exact broken redirect_uri in a real 302 response
# before this fix -- which does not match the registered
# http://localhost:5601/* pattern and would be rejected by Keycloak.
docker run -d --name "$DASH" --network host \
  -e OPENSEARCH_HOSTS="[\"https://localhost:${OS_PORT}\"]" \
  -e OPENSEARCH_USERNAME=kibanaserver \
  -e OPENSEARCH_PASSWORD=kibanaserver \
  -e OPENSEARCH_SSL_VERIFICATIONMODE=none \
  -e SERVER_PORT=${DASH_PORT} \
  -v /tmp/dashsso_openid_extra.yml:/tmp/openid-extra.yml:ro \
  --entrypoint bash \
  opensearchproject/opensearch-dashboards:2.11.1 \
  -c "cat /tmp/openid-extra.yml >> /usr/share/opensearch-dashboards/config/opensearch_dashboards.yml && exec /usr/share/opensearch-dashboards/opensearch-dashboards-docker-entrypoint.sh opensearch-dashboards"
until curl -s -o /dev/null http://localhost:${DASH_PORT}/api/status --max-time 5; do sleep 3; done
# /api/status alone reports ready before the openid auth route actually
# works (observed a real, persistent 503 there for 100+s after /api/status
# already returned 200) -- wait for the real route Dashboards' own login
# flow uses.
until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:${DASH_PORT}/auth/openid/login)" = "302" ]; do sleep 3; done
echo "Dashboards up, openid auth type configured."

echo "OpenSearch + Dashboards + Keycloak ready. Running run_poc.py on the host..."
# Run directly on the host (not in a docker-network runner container, unlike
# an earlier version of this script): Dashboards' own openid redirect_uri
# is pinned to http://localhost:5601 (base_redirect_url above, matching the
# real Keycloak client's registered redirectUris) -- a real browser reaches
# it exactly this way, and every other real-login PoC this session
# (poc/auth_flow/, poc/auth_flow/step_up_conditional_fix/) uses the same
# host-side-script-as-browser pattern for the same reason.
source ~/venv/bin/activate 2>/dev/null || true
python3 "$SCRIPT_DIR/run_poc.py"
