#!/bin/sh
# Provision a per-org OpenSearch Dashboards tenant (idempotent). Real
# design verified end-to-end in poc/opensearch_dashboards_sso/ (11/11 real
# checks) -- see that PoC's README.md for the full account. This is the
# single source of truth shared by dev/prod compose and any future Helm
# provisioning Job, mirroring scripts/provision_keycloak_org.sh's own role,
# and is meant to be called right after that script provisions the org
# itself (needs the org to already exist in Keycloak).
#
# WHY THIS IS PER-ORG AND NOT A SINGLE GENERIC ROLE (unlike the DLS side):
#   Confirmed by reading the real OpenSearch 2.11 docs
#   (access-control/document-level-security.md): ${attr.<TYPE>.<NAME>}
#   parameter substitution is documented ONLY for the "dls" field of index
#   permissions -- there is no equivalent templating for
#   tenant_permissions.tenant_patterns. So unlike the generic DLS role
#   (src/adapter/opensearch/client.py's ensure_generic_tenant_role -- one
#   role, ever, templated by ${attr.jwt.org_id}), Dashboards tenant
#   isolation genuinely needs one real tenant + one real role + one real
#   rolesmapping per org, each pointing at that org's own org_id as the
#   role-mapping's backend_role -- the org's own org_id value becomes one
#   of the backend_roles automatically, because the openid authc domain's
#   roles_key points at kronos-dashboard-roles' combined dashboard_roles
#   claim (org_id + realm roles merged, see
#   poc/opensearch_dashboards_dls/README.md), which always contains the
#   caller's org_id regardless of which realm role(s) they also have
#   (scripts/provision_opensearch_security.py).
#
# Required env:
#   OS_BASE             OpenSearch base URL, e.g. https://opensearch:9200
#   OS_ADMIN_USER / OS_ADMIN_PASSWORD   OpenSearch Security admin credentials
#   KC_BASE              Keycloak base URL, e.g. http://keycloak:8080
#   KC_REALM             Keycloak realm, e.g. kronos
#   KC_ADMIN_USER / KC_ADMIN_PASSWORD   Keycloak master-realm admin credentials
#   ORG_ALIAS            Organization alias, e.g. kronos-dev (used for tenant/role naming and Keycloak lookup)
set -eu

: "${OS_BASE:?OS_BASE is required}"
: "${OS_ADMIN_USER:?OS_ADMIN_USER is required}"
: "${OS_ADMIN_PASSWORD:?OS_ADMIN_PASSWORD is required}"
: "${KC_BASE:?KC_BASE is required}"
: "${KC_REALM:?KC_REALM is required}"
: "${KC_ADMIN_USER:?KC_ADMIN_USER is required}"
: "${KC_ADMIN_PASSWORD:?KC_ADMIN_PASSWORD is required}"
: "${ORG_ALIAS:?ORG_ALIAS is required}"

echo "provision_dashboards_tenant: realm=$KC_REALM org=$ORG_ALIAS os_base=$OS_BASE"

# Wait for Keycloak to be reachable (portable across compose healthchecks
# and k8s readiness -- same pattern as provision_keycloak_org.sh).
i=0
until curl -sf -o /dev/null "$KC_BASE/realms/master/.well-known/openid-configuration"; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "ERROR: Keycloak not reachable at $KC_BASE after ~5m" >&2
    exit 1
  fi
  sleep 5
done

TOKEN=$(curl -sf "$KC_BASE/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=$KC_ADMIN_USER&password=$KC_ADMIN_PASSWORD" \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
  echo "ERROR: could not obtain Keycloak admin token" >&2
  exit 1
fi

# Same alias-matching approach as provision_keycloak_org.sh's find_org_id
# (the organizations 'search' param matches name/domain, not alias).
ORG_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "$KC_BASE/admin/realms/$KC_REALM/organizations?first=0&max=1000" \
  | tr '{' '\n' \
  | grep "\"alias\":\"$ORG_ALIAS\"" \
  | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$ORG_ID" ]; then
  echo "ERROR: organization '$ORG_ALIAS' not found in realm '$KC_REALM' -- provision it first (provision_keycloak_org.sh)" >&2
  exit 1
fi
echo "Resolved org $ORG_ALIAS -> $ORG_ID"

# Wait for OpenSearch's security REST API to be reachable.
i=0
until curl -skf -u "$OS_ADMIN_USER:$OS_ADMIN_PASSWORD" -o /dev/null "$OS_BASE/_cluster/health"; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "ERROR: OpenSearch not reachable at $OS_BASE after ~5m" >&2
    exit 1
  fi
  sleep 5
done

TENANT_NAME="kronos-${ORG_ALIAS}"
ROLE_NAME="kronos-dash-${ORG_ALIAS}"

curl -skf -u "$OS_ADMIN_USER:$OS_ADMIN_PASSWORD" -X PUT \
  "$OS_BASE/_plugins/_security/api/tenants/$TENANT_NAME" \
  -H "Content-Type: application/json" \
  -d "{\"description\":\"KronOS Dashboards tenant for org $ORG_ALIAS\"}" > /dev/null
echo "Tenant $TENANT_NAME ensured."

curl -skf -u "$OS_ADMIN_USER:$OS_ADMIN_PASSWORD" -X PUT \
  "$OS_BASE/_plugins/_security/api/roles/$ROLE_NAME" \
  -H "Content-Type: application/json" \
  -d "{\"cluster_permissions\":[],\"tenant_permissions\":[{\"tenant_patterns\":[\"$TENANT_NAME\"],\"allowed_actions\":[\"kibana_all_write\"]}]}" > /dev/null
echo "Role $ROLE_NAME ensured."

# backend_roles: [ORG_ID] -- matches the openid authc domain's
# roles_key=org_id, so any Keycloak user whose org_id claim equals this
# value automatically satisfies this role-mapping. No per-member
# OpenSearch-side work is ever needed after this, matching the "new
# orgs/members need zero further OpenSearch-side provisioning" property
# already verified for DLS in poc/keycloak_opensearch_dls/.
curl -skf -u "$OS_ADMIN_USER:$OS_ADMIN_PASSWORD" -X PUT \
  "$OS_BASE/_plugins/_security/api/rolesmapping/$ROLE_NAME" \
  -H "Content-Type: application/json" \
  -d "{\"backend_roles\":[\"$ORG_ID\"]}" > /dev/null
echo "Rolesmapping $ROLE_NAME -> backend_role $ORG_ID ensured."

echo "provision_dashboards_tenant: complete"
