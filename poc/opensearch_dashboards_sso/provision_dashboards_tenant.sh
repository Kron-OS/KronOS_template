#!/bin/sh
# Provision a per-org OpenSearch Dashboards tenant (idempotent), the missing
# piece for real per-org saved-object isolation once Dashboards is wired to
# Keycloak OIDC (this PoC's run_poc.sh).
#
# WHY THIS IS PER-ORG AND NOT A SINGLE GENERIC ROLE (unlike the DLS side):
#   Confirmed by reading the real OpenSearch 2.11 docs
#   (access-control/document-level-security.md): ${attr.<TYPE>.<NAME>}
#   parameter substitution is documented ONLY for the "dls" field of index
#   permissions -- there is no equivalent templating for
#   tenant_permissions.tenant_patterns. So unlike ensure_generic_tenant_role()
#   (one role, ever, templated by ${attr.jwt.org_id}), Dashboards tenant
#   isolation genuinely needs one real tenant + one real role + one real
#   rolesmapping per org, each pointing at that org's own org_id as the
#   role-mapping's backend_role -- the SAME flat org_id JWT claim
#   (kronos-org-id client scope) becomes the backend_role automatically,
#   because the openid authc domain's roles_key is configured to point at
#   that same claim (run_poc.sh).
#
# Required env:
#   OS_BASE       OpenSearch base URL, e.g. https://opensearch:9200
#   OS_ADMIN_USER / OS_ADMIN_PASSWORD   OpenSearch Security admin credentials
#   ORG_ALIAS     Organization alias, e.g. kronos-dev (used for tenant/role naming)
#   ORG_ID        Keycloak organization UUID (becomes the rolesmapping backend_role)
set -eu

: "${OS_BASE:?OS_BASE is required}"
: "${OS_ADMIN_USER:?OS_ADMIN_USER is required}"
: "${OS_ADMIN_PASSWORD:?OS_ADMIN_PASSWORD is required}"
: "${ORG_ALIAS:?ORG_ALIAS is required}"
: "${ORG_ID:?ORG_ID is required}"

TENANT_NAME="kronos-${ORG_ALIAS}"
ROLE_NAME="kronos-dash-${ORG_ALIAS}"

echo "provision_dashboards_tenant: org=$ORG_ALIAS org_id=$ORG_ID tenant=$TENANT_NAME"

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
# roles_key=org_id (run_poc.sh), so any Keycloak user whose org_id claim
# equals this value automatically satisfies this role-mapping. No
# per-member OpenSearch-side work is ever needed after this, matching the
# "new orgs/members need zero further OpenSearch-side provisioning"
# property already verified for DLS in poc/keycloak_opensearch_dls/.
curl -skf -u "$OS_ADMIN_USER:$OS_ADMIN_PASSWORD" -X PUT \
  "$OS_BASE/_plugins/_security/api/rolesmapping/$ROLE_NAME" \
  -H "Content-Type: application/json" \
  -d "{\"backend_roles\":[\"$ORG_ID\"]}" > /dev/null
echo "Rolesmapping $ROLE_NAME -> backend_role $ORG_ID ensured."

echo "provision_dashboards_tenant: complete"
