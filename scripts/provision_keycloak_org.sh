#!/bin/sh
# Provision a Keycloak Organization via the Admin REST API (idempotent).
#
# WHY REST AND NOT REALM IMPORT:
#   Keycloak 26.1/26.2 cannot import an `organizations` block via --import-realm
#   (it writes org metadata onto the backing group outside the organization
#   context guard and fails with "Can not update organization group"). Creating
#   the organization through the Admin REST API uses the supported code path.
#
# This script is the single source of truth shared by the dev/prod
# docker-compose `keycloak-init` services and the Helm provisioning Job.
# It assumes the realm (and, for member linking, the users) already exist.
#
# Required env:
#   KC_BASE            Keycloak base URL, e.g. http://keycloak:8080
#   KC_REALM           Target realm, e.g. kronos
#   KC_ADMIN_USER      Master-realm admin username
#   KC_ADMIN_PASSWORD  Master-realm admin password
#   ORG_ALIAS          Organization alias, e.g. kronos-dev
#   ORG_NAME           Organization display name, e.g. "KronOS Dev"
# Optional env:
#   ORG_DESCRIPTION    Free-text description (default empty)
#   ORG_DOMAIN         A single org domain; created as verified (default none)
#   ORG_MEMBER_IDS     Space-separated user UUIDs to link as members (default none)
set -eu

: "${KC_BASE:?KC_BASE is required (e.g. http://keycloak:8080)}"
: "${KC_REALM:?KC_REALM is required (e.g. kronos)}"
: "${KC_ADMIN_USER:?KC_ADMIN_USER is required}"
: "${KC_ADMIN_PASSWORD:?KC_ADMIN_PASSWORD is required}"
: "${ORG_ALIAS:?ORG_ALIAS is required}"
: "${ORG_NAME:?ORG_NAME is required}"
ORG_DESCRIPTION="${ORG_DESCRIPTION:-}"
ORG_DOMAIN="${ORG_DOMAIN:-}"
ORG_MEMBER_IDS="${ORG_MEMBER_IDS:-}"

extract_first_id() { grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4; }

echo "provision_keycloak_org: realm=$KC_REALM org=$ORG_ALIAS base=$KC_BASE"

# Wait for Keycloak to be reachable (portable across compose healthchecks and
# k8s readiness; avoids needing a version-specific keycloak healthcheck).
i=0
until curl -sf -o /dev/null "$KC_BASE/realms/master/.well-known/openid-configuration"; do
  i=$((i + 1))
  if [ "$i" -ge 60 ]; then
    echo "ERROR: Keycloak not reachable at $KC_BASE after ~5m" >&2
    exit 1
  fi
  echo "waiting for Keycloak at $KC_BASE ($i/60)..."
  sleep 5
done

TOKEN=$(curl -sf "$KC_BASE/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=$KC_ADMIN_USER&password=$KC_ADMIN_PASSWORD" \
  | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$TOKEN" ]; then
  echo "ERROR: could not obtain admin token (check KC_ADMIN_USER / KC_ADMIN_PASSWORD)" >&2
  exit 1
fi

# Fail clearly if the realm itself is missing — prod/Helm assume it pre-exists.
if ! curl -sf -o /dev/null -H "Authorization: Bearer $TOKEN" "$KC_BASE/admin/realms/$KC_REALM"; then
  echo "ERROR: realm '$KC_REALM' does not exist; provision the realm before the org" >&2
  exit 1
fi

ORG_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "$KC_BASE/admin/realms/$KC_REALM/organizations?search=$ORG_ALIAS" | extract_first_id)

if [ -z "$ORG_ID" ]; then
  echo "Creating organization $ORG_ALIAS"
  if [ -n "$ORG_DOMAIN" ]; then
    DOMAINS="[{\"name\":\"$ORG_DOMAIN\",\"verified\":true}]"
  else
    DOMAINS="[]"
  fi
  curl -sf -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "$KC_BASE/admin/realms/$KC_REALM/organizations" \
    -d "{\"name\":\"$ORG_NAME\",\"alias\":\"$ORG_ALIAS\",\"enabled\":true,\"description\":\"$ORG_DESCRIPTION\",\"domains\":$DOMAINS}"
  ORG_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
    "$KC_BASE/admin/realms/$KC_REALM/organizations?search=$ORG_ALIAS" | extract_first_id)
else
  echo "Organization $ORG_ALIAS already exists"
fi

if [ -z "$ORG_ID" ]; then
  echo "ERROR: organization $ORG_ALIAS could not be created or found" >&2
  exit 1
fi
echo "Organization ID: $ORG_ID"

# Link members (no-op when ORG_MEMBER_IDS is empty). PUT is idempotent.
for USER_ID in $ORG_MEMBER_IDS; do
  STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    "$KC_BASE/admin/realms/$KC_REALM/organizations/$ORG_ID/members/$USER_ID" || true)
  echo "Linked member $USER_ID -> HTTP $STATUS"
done

echo "provision_keycloak_org: complete"
