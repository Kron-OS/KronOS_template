"""Real second-org fixture for cross-tenant UI isolation E2E specs
(docs/PLAYWRIGHT_E2E_TEST_PLAN.md §3.5).

Reuses proven patterns rather than re-deriving them, all already
established in this repo:
- Live admin token via client_credentials against the real `kronos-backend`
  service account (poc/detection_containment_ui/setup.py).
- Idempotent org lookup/creation via the Admin REST API, mirroring
  scripts/provision_keycloak_org.sh's own approach (that script itself
  can't be reused directly here -- it's shell, requires master-realm
  admin creds this fixture doesn't have, and only *updates* an existing
  org's members, doesn't create a fresh org for a throwaway test).
- The org_id flat-claim user attribute, set via a real GET-then-splice PUT
  -- `PUT .../users/{id}` is NOT a partial update (confirmed bug,
  poc/keycloak_opensearch_dls/README.md bug 1): a body with only
  {"attributes": {...}} silently clears firstName/lastName/email.
- Realm role assignment via a SEPARATE POST .../role-mappings/realm call
  -- a "realmRoles" field in the user-creation POST body is silently
  ignored (confirmed, poc/keycloak_opensearch_dls/step4_new_member/).

A fresh org + fresh throwaway user is created every run (unique suffix) --
simpler than idempotent reuse for a real, disposable E2E fixture, and
avoids any stale-state-from-a-prior-run class of bug.

Prints one JSON object to stdout; diagnostics go to stderr.

Run: ~/venv/bin/python3 frontend/e2e/fixtures/seed_second_org.py
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import UTC, datetime

import httpx

# Milestone OOO: this sibling script didn't get the same
# KRONOS_E2E_KEYCLOAK_URL override seed_detection.py got in Milestone NNN
# -- a real gap, not just a style inconsistency. Running this script
# unmodified against an isolated, differently-port-mapped test-stack
# instance on this host (which also has the real dev stack's own
# Keycloak holding the unremapped 8080) silently created every org/user
# on the WRONG (dev stack's) Keycloak instance while every verification
# check queried the isolated instance -- looked exactly like Keycloak
# silently deleting freshly-created users within ~1 second, and cost
# real debugging time chasing a phantom bug before the actual cause
# (two different Keycloak instances, never one deleting anything) was
# found. Same reasoning as seed_detection.py's own override: correct for
# either compose profile alone (both publish 8080 unremapped), only a
# problem for local multi-stack-host verification, not real CI.
KEYCLOAK_INTERNAL_URL = os.environ.get("KRONOS_E2E_KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}", file=sys.stderr)


def get_admin_token(client: httpx.Client) -> str:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
            "client_secret": KEYCLOAK_ADMIN_CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def create_org(client: httpx.Client, token: str, alias: str, name: str) -> str:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": name,
            "alias": alias,
            "enabled": True,
            "description": "E2E cross-tenant isolation fixture (throwaway)",
            "domains": [{"name": f"{alias}.e2e.invalid", "verified": True}],
        },
    )
    resp.raise_for_status()
    org_id = resp.headers["Location"].rsplit("/", 1)[-1]
    return org_id


def create_user(client: httpx.Client, token: str, username: str, password: str) -> str:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "username": username,
            "email": f"{username}@e2e.invalid",
            "firstName": "E2E",
            "lastName": "IsolationFixture",
            "enabled": True,
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    resp.raise_for_status()
    return resp.headers["Location"].rsplit("/", 1)[-1]


def add_org_member(client: httpx.Client, token: str, org_id: str, user_id: str) -> None:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org_id}/members",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=f'"{user_id}"',
    )
    resp.raise_for_status()


def set_org_id_attribute(client: httpx.Client, token: str, user_id: str, org_id: str) -> None:
    current = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    current.raise_for_status()
    user_repr = current.json()
    user_repr["attributes"] = {**user_repr.get("attributes", {}), "org_id": [org_id]}
    resp = client.put(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
        json=user_repr,
    )
    resp.raise_for_status()


def assign_realm_role(client: httpx.Client, token: str, user_id: str, role_name: str) -> None:
    role_resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/roles/{role_name}",
        headers={"Authorization": f"Bearer {token}"},
    )
    role_resp.raise_for_status()
    role = role_resp.json()
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
        headers={"Authorization": f"Bearer {token}"},
        json=[role],
    )
    resp.raise_for_status()


FIXTURE_ORG_ALIAS_PREFIX = "kronos-e2e-isolation-"


def cleanup_stale_fixtures(client: httpx.Client, token: str) -> None:
    """Real, reproduced hygiene gap (security-scenario subagent review,
    2026-08-28): unlike seed_detection.py (which looks up an EXISTING org,
    never minting new Keycloak principals), this script creates a fresh
    org + a fresh, permanently-enabled real user with a hardcoded,
    reusable password on every single run, with nothing ever deleting
    them -- confirmed live, four prior runs this session alone had left
    four real orgs + four real live-credentialed users sitting in the
    realm. Self-cleans at the START of every run (not relying on a
    `finally` in the calling spec, which wouldn't run if a prior process
    crashed/was killed before teardown) by deleting any org whose alias
    matches this fixture's own naming convention, plus its member users."""
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations?first=0&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    stale = [o for o in resp.json() if o["alias"].startswith(FIXTURE_ORG_ALIAS_PREFIX)]
    for org in stale:
        members_resp = client.get(
            f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org['id']}/members",
            headers={"Authorization": f"Bearer {token}"},
        )
        members_resp.raise_for_status()
        for member in members_resp.json():
            client.delete(
                f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{member['id']}",
                headers={"Authorization": f"Bearer {token}"},
            ).raise_for_status()
        client.delete(
            f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org['id']}",
            headers={"Authorization": f"Bearer {token}"},
        ).raise_for_status()
        log(f"cleaned up stale fixture org {org['alias']} ({org['id']}) + {len(members_resp.json())} member(s)")


def main() -> None:
    suffix = uuid.uuid4().hex[:8]
    org_alias = f"{FIXTURE_ORG_ALIAS_PREFIX}{suffix}"
    username = f"e2e-isolation-{suffix}"
    password = "E2eIsolation#2026"

    with httpx.Client(timeout=15) as client:
        token = get_admin_token(client)
        cleanup_stale_fixtures(client, token)

        org_id = create_org(client, token, org_alias, f"E2E Isolation Org {suffix}")
        log(f"created real org {org_id} alias={org_alias}")

        user_id = create_user(client, token, username, password)
        log(f"created real throwaway user {username} ({user_id})")

        add_org_member(client, token, org_id, user_id)
        set_org_id_attribute(client, token, user_id, org_id)
        assign_realm_role(client, token, user_id, "analyst")
        log(f"user {username} is now a real member of org {org_alias} with org_id attribute + analyst role")

    print(json.dumps({"orgId": org_id, "orgAlias": org_alias, "username": username, "password": password}))


if __name__ == "__main__":
    main()
