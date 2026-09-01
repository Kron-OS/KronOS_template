"""Real second-case-lead fixture for `assert_case_lead_or_admin`
("of case"/"own") RBAC coverage (Gap Audit Milestone CCCC's own
recommendation #2, docs/PLAYWRIGHT_E2E_TEST_PLAN.md).

Unlike `seed_second_org.py` (a fresh THROWAWAY ORG + analyst member, for
cross-tenant isolation), this creates a fresh, real, throwaway user in
the EXISTING target org (default `kronos-dev`) with the real `case-lead`
realm role -- a second, genuinely distinct case-lead account is what's
needed to prove `assert_case_lead_or_admin` rejects a caller who HAS
Role.CASE_LEAD (so `requires_role` alone would let them through) but
does not own the specific case in question. The single static
`case-lead` dev user (docker/keycloak/kronos-realm.json) can't exercise
this by itself -- whatever case it creates, it owns.

Reuses `seed_second_org.py`'s own proven building blocks (user creation,
org-membership add, org_id attribute splice, realm-role assignment) and
`seed_detection.py`'s own `get_org_id` (existing-org lookup, not
creation) rather than re-deriving either.

Prints one JSON object to stdout; diagnostics go to stderr.

Run: ~/venv/bin/python3 frontend/e2e/fixtures/seed_second_case_lead.py [--org-alias kronos-dev]
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402
from _e2e_env import KEYCLOAK_INTERNAL_URL  # noqa: E402

KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
FIXTURE_USERNAME_PREFIX = "e2e-second-case-lead-"


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


def get_org_id(client: httpx.Client, token: str, alias: str) -> str:
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations?first=0&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    for org in resp.json():
        if org["alias"] == alias:
            return org["id"]
    raise RuntimeError(f"org alias {alias} not found")


def create_user(client: httpx.Client, token: str, username: str, password: str) -> str:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "username": username,
            "email": f"{username}@e2e.invalid",
            "firstName": "E2E",
            "lastName": "SecondCaseLeadFixture",
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
    # PUT .../users/{id} is NOT a partial update (poc/keycloak_opensearch_dls/README.md
    # bug 1) -- a body with only {"attributes": {...}} silently clears
    # firstName/lastName/email, so read-then-splice, same as seed_second_org.py.
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
    # A "realmRoles" field in the user-creation POST body is silently
    # ignored (confirmed, poc/keycloak_opensearch_dls/step4_new_member/) --
    # must be a separate call, same as seed_second_org.py.
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


def cleanup_stale_fixtures(client: httpx.Client, token: str) -> None:
    """Same real hygiene lesson as seed_second_org.py's own
    cleanup_stale_fixtures() -- self-clean at the START of every run
    (not a `finally` in the calling spec, which wouldn't run if a prior
    process crashed before teardown), not after."""
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users"
        f"?username={FIXTURE_USERNAME_PREFIX}&exact=false&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    stale = [u for u in resp.json() if u["username"].startswith(FIXTURE_USERNAME_PREFIX)]
    for user in stale:
        client.delete(
            f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user['id']}",
            headers={"Authorization": f"Bearer {token}"},
        ).raise_for_status()
    if stale:
        log(f"cleaned up {len(stale)} stale fixture user(s)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--org-alias", default="kronos-dev")
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:8]
    username = f"{FIXTURE_USERNAME_PREFIX}{suffix}"
    password = "E2eSecondCaseLead#2026"

    with httpx.Client(timeout=15) as client:
        token = get_admin_token(client)
        cleanup_stale_fixtures(client, token)

        org_id = get_org_id(client, token, args.org_alias)
        log(f"resolved live org_id={org_id} for alias={args.org_alias}")

        user_id = create_user(client, token, username, password)
        log(f"created real throwaway user {username} ({user_id})")

        add_org_member(client, token, org_id, user_id)
        set_org_id_attribute(client, token, user_id, org_id)
        assign_realm_role(client, token, user_id, "case-lead")
        log(f"user {username} is now a real case-lead member of org {args.org_alias}")

    print(json.dumps({
        "orgAlias": args.org_alias,
        "username": username,
        "password": password,
        "userId": user_id,
    }))


if __name__ == "__main__":
    main()
