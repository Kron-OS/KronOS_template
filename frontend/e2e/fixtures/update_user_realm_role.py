"""Real Keycloak Admin API realm-role swap for a single existing user --
for Gap Audit Milestone NNNN's mid-session role-change coverage
(docs/PLAYWRIGHT_E2E_TEST_PLAN.md).

Unlike every other `frontend/e2e/fixtures/seed_*.py` script (which create
a fresh throwaway user), this ACTS ON an existing user id -- the real
scenario under test is an org-admin changing an already-logged-in user's
role mid-session, not a freshly-provisioned account. Reuses
`seed_second_case_lead.py`'s own proven `assign_realm_role` building block
(role lookup + POST role-mappings/realm) and adds the DELETE-method
sibling for role removal -- confirmed against Keycloak 26.2's real Admin
API (`DELETE .../role-mappings/realm` takes the same `[role]` JSON body
shape as the POST).

Prints one JSON object to stdout; diagnostics go to stderr.

Run: ~/venv/bin/python3 frontend/e2e/fixtures/update_user_realm_role.py \
    --user-id <uuid> --remove-role case-lead --add-role analyst
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402
from _e2e_env import KEYCLOAK_INTERNAL_URL  # noqa: E402

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


def get_role(client: httpx.Client, token: str, role_name: str) -> dict:
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/roles/{role_name}",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()


def remove_realm_role(client: httpx.Client, token: str, user_id: str, role: dict) -> None:
    resp = client.request(
        "DELETE",
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
        headers={"Authorization": f"Bearer {token}"},
        json=[role],
    )
    resp.raise_for_status()


def assign_realm_role(client: httpx.Client, token: str, user_id: str, role: dict) -> None:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
        headers={"Authorization": f"Bearer {token}"},
        json=[role],
    )
    resp.raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--remove-role", required=True)
    parser.add_argument("--add-role", required=True)
    args = parser.parse_args()

    with httpx.Client(timeout=15) as client:
        token = get_admin_token(client)

        remove = get_role(client, token, args.remove_role)
        add = get_role(client, token, args.add_role)

        remove_realm_role(client, token, args.user_id, remove)
        assign_realm_role(client, token, args.user_id, add)
        log(f"user {args.user_id}: realm role {args.remove_role} -> {args.add_role}")

    print(json.dumps({"userId": args.user_id, "removedRole": args.remove_role, "addedRole": args.add_role}))


if __name__ == "__main__":
    main()
