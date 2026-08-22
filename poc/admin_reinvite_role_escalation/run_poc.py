"""Real Keycloak Admin API repro: does re-inviting an existing org member
with a NEW role (POST /api/admin/org/users/invite's reuse path,
src/external/routes/admin.py::invite_user -> _create_or_get_user ->
_assign_realm_role) actually REPLACE their role, or just ADD the new one
on top of whatever they already had?

`invite_user`'s own docstring says: "If a user with this email already
exists and already belongs to the caller's org, they are reused and
simply re-assigned the requested role" -- "re-assigned" reads as
"replaced". But `invite_user` calls `_assign_realm_role()` (line 182),
which only POSTs the new role -- it never removes any existing one.
Contrast with `update_user_role` (PATCH /users/{id}/role), which calls
`_set_realm_role()` -- GETs current managed roles, DELETEs the stale
ones, THEN adds the new one.

This PoC bypasses the FastAPI route (and its aal2 step-up gate) entirely
and talks to the REAL Keycloak 26.2.5 Admin REST API directly, using the
same real service-account credentials `_keycloak_admin_request()` uses
internally -- this isolates the actual question (does Keycloak's own
POST role-mappings endpoint add or replace?) from the unrelated aal2/
step-up UI flow, which a separate PoC (poc/detection_containment_ui/)
already exercises for a different route.

Run: ~/venv/bin/python3 poc/admin_reinvite_role_escalation/run_poc.py
Requires docker-keycloak-1 (26.2.5) already running.
"""
from __future__ import annotations

import sys
import uuid

import httpx

KEYCLOAK_URL = "http://localhost:8080"
REALM = "kronos"
ADMIN_CLIENT_ID = "kronos-backend"
ADMIN_CLIENT_SECRET = "kronos-backend-secret"
KRONOS_DEV_ORG_ALIAS = "kronos-dev"
MANAGED_ROLES = frozenset({"org-admin", "case-lead", "analyst", "read-only"})

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"{'PASS' if ok else 'FAIL'}: {label}")


def get_admin_token(client: httpx.Client) -> str:
    resp = client.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": ADMIN_CLIENT_ID,
            "client_secret": ADMIN_CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_org_id(client: httpx.Client, token: str, alias: str) -> str:
    resp = client.get(
        f"{KEYCLOAK_URL}/admin/realms/{REALM}/organizations?first=0&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    for org in resp.json():
        if org["alias"] == alias:
            return org["id"]
    raise RuntimeError(f"org alias {alias} not found")


def main() -> None:
    with httpx.Client(timeout=15) as client:
        token = get_admin_token(client)
        headers = {"Authorization": f"Bearer {token}"}
        org_id = get_org_id(client, token, KRONOS_DEV_ORG_ALIAS)
        print(f"resolved real kronos-dev org_id={org_id}")

        # === Step 1: create a real, throwaway user (mirrors
        # _create_or_get_user's own representation shape) ===
        suffix = uuid.uuid4().hex[:8]
        email = f"poc-nn-reinvite-{suffix}@example.invalid"
        representation = {
            "username": email,
            "email": email,
            "firstName": "PoC",
            "lastName": "Reinvite",
            "enabled": True,
            "emailVerified": True,
            "requiredActions": ["UPDATE_PASSWORD"],
            "credentials": [{"type": "password", "value": "PocReinvite#2026xyz", "temporary": True}],
        }
        resp = client.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users", json=representation, headers=headers
        )
        check("real user created (201)", resp.status_code == 201)
        user_id = resp.headers["location"].rstrip("/").rsplit("/", 1)[-1]
        print(f"created real user {user_id} ({email})")

        # Add to the real kronos-dev org (POST .../organizations/{id}/members
        # takes a bare quoted string body, matching _add_org_member's own shape).
        resp = client.post(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/organizations/{org_id}/members",
            content=f'"{user_id}"',
            headers={**headers, "Content-Type": "application/json"},
        )
        check("real user added to kronos-dev org", resp.status_code in (200, 201, 204, 409))

        # === Step 2: "invite" with role=org-admin (mirrors _assign_realm_role) ===
        def assign_role(role_name: str) -> None:
            role = client.get(
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/roles/{role_name}", headers=headers
            ).json()
            resp = client.post(
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
                json=[{"id": role["id"], "name": role["name"]}],
                headers=headers,
            )
            if resp.status_code not in (204, 409):
                raise RuntimeError(f"assign_role({role_name}) failed: {resp.status_code} {resp.text}")

        def current_managed_roles() -> set[str]:
            resp = client.get(
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
                headers=headers,
            )
            resp.raise_for_status()
            return {r["name"] for r in resp.json() if r.get("name") in MANAGED_ROLES}

        assign_role("org-admin")
        roles_after_first_invite = current_managed_roles()
        check(
            "after first invite (role=org-admin): user has exactly {'org-admin'}",
            roles_after_first_invite == {"org-admin"},
        )
        print(f"managed roles after first invite: {roles_after_first_invite}")

        # === Step 3: THE REAL QUESTION -- "re-invite" the SAME existing org
        # member with role=read-only, using the EXACT same _assign_realm_role
        # (add-only) semantics invite_user's reuse path actually calls. ===
        assign_role("read-only")
        roles_after_reinvite = current_managed_roles()
        print(f"managed roles after re-invite with role=read-only: {roles_after_reinvite}")

        check(
            "*** FINDING *** re-inviting with role=read-only did NOT remove "
            "the prior org-admin role -- user still has BOTH roles "
            "simultaneously, despite invite_user's own docstring claiming "
            "the role is 're-assigned'",
            roles_after_reinvite == {"org-admin", "read-only"},
        )
        check(
            "the user is THEREFORE still a real, live org-admin in Keycloak "
            "even though an operator just attempted to demote them to "
            "read-only via the invite/re-invite flow",
            "org-admin" in roles_after_reinvite,
        )

        # === Cross-check: the DEDICATED update_user_role endpoint's own
        # _set_realm_role helper (GET + DELETE stale + assign) DOES correctly
        # replace, proving this is an invite_user-specific inconsistency, not
        # a Keycloak API limitation. ===
        current = client.get(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
            headers=headers,
        ).json()
        stale = [
            {"id": r["id"], "name": r["name"]}
            for r in current
            if r.get("name") in MANAGED_ROLES and r.get("name") != "read-only"
        ]
        if stale:
            del_resp = client.request(
                "DELETE",
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}/role-mappings/realm",
                json=stale,
                headers=headers,
            )
            check("real DELETE of stale role-mappings succeeds", del_resp.status_code == 204)
        roles_after_set_realm_role_style_fix = current_managed_roles()
        check(
            "the DEDICATED update_user_role endpoint's own _set_realm_role "
            "logic (explicit DELETE-stale-then-assign) DOES correctly leave "
            "only {'read-only'} -- confirming this is a real invite_user-"
            "specific bug, not a Keycloak API limitation",
            roles_after_set_realm_role_style_fix == {"read-only"},
        )

        # === Cleanup: remove the real throwaway user ===
        del_user_resp = client.request(
            "DELETE", f"{KEYCLOAK_URL}/admin/realms/{REALM}/users/{user_id}", headers=headers
        )
        check("real throwaway user deleted", del_user_resp.status_code == 204)

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
