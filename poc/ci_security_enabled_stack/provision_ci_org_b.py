#!/usr/bin/env python3
"""PoC-local (not shipped) provisioning: a SECOND real Keycloak Organization
+ one new real user + one new real client, purely to prove cross-org DLS
isolation against the CI security-enabled stack.

Why this exists separately from the real docker-compose.test.yml services:
the shipped keycloak-init service (docker/docker-compose.test.yml, real
production script docker/init/Dockerfile.keycloak-init ->
scripts/provision_keycloak_org.sh) creates exactly ONE org
("kronos-test") from the three realm-imported users -- correct for the
generic "does a real Keycloak org + OpenSearch DLS role exist" bar, but not
enough to prove ISOLATION (that requires two different real orgs with
different real org_id claims). This script adds a second org for that one
purpose, without permanently baking a second fake org into the shipped
compose profile (which every other future security-dependent test would
then have to know about/ignore).

Real, not simulated: every call below is a genuine Keycloak 26.2 Admin REST
API call against the real running kronos-test... err, "kronos" realm
imported by docker-compose.test.yml's keycloak service. Three real gotchas
already discovered and fixed in poc/keycloak_opensearch_dls/README.md are
reused here (org_id User Profile attribute already declared by
scripts/provision_keycloak_org.sh's own run; POST /users ignores a
client-supplied id; PUT /users/{id} is not a partial update).

Required env: KC_BASE, KC_REALM (default "kronos"), KC_ADMIN_USER,
KC_ADMIN_PASSWORD.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

KC_BASE = os.environ.get("KC_BASE", "http://localhost:18080")
KC_REALM = os.environ.get("KC_REALM", "kronos")
KC_ADMIN_USER = os.environ.get("KC_ADMIN_USER", "admin")
KC_ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "admin")

ORG_B_ALIAS = "kronos-ci-org-b"
ORG_B_NAME = "KronOS CI Org B"
CI_USER_USERNAME = "ci-analyst-b"
CI_USER_PASSWORD = "CiAnalystB#2026"
CI_CLIENT_ID = "kronos-ci-verifier"


def _token() -> str:
    resp = urllib.request.urlopen(  # noqa: S310 - trusted local Keycloak
        urllib.request.Request(
            f"{KC_BASE}/realms/master/protocol/openid-connect/token",
            data=(
                f"client_id=admin-cli&grant_type=password&username={KC_ADMIN_USER}"
                f"&password={KC_ADMIN_PASSWORD}"
            ).encode(),
            method="POST",
        ),
        timeout=15,
    )
    return json.loads(resp.read())["access_token"]


def _req(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict | None]:
    url = f"{KC_BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=15)  # noqa: S310
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, (json.loads(raw) if raw else None)


def main() -> None:
    token = _token()
    print(f"provision_ci_org_b: got admin token, realm={KC_REALM}")

    # --- 1. Create the CI verifier client (mirrors kronos-frontend's own
    # audience mapper exactly -- docker/keycloak/kronos-realm.json -- so
    # tokens minted through it carry the same aud=kronos-backend claim the
    # real KeycloakTokenValidator checks). Public + direct-access-grants so
    # a non-interactive CI job can log in without a browser redirect;
    # kronos-frontend/kronos-backend/opensearch-dashboards/kronos-attest
    # (the real shipped clients) all have directAccessGrantsEnabled=False
    # by design (AUTH review), so this is a genuinely new, additive,
    # CI-only client -- no existing client's security posture is touched.
    status, existing = _req(
        "GET", f"/admin/realms/{KC_REALM}/clients?clientId={CI_CLIENT_ID}", token
    )
    if existing:
        print(f"client {CI_CLIENT_ID} already exists, skipping create")
        client_internal_id = existing[0]["id"]
    else:
        status, _ = _req(
            "POST",
            f"/admin/realms/{KC_REALM}/clients",
            token,
            {
                "clientId": CI_CLIENT_ID,
                "enabled": True,
                "publicClient": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": False,
                "protocolMappers": [
                    {
                        "name": "kronos-backend-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "consentRequired": False,
                        "config": {
                            "included.client.audience": "kronos-backend",
                            "id.token.claim": "false",
                            "access.token.claim": "true",
                        },
                    }
                ],
            },
        )
        print(f"create client {CI_CLIENT_ID} -> HTTP {status}")
        _, existing = _req(
            "GET", f"/admin/realms/{KC_REALM}/clients?clientId={CI_CLIENT_ID}", token
        )
        client_internal_id = existing[0]["id"]

    # Real, reproduced finding: OpenSearch's own openid authc domain
    # (scripts/provision_opensearch_security.py) reads its backend_roles
    # from roles_key="dashboard_roles" -- a claim ONLY emitted via the
    # "kronos-dashboard-roles" client scope (docker/keycloak/kronos-realm.json),
    # which the realm's defaultDefaultClientScopes do NOT include (only the
    # real "opensearch-dashboards" client is explicitly wired with it). A
    # first version of this script omitted this and every real DLS-scoped
    # search below 403'd -- confirmed by direct reproduction: the token had
    # a real "roles" claim but no "dashboard_roles" claim at all, so
    # kronos-generic-tenant's rolesmapping (backend_roles=[...]) never
    # matched. This client needs the identical scope shape a real
    # Dashboards-SSO-issued token has for this test to exercise the real
    # DLS path meaningfully.
    _, scopes = _req("GET", f"/admin/realms/{KC_REALM}/client-scopes", token)
    dashboard_scope = next((s for s in scopes if s["name"] == "kronos-dashboard-roles"), None)
    if dashboard_scope is None:
        print("ERROR: kronos-dashboard-roles client scope not found in realm", file=sys.stderr)
        sys.exit(1)
    status, _ = _req(
        "PUT",
        f"/admin/realms/{KC_REALM}/clients/{client_internal_id}/default-client-scopes/{dashboard_scope['id']}",
        token,
    )
    print(f"attach kronos-dashboard-roles scope to {CI_CLIENT_ID} -> HTTP {status}")

    # --- 2. Create the second real user (POST /users ignores a
    # client-supplied id -- poc/keycloak_opensearch_dls/step4_new_member's
    # own finding -- so look it up by username afterward). ---
    status, _ = _req(
        "GET", f"/admin/realms/{KC_REALM}/users?username={CI_USER_USERNAME}&exact=true", token
    )
    _, found = _req(
        "GET", f"/admin/realms/{KC_REALM}/users?username={CI_USER_USERNAME}&exact=true", token
    )
    if found:
        user_id = found[0]["id"]
        print(f"user {CI_USER_USERNAME} already exists (id={user_id})")
    else:
        status, _ = _req(
            "POST",
            f"/admin/realms/{KC_REALM}/users",
            token,
            {
                "username": CI_USER_USERNAME,
                "email": f"{CI_USER_USERNAME}@kronos-ci.test",
                "firstName": "CI",
                "lastName": "AnalystB",
                "enabled": True,
                "emailVerified": True,
                "credentials": [
                    {"type": "password", "value": CI_USER_PASSWORD, "temporary": False}
                ],
            },
        )
        print(f"create user {CI_USER_USERNAME} -> HTTP {status}")
        _, found = _req(
            "GET", f"/admin/realms/{KC_REALM}/users?username={CI_USER_USERNAME}&exact=true", token
        )
        if not found:
            print("ERROR: could not find newly created user", file=sys.stderr)
            sys.exit(1)
        user_id = found[0]["id"]

    # Assign the "analyst" realm role for realism (roles claim non-empty).
    _, roles = _req("GET", f"/admin/realms/{KC_REALM}/roles/analyst", token)
    if roles:
        status, _ = _req(
            "POST",
            f"/admin/realms/{KC_REALM}/users/{user_id}/role-mappings/realm",
            token,
            [roles],
        )
        print(f"assign analyst role to {CI_USER_USERNAME} -> HTTP {status}")

    # --- 3. Create org B and link the new user, via the REAL,
    # UNMODIFIED production script (scripts/provision_keycloak_org.sh) --
    # not a reimplementation. This also re-verifies that script against a
    # SECOND org in the same realm run (idempotent org_id User Profile
    # declaration, member-linking with an existing-attributes user this
    # time, unlike a fresh realm-import user). ---
    import subprocess  # noqa: PLC0415

    env = dict(os.environ)
    env.update(
        {
            "KC_BASE": KC_BASE,
            "KC_REALM": KC_REALM,
            "KC_ADMIN_USER": KC_ADMIN_USER,
            "KC_ADMIN_PASSWORD": KC_ADMIN_PASSWORD,
            "ORG_NAME": ORG_B_NAME,
            "ORG_ALIAS": ORG_B_ALIAS,
            "ORG_DESCRIPTION": "CI-only second org, isolation proof",
            "ORG_DOMAIN": "org-b.kronos-ci.test",
            "ORG_MEMBER_IDS": user_id,
        }
    )
    script_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "scripts",
        "provision_keycloak_org.sh",
    )
    result = subprocess.run(["sh", script_path], env=env, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    print(json.dumps({"user_id": user_id, "org_b_alias": ORG_B_ALIAS}, indent=2))
    print("provision_ci_org_b: complete")


if __name__ == "__main__":
    main()
