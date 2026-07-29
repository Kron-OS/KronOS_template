"""Step 4: a BRAND-NEW org member, created and linked to an ALREADY-EXISTING
real Organization AFTER OpenSearch's role/DLS/mapping is already fully
configured -- does real DLS isolation "just work" for them with zero further
OpenSearch-side provisioning?

Step 3 (../) proved the flat org_id claim mechanism end-to-end, but every
user was provisioned before OpenSearch was ever configured. This isolates
the actual scaling claim from option_a_flat_claim/README.md: "a new org
member needs zero OpenSearch-side changes."

Run via run_poc.sh, which brings up real Keycloak + OpenSearch, provisions
ONE initial member (user-a1) into org A, configures OpenSearch fully, and
prints an explicit marker after which it never touches
/_plugins/_security/* again -- everything from here on (creating user-a3,
linking them into the existing org, logging in as them) is Keycloak-only.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import asyncio  # noqa: E402
import os  # noqa: E402

import httpx  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402

KC_PORT = os.environ.get("KCOSDLS4_KC_PORT", "18085")
OS_PORT = os.environ.get("KCOSDLS4_OS_PORT", "19930")
KC_BASE = f"http://localhost:{KC_PORT}"
OS_URL = f"https://localhost:{OS_PORT}"
REALM = "kronos"
TOKEN_URL = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token"
ADMIN_TOKEN_URL = f"{KC_BASE}/realms/master/protocol/openid-connect/token"

SCRIPT_DIR = Path(__file__).resolve().parent
PARENT_DIR = SCRIPT_DIR.parent

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def get_admin_token() -> str:
    resp = httpx.post(
        ADMIN_TOKEN_URL,
        data={"client_id": "admin-cli", "grant_type": "password", "username": "admin", "password": "admin"},
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def password_grant(username: str, password: str) -> str:
    resp = httpx.post(
        TOKEN_URL,
        data={"client_id": "kronos-frontend", "grant_type": "password", "username": username, "password": password},
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def search_as(token: str, index: str) -> dict:
    with httpx.Client(verify=False) as h:
        resp = h.get(f"{OS_URL}/{index}/_search", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json()


async def main() -> None:
    admin_token = get_admin_token()

    # --- 1. Baseline: the ALREADY-provisioned user-a1 works (sanity) ---
    print("=" * 10, "1. Baseline: pre-existing user-a1 in org A", "=" * 10)
    token_a1 = password_grant("user-a1", "DlsUserA1#2026")
    claims_a1 = jose_jwt.get_unverified_claims(token_a1)
    org_id_a = claims_a1["org_id"]
    print(f"user-a1 org_id = {org_id_a}")
    check("pre-existing user-a1 has the flat org_id claim", isinstance(org_id_a, str))

    client = OpenSearchClient(hosts=[{"host": "localhost", "port": int(OS_PORT)}], http_auth=("admin", "admin"), use_ssl=True, verify_certs=False)
    await client.ensure_index_template()
    index_name = "kronos-shared-case-newmember-202607"
    n = await client.bulk_index([
        (index_name, "doc-org-a", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "belongs to org A",
            "kronos": {"org_id": org_id_a, "case_id": "newmember", "evidence_id": "e1", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
    ])
    await client._client.indices.refresh(index=index_name)
    await client.close()
    check("real doc indexed via the real bulk_index()", n == 1)

    result_a1 = search_as(token_a1, index_name)
    ids_a1 = {h["_id"] for h in result_a1["hits"]["hits"]}
    check("user-a1 sees org A's doc (baseline, before the new member exists)", ids_a1 == {"doc-org-a"}, str(ids_a1))

    # --- 2. THE actual test: create a BRAND NEW Keycloak user, AFTER OpenSearch
    #    is already fully configured, and link them into the EXISTING org. ---
    print("\n" + "=" * 10, "2. Brand-new user created + linked to the EXISTING org (Keycloak-only, no OpenSearch calls)", "=" * 10)
    create_resp = httpx.post(
        f"{KC_BASE}/admin/realms/{REALM}/users",
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"},
        json={
            "username": "user-a3-latecomer",
            "email": "user-a3-latecomer@kronos.dev",
            "firstName": "User",
            "lastName": "A3Latecomer",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": "DlsUserA3#2026", "temporary": False}],
        },
        timeout=10.0,
    )
    print(f"create user-a3-latecomer -> HTTP {create_resp.status_code}")
    check("brand-new Keycloak user created successfully (never existed before this run)", create_resp.status_code == 201)
    # Real finding: POST /users silently IGNORES a client-supplied "id" field
    # and always server-generates one -- the real id is only in the Location
    # header (confirmed empirically; a first attempt that assumed the
    # submitted id was honored caused every subsequent call to 404/400).
    new_user_id = create_resp.headers["Location"].rsplit("/", 1)[-1]
    print(f"real generated user id (from Location header) = {new_user_id}")

    # Real finding: "realmRoles" in the user-creation payload is ALSO silently
    # ignored by POST /users (confirmed: a first attempt included it and the
    # resulting token's 'roles' claim was just the realm defaults, no
    # 'analyst' -- which then made OpenSearch return 403, no privileges
    # matched). Assigning a realm role needs its own explicit call.
    role_resp = httpx.get(
        f"{KC_BASE}/admin/realms/{REALM}/roles/analyst",
        headers={"Authorization": f"Bearer {admin_token}"}, timeout=10.0,
    )
    role_resp.raise_for_status()
    analyst_role = role_resp.json()
    assign_resp = httpx.post(
        f"{KC_BASE}/admin/realms/{REALM}/users/{new_user_id}/role-mappings/realm",
        headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"},
        json=[{"id": analyst_role["id"], "name": analyst_role["name"]}],
        timeout=10.0,
    )
    print(f"assign 'analyst' realm role -> HTTP {assign_resp.status_code}")
    check("'analyst' realm role explicitly assigned to the brand-new user", assign_resp.status_code == 204)

    # Re-invoke the SAME real provisioning script, targeting the ALREADY-EXISTING
    # org, with ONLY the new user's id -- this is the real operational path for
    # "an existing org gets a new member", not a special case written for this test.
    provision_result = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "host",
            "-v", f"{PARENT_DIR}/provision_keycloak_org.sh:/provision_keycloak_org.sh:ro",
            "-e", f"KC_BASE={KC_BASE}", "-e", f"KC_REALM={REALM}",
            "-e", "KC_ADMIN_USER=admin", "-e", "KC_ADMIN_PASSWORD=admin",
            "-e", "ORG_ALIAS=kronos-dls-a", "-e", "ORG_NAME=KronOS DLS Org A",
            "-e", "ORG_DOMAIN=kronos-dls-a.example",
            "-e", f"ORG_MEMBER_IDS={new_user_id}",
            "curlimages/curl:latest", "sh", "/provision_keycloak_org.sh",
        ],
        capture_output=True, text=True,
    )
    print(provision_result.stdout)
    check(
        "provisioning script found the org ALREADY EXISTS (not created again) and only linked the new member",
        "already exists" in provision_result.stdout,
        provision_result.stdout.strip().splitlines()[1] if len(provision_result.stdout.strip().splitlines()) > 1 else "",
    )

    # --- 3. Real login as the brand-new user, real DLS isolation, zero new OpenSearch calls ---
    print("\n" + "=" * 10, "3. Real login + real DLS isolation for the brand-new member", "=" * 10)
    token_a3 = password_grant("user-a3-latecomer", "DlsUserA3#2026")
    claims_a3 = jose_jwt.get_unverified_claims(token_a3)
    print(f"user-a3-latecomer org_id = {claims_a3.get('org_id')}")
    check("brand-new user's REAL JWT carries the SAME flat org_id as the org's original member",
          claims_a3.get("org_id") == org_id_a, str(claims_a3.get("org_id")))

    result_a3 = search_as(token_a3, index_name)
    ids_a3 = {h["_id"] for h in result_a3["hits"]["hits"]}
    print(f"user-a3-latecomer sees: {ids_a3}")
    check(
        "brand-new member is correctly DLS-isolated to org A's doc -- with ZERO OpenSearch-side "
        "calls made for them (no new role, no new mapping, nothing past the MARKER in run_poc.sh)",
        ids_a3 == {"doc-org-a"}, str(ids_a3),
    )

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
