"""PoC: does the combined `dashboard_roles` claim (kronos-dashboard-roles
client scope, two multivalued mappers sharing one claim name) let a single
OpenSearch authc-domain roles_key satisfy BOTH the per-org Dashboards
tenant rolesmapping (backend_roles=[org_id]) AND the DLS-granting
kronos-generic-tenant rolesmapping (backend_roles=[realm role names]) at
once -- and does real cross-org document isolation still hold?

Run via run_poc.sh, which brings up real Keycloak 26.2 + real OpenSearch
2.11.1 with the combined-claim realm/security config, seeds one real
document per org, then runs this script as the "browser" (password grant
against the opensearch-dashboards-poc client -- no mocks, real Keycloak
token issuance, real OpenSearch security plugin evaluation).
"""
from __future__ import annotations

import base64
import json
import os
import sys

import httpx

KC_PORT = os.environ["OSDDLS_KC_PORT"]
OS_PORT = os.environ["OSDDLS_OS_PORT"]
ORG_A_ID = os.environ["ORG_A_ID"]
ORG_B_ID = os.environ["ORG_B_ID"]

KC = f"http://localhost:{KC_PORT}"
OS_URL = f"https://localhost:{OS_PORT}"
REALM = "kronos"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def password_grant(client_id: str, client_secret: str | None, username: str, password: str) -> dict:
    data = {
        "client_id": client_id,
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid",
    }
    if client_secret:
        data["client_secret"] = client_secret
    resp = httpx.post(f"{KC}/realms/{REALM}/protocol/openid-connect/token", data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()


def opensearch_authinfo(access_token: str) -> dict:
    resp = httpx.get(
        f"{OS_URL}/_plugins/_security/authinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def opensearch_search(access_token: str, index: str) -> dict:
    resp = httpx.post(
        f"{OS_URL}/{index}/_search",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"query": {"match_all": {}}},
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    print(f"Org A id: {ORG_A_ID}")
    print(f"Org B id: {ORG_B_ID}")

    # --- User A1 (analyst, org A) via the Dashboards-shaped client ---
    tokens_a = password_grant("opensearch-dashboards-poc", "opensearch-dashboards-poc-secret", "user-a1", "DlsUserA1#2026")
    claims_a = decode_jwt_payload(tokens_a["access_token"])
    dash_roles_a = set(claims_a.get("dashboard_roles", []))
    print(f"user-a1 dashboard_roles claim: {sorted(dash_roles_a)}")
    check("user-a1's dashboard_roles contains their real org_id", ORG_A_ID in dash_roles_a, str(dash_roles_a))
    check("user-a1's dashboard_roles ALSO contains their realm role 'analyst'", "analyst" in dash_roles_a, str(dash_roles_a))
    check("user-a1's dashboard_roles has exactly 2 elements (no duplicates/loss)", len(dash_roles_a) == 2, str(dash_roles_a))
    check("org_id claim (separate, DLS-templated) is unaffected/still present", claims_a.get("org_id") == ORG_A_ID, claims_a.get("org_id"))

    authinfo_a = opensearch_authinfo(tokens_a["access_token"])
    print(f"user-a1 OpenSearch authinfo backend_roles: {authinfo_a.get('backend_roles')}")
    print(f"user-a1 OpenSearch authinfo roles: {authinfo_a.get('roles')}")
    check("user-a1 granted kronos-generic-tenant (DLS/read role)", "kronos-generic-tenant" in authinfo_a.get("roles", []), str(authinfo_a.get("roles")))
    check("user-a1 granted kronos-dash-kronos-osddls-a (their OWN org's tenant role)", "kronos-dash-kronos-osddls-a" in authinfo_a.get("roles", []), str(authinfo_a.get("roles")))
    check("user-a1 NOT granted org B's tenant role", "kronos-dash-kronos-osddls-b" not in authinfo_a.get("roles", []), str(authinfo_a.get("roles")))

    search_a = opensearch_search(tokens_a["access_token"], "kronos-osddls-test-case-*")
    hits_a = search_a.get("hits", {}).get("hits", [])
    messages_a = [h["_source"]["message"] for h in hits_a]
    print(f"user-a1 search results: {messages_a}")
    check("user-a1 search returns EXACTLY 1 doc (their own org's, DLS-filtered)", len(hits_a) == 1, str(messages_a))
    check("user-a1 sees ONLY org A's document, not org B's", messages_a == ["org A secret event"], str(messages_a))

    # --- User B1 (case-lead, org B) -- different role name, different org ---
    tokens_b = password_grant("opensearch-dashboards-poc", "opensearch-dashboards-poc-secret", "user-b1", "DlsUserB1#2026")
    claims_b = decode_jwt_payload(tokens_b["access_token"])
    dash_roles_b = set(claims_b.get("dashboard_roles", []))
    print(f"user-b1 dashboard_roles claim: {sorted(dash_roles_b)}")
    check("user-b1's dashboard_roles contains their real org_id", ORG_B_ID in dash_roles_b, str(dash_roles_b))
    check("user-b1's dashboard_roles ALSO contains their realm role 'case-lead' (different role than user-a1)", "case-lead" in dash_roles_b, str(dash_roles_b))

    authinfo_b = opensearch_authinfo(tokens_b["access_token"])
    print(f"user-b1 OpenSearch authinfo roles: {authinfo_b.get('roles')}")
    check("user-b1 granted kronos-generic-tenant via the 'case-lead' element (not just 'analyst')", "kronos-generic-tenant" in authinfo_b.get("roles", []), str(authinfo_b.get("roles")))
    check("user-b1 granted kronos-dash-kronos-osddls-b (their OWN org's tenant role)", "kronos-dash-kronos-osddls-b" in authinfo_b.get("roles", []), str(authinfo_b.get("roles")))
    check("user-b1 NOT granted org A's tenant role", "kronos-dash-kronos-osddls-a" not in authinfo_b.get("roles", []), str(authinfo_b.get("roles")))

    search_b = opensearch_search(tokens_b["access_token"], "kronos-osddls-test-case-*")
    hits_b = search_b.get("hits", {}).get("hits", [])
    messages_b = [h["_source"]["message"] for h in hits_b]
    print(f"user-b1 search results: {messages_b}")
    check("user-b1 search returns EXACTLY 1 doc (their own org's)", len(hits_b) == 1, str(messages_b))
    check("user-b1 sees ONLY org B's document, not org A's", messages_b == ["org B secret event"], str(messages_b))

    # --- Least-privilege scoping check: kronos-frontend (SPA client) must NOT get dashboard_roles at all ---
    tokens_spa = password_grant("kronos-frontend", None, "user-a1", "DlsUserA1#2026")
    claims_spa = decode_jwt_payload(tokens_spa["access_token"])
    check(
        "kronos-frontend's own token has NO dashboard_roles claim (scope correctly isolated to the Dashboards client only)",
        "dashboard_roles" not in claims_spa,
        str(list(claims_spa.keys())),
    )
    check("kronos-frontend's token still has the normal flat 'roles' claim, unaffected", claims_spa.get("roles") == ["analyst"], claims_spa.get("roles"))

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
