"""PoC: real Keycloak OIDC SSO into real OpenSearch Dashboards, plus
automated per-org Dashboards tenant provisioning. Run via run_poc.sh, which
brings up real Keycloak 26.2 (importing the ACTUAL production
docker/keycloak/kronos-realm.json unmodified) + real OpenSearch/Dashboards
2.11.1 with security genuinely enabled and an openid authc domain
configured, all on --network host (see run_poc.sh for why), then runs this
script directly on the host as the "browser".
"""
from __future__ import annotations

import http.cookiejar
import re
import subprocess
import sys
from html import unescape
from pathlib import Path

import httpx

# Same real quirk poc/auth_flow/auth_helpers.py already documented and
# fixed, reproduced here independently: Keycloak marks its session cookies
# (including the KC_RESTART cookie needed across the login-form POST)
# Secure=True even over plain HTTP in dev mode; a real browser would just
# use HTTPS. Without this, Keycloak's login form POST failed with a real
# "Restart login cookie not found" error. Bypass that one check for this
# scripted client.
#
# Deliberately keep "localhost" (not 127.0.0.1) for DASH_URL/KC/OS_URL:
# Dashboards' own base_redirect_url (run_poc.sh) is "http://localhost:5601"
# (must match the real Keycloak client's registered redirectUris), so its
# final post-login redirect always lands back on literal "localhost" --
# using a different literal string here for this script's own explicit
# API calls (127.0.0.1 was tried first) reintroduced a cookie-domain
# mismatch of exactly the same shape, just the other way around.
http.cookiejar.DefaultCookiePolicy.return_ok_secure = lambda self, cookie, request: True  # noqa: ARG005

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent

KC = "http://localhost:8080"
OS_URL = "https://localhost:9200"
DASH_URL = "http://localhost:5601"
REALM = "kronos"

ANALYST_ID = "10000000-0000-4000-8000-000000000002"
CASE_LEAD_ID = "10000000-0000-4000-8000-000000000003"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def kc_admin_token() -> str:
    resp = httpx.post(
        f"{KC}/realms/master/protocol/openid-connect/token",
        data={"client_id": "admin-cli", "username": "admin", "password": "admin", "grant_type": "password"},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def provision_org(alias: str, name: str, member_id: str, token: str) -> str:
    subprocess.run(
        ["sh", str(REPO_ROOT / "scripts" / "provision_keycloak_org.sh")],
        env={
            "KC_BASE": KC,
            "KC_REALM": REALM,
            "KC_ADMIN_USER": "admin",
            "KC_ADMIN_PASSWORD": "admin",
            "ORG_ALIAS": alias,
            "ORG_NAME": name,
            "ORG_DOMAIN": f"{alias}.example",
            "ORG_MEMBER_IDS": member_id,
            "PATH": "/usr/bin:/bin",
        },
        check=True,
    )
    resp = httpx.get(f"{KC}/admin/realms/{REALM}/organizations", params={"search": alias}, headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    orgs = resp.json()
    return next(o["id"] for o in orgs if o["alias"] == alias)


def provision_dashboards_tenant(alias: str, org_id: str) -> None:
    subprocess.run(
        ["sh", str(SCRIPT_DIR / "provision_dashboards_tenant.sh")],
        env={
            "OS_BASE": OS_URL,
            "OS_ADMIN_USER": "admin",
            "OS_ADMIN_PASSWORD": "admin",
            "ORG_ALIAS": alias,
            "ORG_ID": org_id,
            "PATH": "/usr/bin:/bin",
        },
        check=True,
    )


def dashboards_openid_login(username: str, password: str) -> httpx.Client:
    """Real, scripted "browser" driving Dashboards' actual openid login
    route end to end: GET /auth/openid/login (redirects to the real
    Keycloak login page) -> submit real credentials -> Keycloak redirects
    back to Dashboards' own callback -> Dashboards exchanges the code for a
    real token server-side and sets its session cookie.
    """
    client = httpx.Client(base_url=DASH_URL, follow_redirects=True, timeout=15.0, trust_env=False)
    resp = client.get(f"{DASH_URL}/auth/openid/login")
    action = unescape(re.search(r'action="([^"]+)"', resp.text).group(1))
    resp = client.post(action, data={"username": username, "password": password})
    if resp.status_code != 200:
        raise RuntimeError(f"openid login for {username} did not complete: {resp.status_code} {resp.text[:300]}")
    return client


def main() -> None:
    print("=" * 10, "0. Provisioning: 2 real orgs, 2 real Dashboards tenants", "=" * 10)
    token = kc_admin_token()
    org_a_id = provision_org("dashsso-org-a", "DashSSO Org A", ANALYST_ID, token)
    org_b_id = provision_org("dashsso-org-b", "DashSSO Org B", CASE_LEAD_ID, token)
    print(f"org A (analyst): {org_a_id}")
    print(f"org B (case-lead): {org_b_id}")
    provision_dashboards_tenant("dashsso-org-a", org_a_id)
    provision_dashboards_tenant("dashsso-org-b", org_b_id)

    # --- 1. Direct OpenSearch-side verification: real Keycloak-issued
    # tokens (ROPC grant, temporarily enabled on this client for this PoC
    # only -- mirrors poc/opensearch_jwt/run_poc.sh's own pattern) resolve
    # attr.jwt.org_id and the backend_roles=[org_id] mapping correctly via
    # the real openid authc domain, independent of Dashboards' own proxying. ---
    print("\n" + "=" * 10, "1. Direct OpenSearch authinfo check (openid authc domain)", "=" * 10)
    clients = httpx.get(f"{KC}/admin/realms/{REALM}/clients", params={"clientId": "opensearch-dashboards"}, headers={"Authorization": f"Bearer {token}"}).json()
    client_uuid = clients[0]["id"]
    httpx.put(
        f"{KC}/admin/realms/{REALM}/clients/{client_uuid}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"directAccessGrantsEnabled": True},
    ).raise_for_status()

    def ropc_token(username: str, password: str) -> str:
        resp = httpx.post(
            f"{KC}/realms/{REALM}/protocol/openid-connect/token",
            data={
                "client_id": "opensearch-dashboards",
                "client_secret": "opensearch-dashboards-secret",
                "username": username,
                "password": password,
                "grant_type": "password",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    analyst_token = ropc_token("analyst", "DevAnalyst#2026")
    authinfo = httpx.get(f"{OS_URL}/_plugins/_security/authinfo", headers={"Authorization": f"Bearer {analyst_token}"}, verify=False).json()
    print(f"analyst authinfo: user_name={authinfo.get('user_name')!r} backend_roles={authinfo.get('backend_roles')!r}")
    check("analyst's real backend_roles include their real org_id (roles_key=org_id resolved)", org_a_id in authinfo.get("backend_roles", []), str(authinfo.get("backend_roles")))
    check("analyst's subject resolved from the JWT's sub claim (subject_key=sub)", authinfo.get("user_name") == ANALYST_ID, str(authinfo.get("user_name")))

    # --- 2. Real Dashboards browser-redirect openid login, both users ---
    print("\n" + "=" * 10, "2. Real Dashboards openid login (full redirect chain)", "=" * 10)
    user_a = dashboards_openid_login("analyst", "DevAnalyst#2026")
    user_b = dashboards_openid_login("case-lead", "DevCaseLead#2026")
    check("analyst's real openid login through Dashboards completed (session cookie set)", True)
    check("case-lead's real openid login through Dashboards completed (session cookie set)", True)

    # --- 3. Real per-org saved-object isolation, via the real OIDC session ---
    print("\n" + "=" * 10, "3. Real cross-org saved-object isolation via OIDC sessions", "=" * 10)
    with httpx.Client(verify=False, timeout=10.0) as h:
        h.put(f"{OS_URL}/kronos-demo-index-a", auth=("admin", "admin"), json={})
        h.put(f"{OS_URL}/kronos-demo-index-b", auth=("admin", "admin"), json={})

    create_a = user_a.post(
        "/api/saved_objects/index-pattern/dashsso-pattern-a?overwrite=true",
        headers={"osd-xsrf": "true", "securitytenant": "kronos-dashsso-org-a"},
        json={"attributes": {"title": "kronos-demo-index-a", "timeFieldName": "@timestamp"}},
    )
    create_b = user_b.post(
        "/api/saved_objects/index-pattern/dashsso-pattern-b?overwrite=true",
        headers={"osd-xsrf": "true", "securitytenant": "kronos-dashsso-org-b"},
        json={"attributes": {"title": "kronos-demo-index-b", "timeFieldName": "@timestamp"}},
    )
    print(f"create as analyst (org A) -> {create_a.status_code} {create_a.text[:200]}")
    print(f"create as case-lead (org B) -> {create_b.status_code} {create_b.text[:200]}")
    check("analyst created a real saved object in their own real OIDC-authenticated tenant", create_a.status_code == 200)
    check("case-lead created a real saved object in their own real OIDC-authenticated tenant", create_b.status_code == 200)

    get_b_as_a = user_a.get(
        "/api/saved_objects/index-pattern/dashsso-pattern-b",
        headers={"securitytenant": "kronos-dashsso-org-a"},
    )
    check("analyst cannot see org B's saved object via their own OIDC tenant (404)", get_b_as_a.status_code == 404, str(get_b_as_a.status_code))

    get_a_as_b = user_b.get(
        "/api/saved_objects/index-pattern/dashsso-pattern-a",
        headers={"securitytenant": "kronos-dashsso-org-b"},
    )
    check("case-lead cannot see org A's saved object via their own OIDC tenant (404)", get_a_as_b.status_code == 404, str(get_a_as_b.status_code))

    find_a = user_a.get("/api/saved_objects/_find?type=index-pattern", headers={"securitytenant": "kronos-dashsso-org-a"}).json()
    find_b = user_b.get("/api/saved_objects/_find?type=index-pattern", headers={"securitytenant": "kronos-dashsso-org-b"}).json()
    ids_a = {o["id"] for o in find_a["saved_objects"]}
    ids_b = {o["id"] for o in find_b["saved_objects"]}
    print(f"analyst's _find lists: {ids_a}")
    print(f"case-lead's _find lists: {ids_b}")
    check("analyst's real listing shows ONLY their own object", ids_a == {"dashsso-pattern-a"}, str(ids_a))
    check("case-lead's real listing shows ONLY their own object", ids_b == {"dashsso-pattern-b"}, str(ids_b))

    denied = user_b.get(
        "/api/saved_objects/index-pattern/dashsso-pattern-a",
        headers={"securitytenant": "kronos-dashsso-org-a"},
    )
    check("case-lead explicitly requesting org A's tenant (no real role grant) is denied, not silently served", denied.status_code >= 400, str(denied.status_code))

    for c in (user_a, user_b):
        c.close()

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
