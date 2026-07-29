"""PoC: A3 GATE -- can a real KronOS tenant analyst reach OpenSearch Security
Analytics / Alerting data or actions at all?

Root question (docs/NEXTGEN_SOC_ROADMAP.md M0/A3): KronOS's tenant isolation
is Document-Level Security templated on kronos.org_id, applied to kronos-*
indices via the kronos-generic-tenant role. Security Analytics detectors are
cluster-level objects and findings live in .opensearch-sap-* system indices
-- does DLS (or ANY mechanism) extend to them, and could one tenant read
another tenant's findings/detectors?

This script authenticates as a REAL tenant user (case-lead, org kronos-dev)
through the REAL Keycloak OIDC flow used by real OpenSearch Dashboards SSO
logins today -- the `opensearch-dashboards` confidential client, which is
the one that actually emits the combined `dashboard_roles` claim
(org_id + role name) that `kronos-generic-tenant`'s rolesmapping and the
per-org Dashboards tenant rolesmapping both key on. This is NOT a synthetic
JWT and NOT the jwt_auth_domain (which is configured but http_enabled:false
in this cluster -- confirmed by reading the real securityconfig). It is the
exact login path a real analyst's browser takes.

Every check below is a REAL HTTP call against the REAL, live OpenSearch
2.11.1 cluster this repo's docker-compose.dev.yml runs -- no mocks.

Run: source ~/venv/bin/activate && python poc/security_analytics_tenant_isolation/run_poc.py
Requires: the real dev stack up (kronos.local), including a currently-valid
step-ca leaf cert (see README.md -- this cert has a 24h TTL and needs
`docker compose -f docker/docker-compose.dev.yml up -d tls-init && docker
restart docker-nginx-1` if expired).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
import auth_helpers as ah  # noqa: E402

OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def decode_jwt(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def real_dashboards_login(username: str, password: str) -> str:
    """Real authorization-code+PKCE login against the REAL
    `opensearch-dashboards` confidential client (docker/keycloak/kronos-realm.json)
    -- the client real Dashboards SSO logins actually use, confirmed to be
    the one whose token carries the `dashboard_roles` claim
    (kronos-generic-tenant's rolesmapping key). auth_helpers.real_browser_login
    doesn't support a confidential client's secret at the token-exchange
    step, so the exchange is done directly here (init still reuses
    auth_helpers' real PKCE + login-form submission -- no auth logic
    reinvented)."""
    ah.KC = "https://kronos.local:8443"
    ah.CLIENT_ID = "opensearch-dashboards"
    ah.REDIRECT_URI = "https://kronos.local:5602/auth/openid/login"
    ah.trust_dev_stack_step_ca()

    client = httpx.Client(follow_redirects=True, verify=ah.CA_BUNDLE)
    verifier, challenge = ah.new_pkce_pair()
    resp = ah.start_auth(client, (verifier, challenge), state="a3-gate")
    resp = ah.submit_username_password(client, resp, username, password)

    loc = resp.headers.get("location")
    while loc and ah.REDIRECT_URI not in loc:
        resp = client.get(loc, follow_redirects=False)
        loc = resp.headers.get("location")
    if not loc:
        raise RuntimeError(f"no redirect Location found; last response {resp.status_code}")
    code = parse_qs(urlparse(loc).query).get("code", [None])[0]
    if not code:
        raise RuntimeError(f"no ?code= in redirect: {loc}")

    token_resp = httpx.post(
        f"{ah.KC}/realms/{ah.REALM}/protocol/openid-connect/token",
        verify=ah.CA_BUNDLE,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": ah.REDIRECT_URI,
            "client_id": ah.CLIENT_ID,
            "client_secret": "opensearch-dashboards-secret",
            "code_verifier": verifier,
        },
    )
    token_resp.raise_for_status()
    return token_resp.json()["access_token"]


def os_get(token: str, path: str) -> httpx.Response:
    return httpx.get(f"{OS_URL}{path}", headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=15)


def os_post(token: str, path: str, body: dict) -> httpx.Response:
    return httpx.post(
        f"{OS_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        json=body,
        verify=False,
        timeout=15,
    )


def main() -> None:
    print("=== 1. Real Dashboards SSO login as a real tenant analyst (case-lead, org kronos-dev) ===")
    token = real_dashboards_login("case-lead", "DevCaseLead#2026")
    claims = decode_jwt(token)
    check("real token issued", bool(token))
    check(
        "token carries the real combined dashboard_roles claim (org_id + role)",
        isinstance(claims.get("dashboard_roles"), list) and len(claims["dashboard_roles"]) >= 2,
        claims.get("dashboard_roles"),
    )

    print("\n=== 2. Confirm real role resolution via OpenSearch's own authinfo ===")
    authinfo = os_get(token, "/_plugins/_security/authinfo").json()
    roles = authinfo.get("roles", [])
    check(
        "resolves to kronos-generic-tenant (the DLS-granting role) and a Dashboards tenant role, nothing SA/alerting-related",
        "kronos-generic-tenant" in roles and not any("security_analytics" in r or "alerting" in r for r in roles),
        roles,
    )

    print("\n=== 3. Sanity: this real tenant session CAN read kronos-* (DLS working as already verified in prior PoCs) ===")
    resp = os_post(token, "/kronos-*/_search?size=0", {"query": {"match_all": {}}})
    check("kronos-* search succeeds for a real tenant session", resp.status_code == 200, f"status={resp.status_code}")

    print("\n=== 4. Can this real tenant session list/search Security Analytics detectors? ===")
    resp = os_post(token, "/_plugins/_security_analytics/detectors/_search", {"query": {"match_all": {}}})
    check(
        "detector search is DENIED (403) for a plain tenant role -- no cluster permission granted",
        resp.status_code == 403,
        f"status={resp.status_code} body={resp.text[:200]}",
    )

    print("\n=== 5. Can this real tenant session search alerting monitors (the underlying findings/alerts engine)? ===")
    resp = os_post(token, "/_plugins/_alerting/monitors/_search", {"query": {"match_all": {}}})
    check(
        "alerting monitor search is DENIED (403) -- separate plugin, also no permission granted",
        resp.status_code == 403,
        f"status={resp.status_code} body={resp.text[:200]}",
    )

    print("\n=== 6. Can this real tenant session read the .opensearch-sap-* system indices DIRECTLY (bypassing the plugin API layer)? ===")
    resp = os_get(token, "/.opensearch-sap-pre-packaged-rules-config/_search?size=1")
    check(
        "direct raw-index read is DENIED (403) -- kronos-generic-tenant's index_permissions cover ONLY kronos-*",
        resp.status_code == 403,
        f"status={resp.status_code} body={resp.text[:200]}",
    )

    print("\n=== 7. As admin: enumerate OpenSearch's OWN built-in SA/alerting roles and confirm none are mapped to any KronOS tenant role ===")
    roles_resp = httpx.get(f"{OS_URL}/_plugins/_security/api/roles", auth=OS_ADMIN, verify=False, timeout=15).json()
    sa_alerting_roles = {
        name: role.get("cluster_permissions", [])
        for name, role in roles_resp.items()
        if any("securityanalytics" in p or "alerting" in p for p in role.get("cluster_permissions", []))
    }
    check(
        "OpenSearch ships dedicated SA/alerting RBAC roles (cluster-action-level, NOT document-level DLS)",
        len(sa_alerting_roles) > 0,
        sorted(sa_alerting_roles.keys()),
    )

    unmapped_ok = True
    mapped_findings = []
    for role_name in sa_alerting_roles:
        mapping_resp = httpx.get(
            f"{OS_URL}/_plugins/_security/api/rolesmapping/{role_name}", auth=OS_ADMIN, verify=False, timeout=15
        )
        if mapping_resp.status_code == 200:
            mapping = mapping_resp.json().get(role_name, {})
            backend_roles = mapping.get("backend_roles", [])
            tenant_role_names = {"org-admin", "case-lead", "analyst", "read-only"}
            if tenant_role_names & set(backend_roles):
                unmapped_ok = False
                mapped_findings.append((role_name, backend_roles))
    check(
        "NONE of OpenSearch's SA/alerting roles are currently mapped to any KronOS tenant backend_role "
        "(if one ever is, that user sees EVERY org's detectors/findings cluster-wide -- these roles have "
        "no DLS/per-tenant scoping mechanism at all)",
        unmapped_ok,
        mapped_findings if mapped_findings else "confirmed unmapped",
    )

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
