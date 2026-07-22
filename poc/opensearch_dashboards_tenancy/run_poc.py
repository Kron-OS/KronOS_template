"""PoC: OpenSearch Dashboards multi-tenancy (saved-object isolation) --
new construction. This repo runs Dashboards with
DISABLE_SECURITY_DASHBOARDS_PLUGIN=true in dev; this concept has never been
built or tested here. It is a DIFFERENT thing from DLS (poc/opensearch_jwt/,
poc/keycloak_opensearch_dls/): DLS restricts which *documents* a query
returns; Dashboards tenancy isolates *saved objects* (index-patterns,
visualizations, dashboards themselves) per org, per
docs/subsystems/multi-tenancy.md's "One OS Dashboards tenant per org" line
and the docs.opensearch.org multi-tenancy-config page.

Run via run_poc.sh, which brings up real OpenSearch + Dashboards with
security genuinely enabled, two real per-org tenants (kronos-org-a,
kronos-org-b), two roles each granted kibana_all_write on only their own
tenant, and two internal (basic-auth) users mapped to them.
"""
from __future__ import annotations

import os
import sys

import httpx

OS_PORT = os.environ.get("KCDASH_OS_PORT", "19950")
DASH_PORT = os.environ.get("KCDASH_DASH_PORT", "15601")
OS_URL = f"https://localhost:{OS_PORT}"
DASH_URL = f"http://localhost:{DASH_PORT}"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def dash_login(username: str, password: str) -> httpx.Client:
    client = httpx.Client(base_url=DASH_URL, timeout=10.0)
    resp = client.post(
        "/auth/login",
        headers={"osd-xsrf": "true"},
        json={"username": username, "password": password},
    )
    resp.raise_for_status()
    return client


def main() -> None:
    # --- 1. Real logins, real per-user tenant visibility ---
    print("=" * 10, "1. Real Dashboards logins + tenant visibility", "=" * 10)
    admin = dash_login("admin", "admin")
    user_a = dash_login("dash-user-a", "DashUserA#2026")
    user_b = dash_login("dash-user-b", "DashUserB#2026")

    resp_a = httpx.post(f"{DASH_URL}/auth/login", headers={"osd-xsrf": "true"},
                         json={"username": "dash-user-a", "password": "DashUserA#2026"})
    resp_b = httpx.post(f"{DASH_URL}/auth/login", headers={"osd-xsrf": "true"},
                         json={"username": "dash-user-b", "password": "DashUserB#2026"})
    tenants_a = resp_a.json()["tenants"]
    tenants_b = resp_b.json()["tenants"]
    print(f"user-a tenants: {tenants_a}")
    print(f"user-b tenants: {tenants_b}")
    check("user-a's real tenant list includes their own org tenant", "kronos-org-a" in tenants_a)
    check("user-a's real tenant list does NOT include org B's tenant", "kronos-org-b" not in tenants_a)
    check("user-b's real tenant list includes their own org tenant", "kronos-org-b" in tenants_b)
    check("user-b's real tenant list does NOT include org A's tenant", "kronos-org-a" not in tenants_b)

    # --- 2. Create a real index + real saved object (index-pattern) per org ---
    print("\n" + "=" * 10, "2. Real saved objects created per-org, in their own tenant", "=" * 10)
    with httpx.Client(verify=False, timeout=10.0) as h:
        h.put(f"{OS_URL}/kronos-demo-index-a", auth=("admin", "admin"), json={})
        h.put(f"{OS_URL}/kronos-demo-index-b", auth=("admin", "admin"), json={})

    create_a = user_a.post(
        "/api/saved_objects/index-pattern/kronos-demo-pattern-a?overwrite=true",
        headers={"osd-xsrf": "true", "securitytenant": "kronos-org-a"},
        json={"attributes": {"title": "kronos-demo-index-a", "timeFieldName": "@timestamp"}},
    )
    create_b = user_b.post(
        "/api/saved_objects/index-pattern/kronos-demo-pattern-b?overwrite=true",
        headers={"osd-xsrf": "true", "securitytenant": "kronos-org-b"},
        json={"attributes": {"title": "kronos-demo-index-b", "timeFieldName": "@timestamp"}},
    )
    print(f"create as user-a -> {create_a.status_code}")
    print(f"create as user-b -> {create_b.status_code}")
    check("user-a's real saved object created in their own tenant", create_a.status_code == 200)
    check("user-b's real saved object created in their own tenant", create_b.status_code == 200)

    # --- 3. THE actual isolation test: direct GET and _find listing, both directions ---
    print("\n" + "=" * 10, "3. Real cross-org saved-object isolation", "=" * 10)
    get_b_as_a = user_a.get(
        "/api/saved_objects/index-pattern/kronos-demo-pattern-b",
        headers={"securitytenant": "kronos-org-a"},
    )
    print(f"user-a GETs org B's object via their OWN tenant -> {get_b_as_a.status_code}")
    check("user-a cannot see org B's saved object (404, not leaked)", get_b_as_a.status_code == 404)

    get_a_as_b = user_b.get(
        "/api/saved_objects/index-pattern/kronos-demo-pattern-a",
        headers={"securitytenant": "kronos-org-b"},
    )
    print(f"user-b GETs org A's object via their OWN tenant -> {get_a_as_b.status_code}")
    check("user-b cannot see org A's saved object (404, not leaked)", get_a_as_b.status_code == 404)

    find_a = user_a.get("/api/saved_objects/_find?type=index-pattern", headers={"securitytenant": "kronos-org-a"}).json()
    find_b = user_b.get("/api/saved_objects/_find?type=index-pattern", headers={"securitytenant": "kronos-org-b"}).json()
    ids_a = {o["id"] for o in find_a["saved_objects"]}
    ids_b = {o["id"] for o in find_b["saved_objects"]}
    print(f"user-a's _find lists: {ids_a}")
    print(f"user-b's _find lists: {ids_b}")
    check("user-a's saved-object listing shows ONLY their own object", ids_a == {"kronos-demo-pattern-a"}, str(ids_a))
    check("user-b's saved-object listing shows ONLY their own object", ids_b == {"kronos-demo-pattern-b"}, str(ids_b))

    denied = user_b.get(
        "/api/saved_objects/index-pattern/kronos-demo-pattern-a",
        headers={"securitytenant": "kronos-org-a"},  # explicitly requesting a tenant user-b has no grant on
    )
    print(f"user-b explicitly requests org A's tenant (no grant) -> {denied.status_code}")
    check("requesting a tenant with no role grant is denied, not silently served", denied.status_code >= 400)

    for c in (admin, user_a, user_b):
        c.close()

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
