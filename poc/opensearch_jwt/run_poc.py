"""PoC (new construction, per CLAUDE.md Section F.4 -- this repo has ZERO
OpenSearch security-plugin/JWT wiring today, security is disabled in dev):
build and verify real JWT authentication + real DLS tenant isolation
against a real OpenSearch 2.11.1 with the security plugin genuinely
enabled, using real Keycloak-issued tokens and the real, unmodified
src/adapter/opensearch/client.py (OpenSearchClient.ensure_tenant_role,
ensure_index_template, bulk_index).

Prereqs (see README.md "How to run" for the full one-time bootstrap this
script assumes has already been done — the security-config REST calls
that require an opensearch.yml flag not settable via this script alone):
  - kronos-poc-osjwt-opensearch: OpenSearch 2.11.1, security enabled,
    'plugins.security.unsupported.restapi.allow_securityconfig_modification:
    true' added to opensearch.yml (see README), JWT auth domain configured
    per jwt_auth_domain.json (RAW base64 signing_key -- see README for why).
  - kronos-poc-osjwt-keycloak: Keycloak 26.2, kronos realm imported, one
    org with 'analyst' as a member, kronos-frontend direct grants enabled.

Run: source ~/venv/bin/activate && python poc/opensearch_jwt/run_poc.py
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402

OS_URL = "https://localhost:19800"
KC_URL = "http://localhost:18083"
ORG_ID = os.environ.get("OSJWT_ORG_ID", "")
ANALYST_SUB = "10000000-0000-4000-8000-000000000002"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def get_token() -> str:
    resp = httpx.post(
        f"{KC_URL}/realms/kronos/protocol/openid-connect/token",
        data={
            "client_id": "kronos-frontend",
            "username": "analyst",
            "password": "DevAnalyst#2026",
            "grant_type": "password",
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def decode(token: str) -> dict:
    parts = token.split(".")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


async def main() -> None:
    token = get_token()
    claims = decode(token)
    org_id = ORG_ID or next(iter(claims.get("organization", {}).values()), {}).get("id")
    print(f"real token: sub={claims['sub']} roles={claims['roles']} org_id={org_id}")
    check("real token carries the org_id needed for this PoC", bool(org_id))

    # --- 1. Real JWT authentication to OpenSearch ---
    with httpx.Client(verify=False) as h:
        resp = h.get(f"{OS_URL}/_plugins/_security/authinfo", headers={"Authorization": f"Bearer {token}"})
    print(f"\nauthinfo -> {resp.status_code} {resp.text[:300]}")
    check("real JWT authenticates to real OpenSearch (not 401)", resp.status_code == 200)
    info = resp.json() if resp.status_code == 200 else {}
    check("backend_roles correctly extracted from the flat 'roles' claim", info.get("backend_roles") == ["analyst"])
    check("nested 'organization' claim IS exposed as a custom attribute name", "attr.jwt.organization" in info.get("custom_attribute_names", []))

    # --- 2. Real OpenSearchClient.ensure_tenant_role() against real, enabled security ---
    client = OpenSearchClient(hosts=[{"host": "localhost", "port": 19800}], http_auth=("admin", "admin"), use_ssl=True, verify_certs=False)
    try:
        await client.ensure_tenant_role(org_id=org_id, org_alias="osjwt")
        check("real ensure_tenant_role() succeeds with security genuinely enabled (400 in dev-disabled mode -- see poc/opensearch/README.md)", True)
    except Exception as exc:  # noqa: BLE001
        check("ensure_tenant_role() succeeds", False, f"{type(exc).__name__}: {exc}")

    with httpx.Client(verify=False, auth=("admin", "admin")) as h:
        role = h.get(f"{OS_URL}/_plugins/_security/api/roles/kronos-tenant-{org_id}").json()
    dls = role.get(f"kronos-tenant-{org_id}", {}).get("index_permissions", [{}])[0].get("dls", "")
    check("the real role's DLS filter is scoped to this exact org_id", org_id in dls, dls)

    # --- 3. THE GAP: no role mapping exists yet -- confirm, then complete it manually ---
    with httpx.Client(verify=False) as h:
        resp = h.get(f"{OS_URL}/_plugins/_security/authinfo", headers={"Authorization": f"Bearer {token}"})
    roles_before = resp.json().get("roles", [])
    check(
        "GAP CONFIRMED: ensure_tenant_role() alone does not grant the role to any user "
        "(no rolesmapping call exists in src/) -- user's effective roles don't include it yet",
        f"kronos-tenant-{org_id}" not in roles_before,
        str(roles_before),
    )

    with httpx.Client(verify=False, auth=("admin", "admin")) as h:
        h.put(
            f"{OS_URL}/_plugins/_security/api/rolesmapping/kronos-tenant-{org_id}",
            json={"users": [ANALYST_SUB]},
        )

    with httpx.Client(verify=False) as h:
        resp = h.get(f"{OS_URL}/_plugins/_security/authinfo", headers={"Authorization": f"Bearer {token}"})
    roles_after = resp.json().get("roles", [])
    check("after manually completing the missing mapping, the user's roles DO include the tenant role", f"kronos-tenant-{org_id}" in roles_after, str(roles_after))

    # --- 4. Real end-to-end DLS enforcement proof ---
    index_name = f"kronos-osjwt-case-x-202607"
    with httpx.Client(verify=False, auth=("admin", "admin")) as h:
        h.delete(f"{OS_URL}/{index_name}")
    await client.ensure_index_template()  # the poc/full_pipeline/ fix -- without this, DLS term queries silently match nothing
    docs = [
        (index_name, "doc-mine", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "belongs to my org",
            "kronos": {"org_id": org_id, "case_id": "x", "evidence_id": "e1", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
        (index_name, "doc-other-org", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "belongs to a DIFFERENT org",
            "kronos": {"org_id": "ffffffff-0000-0000-0000-000000000000", "case_id": "x", "evidence_id": "e2", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
    ]
    n = await client.bulk_index(docs)
    await client._client.indices.refresh(index=index_name)
    check("both real docs indexed via the real bulk_index()", n == 2)

    with httpx.Client(verify=False) as h:
        search = h.get(f"{OS_URL}/{index_name}/_search", headers={"Authorization": f"Bearer {token}"}).json()
    hits = search["hits"]["hits"]
    ids = {h["_id"] for h in hits}
    print(f"\nreal DLS-scoped search as analyst -> {search['hits']['total']} hit(s): {ids}")
    check("DLS correctly returns ONLY the user's own-org document", ids == {"doc-mine"}, str(ids))

    await client.close()

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


if __name__ == "__main__":
    asyncio.run(main())
