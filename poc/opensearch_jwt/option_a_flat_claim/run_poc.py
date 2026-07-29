"""PoC: does OpenSearch's ${attr.jwt.X} DLS templating work for a FLAT
scalar custom JWT claim, the way it demonstrably does NOT for the nested
"organization" claim (see ../README.md result #2)?

This is deliberately Keycloak-free (per the plan: "verify this works at
all... before touching Keycloak") -- JWTs are hand-signed with a throwaway
RSA key so the claim shape can be controlled directly: a flat top-level
"org_id" string, not the nested Keycloak Organizations shape.

If this works, it validates a fundamentally simpler production design than
today's ensure_tenant_role(): ONE static OpenSearch role with a templated
DLS filter, mapped ONCE to a broad backend_role -- no per-org role
creation, no per-user role-mapping calls, ever. New orgs and new org
members would need zero OpenSearch-side provisioning.

Run: source ~/venv/bin/activate && python poc/opensearch_jwt/option_a_flat_claim/run_poc.py
(OpenSearch from run_poc.sh must already be up with the JWT authc domain
configured against this script's own throwaway test key.)
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import httpx  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402

OS_URL = "https://localhost:19900"
PRIVATE_KEY_PATH = Path(__file__).parent / "test_key.pem"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def mint_token(sub: str, org_id: str) -> str:
    private_key = PRIVATE_KEY_PATH.read_text()
    claims = {
        "sub": sub,
        "iss": "kronos-poc-test-issuer",
        "aud": "kronos-backend",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "roles": ["analyst"],
        "org_id": org_id,  # flat scalar claim -- the thing under test
    }
    return jose_jwt.encode(claims, private_key, algorithm="RS256")


def search_as(token: str, index: str) -> dict:
    with httpx.Client(verify=False) as h:
        resp = h.get(f"{OS_URL}/{index}/_search", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json()


async def main() -> None:
    token_a = mint_token("user-a-sub", "org-aaaa-1111")
    token_b = mint_token("user-b-sub", "org-bbbb-2222")
    token_a2 = mint_token("user-a2-sub", "org-aaaa-1111")  # second, never-provisioned member of org A

    # --- 1. Real JWT authentication + attribute exposure check ---
    with httpx.Client(verify=False) as h:
        resp = h.get(f"{OS_URL}/_plugins/_security/authinfo", headers={"Authorization": f"Bearer {token_a}"})
    print(f"authinfo (user A) -> {resp.status_code} {resp.text[:300]}")
    check("real hand-signed JWT authenticates to real OpenSearch", resp.status_code == 200)
    info = resp.json() if resp.status_code == 200 else {}
    check("flat 'org_id' claim IS exposed as a custom attribute", "attr.jwt.org_id" in info.get("custom_attribute_names", []))

    # --- 2. Real docs via the real OpenSearchClient ---
    client = OpenSearchClient(hosts=[{"host": "localhost", "port": 19900}], http_auth=("admin", "admin"), use_ssl=True, verify_certs=False)
    await client.ensure_index_template()
    index_name = "kronos-shared-case-x-202607"
    docs = [
        (index_name, "doc-org-a", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "belongs to org A",
            "kronos": {"org_id": "org-aaaa-1111", "case_id": "x", "evidence_id": "e1", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
        (index_name, "doc-org-b", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "belongs to org B",
            "kronos": {"org_id": "org-bbbb-2222", "case_id": "x", "evidence_id": "e2", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
    ]
    n = await client.bulk_index(docs)
    await client._client.indices.refresh(index=index_name)
    check("both real docs indexed via the real bulk_index()", n == 2)
    await client.close()

    # --- 3. THE key test: ONE role, ONE mapping, THREE users, zero per-org/per-user backend calls ---
    result_a = search_as(token_a, index_name)
    ids_a = {h["_id"] for h in result_a["hits"]["hits"]}
    print(f"\nuser A (org-aaaa-1111) sees: {ids_a}")
    check("user A sees ONLY org A's doc", ids_a == {"doc-org-a"}, str(ids_a))

    result_b = search_as(token_b, index_name)
    ids_b = {h["_id"] for h in result_b["hits"]["hits"]}
    print(f"user B (org-bbbb-2222) sees: {ids_b}")
    check("user B sees ONLY org B's doc", ids_b == {"doc-org-b"}, str(ids_b))

    result_a2 = search_as(token_a2, index_name)
    ids_a2 = {h["_id"] for h in result_a2["hits"]["hits"]}
    print(f"user A2 (org-aaaa-1111, NEVER individually provisioned) sees: {ids_a2}")
    check(
        "a brand-new, never-provisioned second member of org A is ALSO correctly isolated "
        "-- with zero new OpenSearch-side backend calls (no new role, no new mapping)",
        ids_a2 == {"doc-org-a"},
        str(ids_a2),
    )

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


if __name__ == "__main__":
    asyncio.run(main())
