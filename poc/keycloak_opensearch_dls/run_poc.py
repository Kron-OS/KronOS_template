"""Step 3: real Keycloak 26.2 + real OpenSearch 2.11.1 -- does the flat
org_id claim (a real user attribute, mapped by a real
oidc-usermodel-attribute-mapper) actually flow through a real password-grant
login and drive real DLS isolation across two real Organizations?

Follow-up to ../opensearch_jwt/option_a_flat_claim/ (Keycloak-free, hand-signed
JWTs) and ../opensearch_jwt/option_a_flat_claim/keycloak_mapper_research.md
(source-verified design). This is the first time this flat-claim design is
tested against a REAL Keycloak token instead of a hand-signed one.

Run via run_poc.sh (which starts real Keycloak + OpenSearch, provisions two
real Organizations via the step-3-extended provision_keycloak_org.sh, and
configures OpenSearch's JWT authc + one generic DLS role).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import asyncio  # noqa: E402

import httpx  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402

KC_PORT = os.environ.get("KCOSDLS_KC_PORT", "18084")
OS_PORT = os.environ.get("KCOSDLS_OS_PORT", "19920")
KC_BASE = f"http://localhost:{KC_PORT}"
OS_URL = f"https://localhost:{OS_PORT}"
REALM = "kronos"
TOKEN_URL = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def password_grant(username: str, password: str) -> str:
    resp = httpx.post(
        TOKEN_URL,
        data={
            "client_id": "kronos-frontend",
            "grant_type": "password",
            "username": username,
            "password": password,
        },
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
    # --- 1. Real password-grant logins against real Keycloak ---
    print("=" * 10, "1. Real password-grant logins", "=" * 10)
    token_a1 = password_grant("user-a1", "DlsUserA1#2026")
    token_a2 = password_grant("user-a2", "DlsUserA2#2026")
    token_b1 = password_grant("user-b1", "DlsUserB1#2026")

    claims_a1 = jose_jwt.get_unverified_claims(token_a1)
    claims_a2 = jose_jwt.get_unverified_claims(token_a2)
    claims_b1 = jose_jwt.get_unverified_claims(token_b1)
    print("user-a1 claims:", json.dumps({k: claims_a1.get(k) for k in ("sub", "roles", "organization", "org_id")}, indent=2))
    print("user-a2 claims:", json.dumps({k: claims_a2.get(k) for k in ("sub", "roles", "organization", "org_id")}, indent=2))
    print("user-b1 claims:", json.dumps({k: claims_b1.get(k) for k in ("sub", "roles", "organization", "org_id")}, indent=2))

    check("real login succeeded for all 3 users (password grant against real Keycloak)", True)
    check("user-a1's REAL JWT carries a flat top-level 'org_id' claim", isinstance(claims_a1.get("org_id"), str))
    check("user-a2's REAL JWT carries the SAME flat org_id as user-a1 (same org)",
          claims_a2.get("org_id") == claims_a1.get("org_id") and claims_a1.get("org_id") is not None)
    check("user-b1's REAL JWT carries a DIFFERENT flat org_id (different org)",
          claims_b1.get("org_id") is not None and claims_b1.get("org_id") != claims_a1.get("org_id"))

    org_id_a = claims_a1.get("org_id")
    org_id_b = claims_b1.get("org_id")

    # --- 2. Real docs via the real OpenSearchClient ---
    print("\n" + "=" * 10, "2. Real bulk_index() into real OpenSearch", "=" * 10)
    client = OpenSearchClient(hosts=[{"host": "localhost", "port": int(OS_PORT)}], http_auth=("admin", "admin"), use_ssl=True, verify_certs=False)
    await client.ensure_index_template()
    index_name = "kronos-shared-case-dls-202607"
    docs = [
        (index_name, "doc-org-a", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "belongs to real org A",
            "kronos": {"org_id": org_id_a, "case_id": "dls", "evidence_id": "e1", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
        (index_name, "doc-org-b", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "belongs to real org B",
            "kronos": {"org_id": org_id_b, "case_id": "dls", "evidence_id": "e2", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
    ]
    n = await client.bulk_index(docs)
    await client._client.indices.refresh(index=index_name)
    check("both real docs indexed via the real bulk_index()", n == 2)
    await client.close()

    # --- 3. THE key test: real Keycloak tokens driving real DLS isolation ---
    print("\n" + "=" * 10, "3. Real DLS isolation via REAL Keycloak-issued tokens", "=" * 10)
    result_a1 = search_as(token_a1, index_name)
    ids_a1 = {h["_id"] for h in result_a1["hits"]["hits"]}
    print(f"user-a1 (real org {org_id_a}) sees: {ids_a1}")
    check("user-a1 sees ONLY org A's doc (real token, real org)", ids_a1 == {"doc-org-a"}, str(ids_a1))

    result_a2 = search_as(token_a2, index_name)
    ids_a2 = {h["_id"] for h in result_a2["hits"]["hits"]}
    print(f"user-a2 (real org {org_id_a}, second member of org A) sees: {ids_a2}")
    check("user-a2 (second real member of org A) is ALSO correctly isolated -- zero OpenSearch-side per-member work", ids_a2 == {"doc-org-a"}, str(ids_a2))

    result_b1 = search_as(token_b1, index_name)
    ids_b1 = {h["_id"] for h in result_b1["hits"]["hits"]}
    print(f"user-b1 (real org {org_id_b}) sees: {ids_b1}")
    check("user-b1 sees ONLY org B's doc (real token, real org)", ids_b1 == {"doc-org-b"}, str(ids_b1))

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
