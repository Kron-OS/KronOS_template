"""Step 5 verification (not a full PoC of its own): does the REAL, refactored
src/adapter/opensearch/client.py OpenSearchClient.ensure_generic_tenant_role()
actually produce a correct role + mapping and correct DLS isolation, or is
it just plausible-looking code modeled on the raw curl calls the earlier
PoCs used? Per CLAUDE.md Section F, the earlier PoCs (option_a_flat_claim/,
keycloak_opensearch_dls/) proved the *design* by hand-crafting the role/
mapping via curl -- they never called this method. This closes that gap by
calling the real method directly against a real OpenSearch and confirming
real DLS isolation with a hand-signed JWT (reusing
../opensearch_jwt/option_a_flat_claim/test_key.pem).

Run: source ~/venv/bin/activate && python poc/keycloak_opensearch_dls/verify_src_ensure_generic_tenant_role.py
(OpenSearch must already be up with the JWT authc domain configured against
test_key.pem -- see the run log this file's README/output.txt links to.)
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402

OS_URL = "https://localhost:19940"
PRIVATE_KEY_PATH = Path(__file__).resolve().parents[1] / "opensearch_jwt" / "option_a_flat_claim" / "test_key.pem"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def mint_token(sub: str, org_id: str) -> str:
    private_key = PRIVATE_KEY_PATH.read_text()
    claims = {
        "sub": sub, "iss": "kronos-poc-test-issuer", "aud": "kronos-backend",
        "exp": int(time.time()) + 3600, "iat": int(time.time()),
        "roles": ["analyst"], "org_id": org_id,
    }
    return jose_jwt.encode(claims, private_key, algorithm="RS256")


def search_as(token: str, index: str) -> dict:
    with httpx.Client(verify=False) as h:
        resp = h.get(f"{OS_URL}/{index}/_search", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json()


async def main() -> None:
    client = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 19940}],
        http_auth=("admin", "admin"), use_ssl=True, verify_certs=False,
    )

    # --- THE thing this script exists to prove: call the REAL src/ method ---
    await client.ensure_generic_tenant_role()
    print("Called the real OpenSearchClient.ensure_generic_tenant_role()")

    with httpx.Client(verify=False) as h:
        role_resp = h.get(f"{OS_URL}/_plugins/_security/api/roles/kronos-generic-tenant", auth=("admin", "admin"))
        mapping_resp = h.get(f"{OS_URL}/_plugins/_security/api/rolesmapping/kronos-generic-tenant", auth=("admin", "admin"))
    print("role GET ->", role_resp.status_code, role_resp.text[:300])
    print("mapping GET ->", mapping_resp.status_code, mapping_resp.text[:300])
    check("real role created via the real src/ method (GET returns 200, not 404)", role_resp.status_code == 200)
    check("real mapping created via the real src/ method (GET returns 200, not 404)", mapping_resp.status_code == 200)
    check("real mapping includes all four KronOS realm roles", all(
        r in mapping_resp.json()["kronos-generic-tenant"]["backend_roles"]
        for r in ("org-admin", "case-lead", "analyst", "read-only")
    ))

    # --- Idempotency: calling it again must not error (PUT is idempotent) ---
    await client.ensure_generic_tenant_role()
    check("calling ensure_generic_tenant_role() a second time does not raise", True)

    # --- Real DLS isolation end-to-end, through the real method this time ---
    await client.ensure_index_template()
    index_name = "kronos-step5verify-case-x-202607"
    n = await client.bulk_index([
        (index_name, "doc-org-a", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "org A",
            "kronos": {"org_id": "org-aaaa-1111", "case_id": "x", "evidence_id": "e1", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
        (index_name, "doc-org-b", {
            "@timestamp": "2026-07-22T00:00:00Z", "message": "org B",
            "kronos": {"org_id": "org-bbbb-2222", "case_id": "x", "evidence_id": "e2", "parser": "test", "parser_version": "1", "record_index": 0, "ingest_timestamp": "2026-07-22T00:00:00Z"},
        }),
    ])
    await client._client.indices.refresh(index=index_name)
    check("both real docs indexed via the real bulk_index()", n == 2)
    await client.close()

    token_a = mint_token("user-a", "org-aaaa-1111")
    token_b = mint_token("user-b", "org-bbbb-2222")
    ids_a = {h["_id"] for h in search_as(token_a, index_name)["hits"]["hits"]}
    ids_b = {h["_id"] for h in search_as(token_b, index_name)["hits"]["hits"]}
    print(f"user-a sees: {ids_a}, user-b sees: {ids_b}")
    check("user A isolated to org A's doc via the REAL src/ role+mapping", ids_a == {"doc-org-a"}, str(ids_a))
    check("user B isolated to org B's doc via the REAL src/ role+mapping", ids_b == {"doc-org-b"}, str(ids_b))

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
