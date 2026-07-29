"""PoC: does the existing kronos-generic-tenant DLS clause and the existing
ISM policy -- both templated on the kronos-* wildcard -- already cover a new
kronos-{org}-stream-{source}-{yyyymm} index family (roadmap M1/B2), with NO
config change needed?

Real check against the real, live OpenSearch 2.11.1 cluster:
1. Create a real index matching build_stream_index_name()'s real output
   shape, relying on the real hardened index_template.json (A1) to
   auto-apply via its own kronos-* index_patterns -- not a hand-built
   mapping.
2. Index two real documents: one tagged with the real, live case-lead
   analyst's actual org_id (confirmed via a real Dashboards-SSO login, same
   mechanism poc/security_analytics_tenant_isolation/ used), one tagged with
   a different (synthetic -- this dev stack only has one real provisioned
   org) org_id, to prove the DLS filter really discriminates on the field
   value, not on the index name/pattern.
3. Query as the real case-lead session -- confirm only the matching
   document returns.
4. Confirm via the real _plugins/_ism/explain API that the existing ISM
   policy actually attached itself to this new index (not assumed from the
   policy file's index_patterns wildcard alone).
5. Clean up the throwaway index.

Run: source ~/venv/bin/activate && python poc/stream_index_dls/run_poc.py
Requires the real, live dev stack up. If real HTTPS calls to kronos.local
fail with a certificate-expired error (step-ca leaf cert has a 24h TTL, no
auto-renew): `docker compose -f docker/docker-compose.dev.yml up -d
tls-init && docker restart docker-nginx-1`, then retry.
"""
from __future__ import annotations

import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
import auth_helpers as ah  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.application.timeline_normalization import build_stream_index_name  # noqa: E402

OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def real_dashboards_login(username: str, password: str) -> tuple[str, str]:
    """Real authorization-code+PKCE login against the real opensearch-dashboards
    confidential client (same mechanism poc/security_analytics_tenant_isolation/
    verified real Dashboards SSO logins use). Returns (access_token, org_id)."""
    ah.KC = "https://kronos.local:8443"
    ah.CLIENT_ID = "opensearch-dashboards"
    ah.REDIRECT_URI = "https://kronos.local:5602/auth/openid/login"
    ah.trust_dev_stack_step_ca()

    client = httpx.Client(follow_redirects=True, verify=ah.CA_BUNDLE)
    verifier, challenge = ah.new_pkce_pair()
    resp = ah.start_auth(client, (verifier, challenge), state="b2-stream-dls-poc")
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
    token = token_resp.json()["access_token"]
    claims = ah.decode_jwt_payload(token)
    return token, claims["org_id"]


def main() -> None:
    ts = datetime.now(UTC)
    index_name = build_stream_index_name("kronos-dev", "kronos-poc-source", ts)
    check(
        "build_stream_index_name() produces the expected kronos-* shape",
        index_name.startswith("kronos-kronos-dev-stream-kronos-poc-source-"),
        index_name,
    )

    print(f"\n=== 1. Create real index '{index_name}' -- relies on the real hardened index_template.json to auto-apply ===")
    resp = httpx.put(f"{OS_URL}/{index_name}", auth=OS_ADMIN, verify=False, timeout=15)
    check("index created (or already existed)", resp.status_code in (200, 400), f"status={resp.status_code}")

    mapping_resp = httpx.get(f"{OS_URL}/{index_name}/_mapping", auth=OS_ADMIN, verify=False, timeout=15).json()
    dynamic = mapping_resp.get(index_name, {}).get("mappings", {}).get("dynamic")
    check(
        "real index inherited the hardened template's dynamic:false (A1) automatically",
        dynamic == "false" or dynamic is False,
        f"dynamic={dynamic!r}",
    )
    has_org_id_keyword = (
        mapping_resp.get(index_name, {})
        .get("mappings", {})
        .get("properties", {})
        .get("kronos", {})
        .get("properties", {})
        .get("org_id", {})
        .get("type")
        == "keyword"
    )
    check("real index inherited kronos.org_id mapped as keyword", has_org_id_keyword)

    print("\n=== 2. Real Dashboards SSO login as the real, live case-lead analyst ===")
    token, real_org_id = real_dashboards_login("case-lead", "DevCaseLead#2026")
    check("real token issued, real org_id extracted", bool(token) and bool(real_org_id), real_org_id)

    other_org_id = str(uuid.uuid4())
    print(f"\n=== 3. Index two real documents: one for the real org ({real_org_id}), one for a different org ({other_org_id}) ===")
    for doc_id, org_id in (("real-org-doc", real_org_id), ("other-org-doc", other_org_id)):
        doc = {
            "@timestamp": ts.isoformat(),
            "event": {"kind": "event", "category": ["network"]},
            "message": f"stream test event for org {org_id}",
            "kronos": {
                "org_id": org_id,
                "org_alias": "kronos-dev" if org_id == real_org_id else "other-org",
                "parser": "poc-stream-test",
                "parser_version": "0.0.1",
                "ingest_timestamp": ts.isoformat(),
            },
        }
        r = httpx.put(
            f"{OS_URL}/{index_name}/_doc/{doc_id}?refresh=true",
            auth=OS_ADMIN,
            json=doc,
            verify=False,
            timeout=15,
        )
        check(f"indexed real doc '{doc_id}'", r.status_code in (200, 201), f"status={r.status_code}")

    time.sleep(1)

    print("\n=== 4. As admin (no DLS): confirm BOTH documents are really there ===")
    admin_search = httpx.post(
        f"{OS_URL}/{index_name}/_search",
        auth=OS_ADMIN,
        json={"query": {"match_all": {}}},
        verify=False,
        timeout=15,
    ).json()
    check(
        "admin sees both real documents (proves the isolation we're about to test is real DLS, not 'nothing is there')",
        admin_search["hits"]["total"]["value"] == 2,
        admin_search["hits"]["total"],
    )

    print("\n=== 5. As the real case-lead session (DLS active): confirm ONLY the matching-org document returns ===")
    tenant_search = httpx.post(
        f"{OS_URL}/{index_name}/_search",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": {"match_all": {}}},
        verify=False,
        timeout=15,
    ).json()
    hits = tenant_search.get("hits", {}).get("hits", [])
    check(
        "real tenant session sees exactly 1 document (its own org's)",
        len(hits) == 1,
        f"count={len(hits)} body={tenant_search if len(hits) != 1 else ''}",
    )
    if hits:
        check(
            "the visible document is the real org's document, not the other org's",
            hits[0]["_id"] == "real-org-doc",
            hits[0]["_id"],
        )

    print("\n=== 6. Confirm the existing ISM policy really attached to this new stream index (not assumed from the wildcard alone) ===")
    ism_resp = httpx.get(
        f"{OS_URL}/_plugins/_ism/explain/{index_name}", auth=OS_ADMIN, verify=False, timeout=15
    ).json()
    index_ism_state = ism_resp.get(index_name, {})
    policy_id = index_ism_state.get("index.plugins.index_state_management.policy_id")
    check(
        "the real kronos-* ISM policy is attached to the new stream index automatically",
        bool(policy_id),
        f"policy_id={policy_id!r} full={index_ism_state}",
    )

    print(f"\n=== 7. Cleanup: delete throwaway index '{index_name}' ===")
    del_resp = httpx.delete(f"{OS_URL}/{index_name}", auth=OS_ADMIN, verify=False, timeout=15)
    check("throwaway index deleted", del_resp.status_code == 200, f"status={del_resp.status_code}")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
