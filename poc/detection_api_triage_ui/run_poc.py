"""PoC: C6 detection list/detail/triage HTTP routes -- real backend, real
Keycloak logins, real Postgres-backed Detection rows.

Verifies src/external/routes/detections.py (list/detail/triage) against the
REAL, already-running dev-stack backend (docker-kronos-backend-1, reached
directly at http://localhost:8000 -- uvicorn --reload already picked up the
new route module once it was added and wired into fastapi_app.py) using
REAL Keycloak-issued JWTs from REAL PKCE browser logins
(poc/auth_flow/auth_helpers.py -- the same helper poc/security_analytics_
tenant_isolation/ and other PoCs this session use), never hand-minted
tokens and never an in-process TestClient standing in for the real HTTP
boundary.

Real data used (left in Postgres by poc/detection_finding_sync/'s own real
run, per its README -- not re-created here): 10 real Detection rows for org
kronos-dev, detector "kronos-kronos-dev-network-detector", case_id
1a49dcd0-b6a6-4410-83aa-def7ffc9f9fa, real rule 1fc0809e-06bf-4de3-ad52-
25e5263b7623 (t1021.001), one already TRUE_POSITIVE from that PoC's own
triage exercise, nine still NEW. Confirmed directly via
`docker exec docker-postgres-1 psql -U kronos -d kronos -c "SELECT ... FROM
detections"` before writing this script (see README.md).

Real users (docker/keycloak/kronos-realm.json, org kronos-dev):
  - case-lead / DevCaseLead#2026  (role case-lead)
  - analyst   / DevAnalyst#2026   (role analyst)
Real throwaway second org + user, created via this repo's own
scripts/provision_keycloak_org.sh (idempotent, same script dev/prod/Helm
use) purely to exercise real cross-org isolation, deleted at the end:
  - kronos-poc-c6 org (id 825f35fc-c8f4-4fc0-bc40-f457deb178b6)
  - poc-c6-analyst / PocC6Analyst#2026 (role analyst)
Real throwaway READ_ONLY user in org kronos-dev (no read-only dev user is
seeded by kronos-realm.json, so one was created for this PoC to prove the
route's RBAC split -- read routes allow all four roles, triage requires
org-admin/case-lead/analyst), deleted at the end:
  - poc-c6-readonly / PocC6ReadOnly#2026 (role read-only, org kronos-dev)

Run: source ~/venv/bin/activate && python poc/detection_api_triage_ui/run_poc.py
Requires: the real dev stack up, a currently-valid step-ca leaf cert for
kronos.local (24h TTL -- `docker compose -f docker/docker-compose.dev.yml
up -d tls-init && docker restart docker-nginx-1` if expired; confirmed
fresh for this run: notBefore=2026-07-31T05:08:19Z).
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
import auth_helpers as ah  # noqa: E402

BACKEND_URL = "http://localhost:8000"  # real docker-kronos-backend-1, host-published
CA_BUNDLE = "/tmp/kronos_root_ca.crt"  # docker cp docker-tls-init-1:/certs/root_ca.crt

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def real_login(username: str, password: str) -> str:
    """Real PKCE authorization-code login against the real kronos-frontend
    SPA client (the same client the actual browser frontend uses) through
    real kronos.local nginx + Keycloak. Returns a real access token whose
    ``aud`` includes ``kronos-backend`` (kronos-frontend's own audience
    mapper, docker/keycloak/kronos-realm.json)."""
    ah.KC = "https://kronos.local:8443"
    ah.CLIENT_ID = "kronos-frontend"
    ah.REDIRECT_URI = "https://kronos.local/callback"
    ah.CA_BUNDLE = CA_BUNDLE

    client = httpx.Client(follow_redirects=True, verify=ah.CA_BUNDLE)
    verifier, challenge = ah.new_pkce_pair()
    resp = ah.start_auth(client, (verifier, challenge), state=f"c6-{username}")
    resp = ah.submit_username_password(client, resp, username, password)
    tokens = ah.extract_code_and_exchange(client, resp, verifier)
    return tokens["access_token"]


def main() -> None:
    print("=== Real logins (PKCE, real Keycloak, real kronos-frontend client) ===")
    case_lead_token = real_login("case-lead", "DevCaseLead#2026")
    analyst_token = real_login("analyst", "DevAnalyst#2026")
    other_org_token = real_login("poc-c6-analyst", "PocC6Analyst#2026")
    readonly_token = real_login("poc-c6-readonly", "PocC6ReadOnly#2026")

    for name, tok in [
        ("case-lead", case_lead_token),
        ("analyst", analyst_token),
        ("poc-c6-analyst", other_org_token),
        ("poc-c6-readonly", readonly_token),
    ]:
        claims = ah.decode_jwt_payload(tok)
        print(f"  {name}: org={claims.get('organization')}, roles={claims.get('roles')}")

    check(
        "case-lead's real token org_id is kronos-dev's real org id",
        ah.decode_jwt_payload(case_lead_token)["org_id"] == "482072f5-8086-4815-be03-879cc2eaecb5",
    )
    check(
        "poc-c6-analyst's real token org_id is the real SECOND org (not kronos-dev)",
        ah.decode_jwt_payload(other_org_token)["org_id"] == "825f35fc-c8f4-4fc0-bc40-f457deb178b6",
    )

    case_lead_headers = {"Authorization": f"Bearer {case_lead_token}"}
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    other_org_headers = {"Authorization": f"Bearer {other_org_token}"}
    readonly_headers = {"Authorization": f"Bearer {readonly_token}"}

    # === Part 1: list, real org data, real filtering ===
    print("\n=== Part 1: GET /api/detections (org kronos-dev, real synced rows) ===")
    resp = httpx.get(
        f"{BACKEND_URL}/api/detections", headers=case_lead_headers, params={"pageSize": 50}
    )
    print(f"  -> {resp.status_code}")
    check("case-lead can list detections (200)", resp.status_code == 200)
    body = resp.json()
    check(
        "at least the 10 real Detection rows left by poc/detection_finding_sync/ are visible",
        body["total"] >= 10,
        f"total={body['total']}",
    )

    true_positive = [d for d in body["items"] if d["triageState"] == "TRUE_POSITIVE"]
    new_items = [d for d in body["items"] if d["triageState"] == "NEW"]
    check(
        "at least one real TRUE_POSITIVE row present (from C4's own triage exercise)",
        len(true_positive) >= 1,
    )
    check("at least one real NEW row present", len(new_items) >= 2, f"count={len(new_items)}")

    resp2 = httpx.get(
        f"{BACKEND_URL}/api/detections",
        headers=case_lead_headers,
        params={"triageState": "NEW", "pageSize": 50},
    )
    filtered = resp2.json()["items"]
    check(
        "triageState=NEW query filter returns only NEW rows",
        len(filtered) > 0 and all(d["triageState"] == "NEW" for d in filtered),
        f"count={len(filtered)}",
    )

    sample_case_id = body["items"][0]["caseId"]
    resp3 = httpx.get(
        f"{BACKEND_URL}/api/detections",
        headers=case_lead_headers,
        params={"caseId": sample_case_id, "pageSize": 50},
    )
    check(
        "caseId query filter returns only that case's detections",
        len(resp3.json()["items"]) > 0
        and all(d["caseId"] == sample_case_id for d in resp3.json()["items"]),
    )

    resp4 = httpx.get(f"{BACKEND_URL}/api/detections", headers=analyst_headers)
    check(
        "analyst (read-tier role) can also list detections (matches §1 matrix's "
        "'Search timeline' read row)",
        resp4.status_code == 200,
    )

    # === Part 2: detail ===
    print("\n=== Part 2: GET /api/detections/{id} ===")
    target_new = new_items[0]
    resp = httpx.get(f"{BACKEND_URL}/api/detections/{target_new['id']}", headers=case_lead_headers)
    check("case-lead can read a single detection's detail", resp.status_code == 200)
    detail = resp.json()
    check(
        "detail carries a real rule_id (replayability)",
        len(detail["ruleMatches"]) > 0 and bool(detail["ruleMatches"][0]["ruleId"]),
        str(detail["ruleMatches"]),
    )
    check(
        "detail's attackTags exposes the real ATT&CK tag t1021.001",
        "attack.t1021.001" in detail["attackTags"],
        str(detail["attackTags"]),
    )

    resp = httpx.get(f"{BACKEND_URL}/api/detections/{'0' * 8}-0000-0000-0000-{'0' * 12}", headers=case_lead_headers)
    check("a nonexistent detection_id also returns 404", resp.status_code == 404, f"got {resp.status_code}")

    # === Part 3: cross-org isolation (roadmap invariant #3) ===
    print("\n=== Part 3: cross-org isolation -- real second org, real second login ===")
    resp = httpx.get(f"{BACKEND_URL}/api/detections", headers=other_org_headers)
    check(
        "poc-c6-analyst (different real org) sees ZERO of kronos-dev's detections",
        resp.status_code == 200 and resp.json()["total"] == 0,
        f"status={resp.status_code} total={resp.json().get('total')}",
    )

    resp = httpx.get(f"{BACKEND_URL}/api/detections/{target_new['id']}", headers=other_org_headers)
    check(
        "poc-c6-analyst reading kronos-dev's real detection by id -> 404 "
        "(NOT 403 -- must not leak cross-org existence)",
        resp.status_code == 404,
        f"got {resp.status_code}",
    )

    resp = httpx.post(
        f"{BACKEND_URL}/api/detections/{target_new['id']}/triage",
        headers=other_org_headers,
        json={"targetState": "INVESTIGATING"},
    )
    check(
        "poc-c6-analyst cannot triage kronos-dev's real detection -> 404",
        resp.status_code == 404,
        f"got {resp.status_code}",
    )

    resp = httpx.get(f"{BACKEND_URL}/api/detections/{target_new['id']}", headers=case_lead_headers)
    check(
        "target detection's triage_state genuinely unchanged after the cross-org attempt",
        resp.json()["triageState"] == "NEW",
    )

    # === Part 4: real triage transitions via the API (roadmap invariant #4) ===
    print("\n=== Part 4: real triage transitions via POST /triage ===")
    resp = httpx.post(
        f"{BACKEND_URL}/api/detections/{target_new['id']}/triage",
        headers=analyst_headers,
        json={"targetState": "INVESTIGATING"},
    )
    check(
        "analyst: real NEW -> INVESTIGATING transition via the real API",
        resp.status_code == 200 and resp.json()["triageState"] == "INVESTIGATING",
        f"got {resp.status_code} {resp.text[:200]}",
    )

    resp = httpx.get(f"{BACKEND_URL}/api/detections/{target_new['id']}", headers=case_lead_headers)
    check(
        "re-read from the real API confirms the persisted triage_state",
        resp.json()["triageState"] == "INVESTIGATING",
    )

    other_new_candidates = [d for d in new_items if d["id"] != target_new["id"]]
    other_new = other_new_candidates[0]
    resp = httpx.post(
        f"{BACKEND_URL}/api/detections/{other_new['id']}/triage",
        headers=analyst_headers,
        json={"targetState": "TRUE_POSITIVE"},
    )
    check(
        "illegal NEW -> TRUE_POSITIVE (skipping INVESTIGATING) returns 409, not a raw 500",
        resp.status_code == 409,
        f"got {resp.status_code} {resp.text[:200]}",
    )

    resp = httpx.get(f"{BACKEND_URL}/api/detections/{other_new['id']}", headers=case_lead_headers)
    check(
        "the rejected illegal transition did NOT mutate the persisted state",
        resp.json()["triageState"] == "NEW",
    )

    tp = true_positive[0]
    resp = httpx.post(
        f"{BACKEND_URL}/api/detections/{tp['id']}/triage",
        headers=analyst_headers,
        json={"targetState": "INVESTIGATING"},
    )
    check(
        "a terminal TRUE_POSITIVE detection rejects re-transition -> 409 (no reopen loophole)",
        resp.status_code == 409,
        f"got {resp.status_code}",
    )

    # === Part 5: RBAC split -- read-only can read, cannot triage ===
    print("\n=== Part 5: read-only role -- can list/read, cannot triage ===")
    resp = httpx.get(f"{BACKEND_URL}/api/detections", headers=readonly_headers)
    check(
        "read-only role CAN list detections (matches §1 matrix's read-tier rows)",
        resp.status_code == 200 and resp.json()["total"] >= 10,
        f"status={resp.status_code}",
    )
    resp = httpx.get(f"{BACKEND_URL}/api/detections/{tp['id']}", headers=readonly_headers)
    check("read-only role CAN read a single detection's detail", resp.status_code == 200)
    resp = httpx.post(
        f"{BACKEND_URL}/api/detections/{other_new['id']}/triage",
        headers=readonly_headers,
        json={"targetState": "INVESTIGATING"},
    )
    check(
        "read-only role CANNOT triage -> 403 (mirrors §1 matrix's 'Upload evidence' "
        "row: org-admin/case-lead/analyst yes, read-only no)",
        resp.status_code == 403,
        f"got {resp.status_code} {resp.text[:200]}",
    )

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILURES:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
