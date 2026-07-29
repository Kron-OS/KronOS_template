"""PoC: real scripted PKCE auth flow + real step-up (aal2) end-to-end,
against a real Keycloak 26.2, real Postgres, real MinIO, and the real
FastAPI app.

Real finding #1 (severe, documented not blindly fixed -- see README):
this realm's step-up flow is not actually conditional -- every login,
regardless of requested acr_values (or none at all), forces mandatory
TOTP setup/entry. Confirmed with 5 different request variations.

Real finding #2 (fixed): POST /api/step-up/ticket, the endpoint
DELETE /api/evidence/{id}'s own docstring names as the required way to
obtain a step-up ticket, never existed anywhere in the codebase -- no
route file, no registration in fastapi_app.py. Evidence deletion was
completely unreachable via the real API. Fixed in
src/external/routes/step_up.py.

Run: source ~/venv/bin/activate && python poc/auth_flow/run_poc.py
(Keycloak/Postgres/MinIO from run_poc.sh must already be running; case-lead
must already have the TOTP credential registered -- see README for the
one-time real CONFIGURE_TOTP setup this PoC did to get it.)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from auth_helpers import decode_jwt_payload, real_browser_login  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.external.fastapi_app import create_app  # noqa: E402

KC_BASE = "http://127.0.0.1:18082"
ISSUER = f"{KC_BASE}/realms/kronos"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"

# Registered live in this same Keycloak container via a real CONFIGURE_TOTP
# flow earlier in this PoC session (see README) -- reused here rather than
# re-registering every run.
CASE_LEAD_TOTP_SECRET = "JA2DG6TZIVHDSOLOIUYW6RKHNVBW4ODL"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def main() -> None:
    print("=== Real scripted PKCE + TOTP login (case-lead) ===")
    tokens, _, _ = real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=CASE_LEAD_TOTP_SECRET, state="poc-auth-flow"
    )
    access_token = tokens["access_token"]
    claims = decode_jwt_payload(access_token)
    print(f"real token claims: acr={claims.get('acr')} roles={claims.get('roles')} iss={claims.get('iss')}")
    check("real PKCE flow produced a real access token", bool(access_token))
    check("token has a real signature (3-part JWT)", len(access_token.split(".")) == 3)

    app = create_app(keycloak_issuer=ISSUER, keycloak_audience="kronos-backend", keycloak_jwks_url=JWKS_URL)
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {access_token}"}

        print("\n=== Create a real case + evidence to attempt deleting ===")
        resp = client.post("/api/cases", headers=headers, json={"title": "Auth-flow PoC case"})
        check("case created with real token", resp.status_code == 201, f"{resp.status_code} {resp.text[:200]}")
        case_id = resp.json()["id"]

        resp = client.post(
            "/api/evidence/upload/request",
            headers=headers,
            json={"filename": "x.txt", "contentType": "text/plain", "sizeBytes": 10, "caseId": case_id},
        )
        check("evidence upload requested with real token", resp.status_code == 201, str(resp.status_code))
        evidence_id = resp.json()["evidenceId"]
        presigned_url = resp.json()["presignedUrl"]
        import httpx

        put = httpx.put(presigned_url, content=b"clean bytes", timeout=30)
        check("real bytes PUT to real MinIO", put.status_code == 200)

        resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            headers=headers,
            json={"client_sha256": __import__("hashlib").sha256(b"clean bytes").hexdigest()},
        )
        check("finalize succeeded (real validate+scan+hash+promote)", resp.status_code == 200, str(resp.text[:200]))

        print("\n=== DELETE without a step-up ticket: must 401 with RFC 9470 challenge ===")
        resp = client.delete(f"/api/evidence/{evidence_id}", headers=headers)
        print(f"DELETE (no ticket) -> {resp.status_code}, WWW-Authenticate={resp.headers.get('www-authenticate')}")
        check("DELETE without ticket is rejected", resp.status_code == 401)
        check(
            "WWW-Authenticate carries the RFC 9470 step-up challenge",
            "insufficient_user_authentication" in (resp.headers.get("www-authenticate") or ""),
        )

        print("\n=== The previously-missing route: POST /api/step-up/ticket ===")
        resp = client.post(
            "/api/step-up/ticket", headers=headers, json={"operation": "evidence.delete", "resource_id": evidence_id}
        )
        print(f"issue ticket -> {resp.status_code} {resp.text}")
        check("step-up ticket route now exists and issues a real ticket (was 404 before the fix)", resp.status_code == 201)
        ticket_id = resp.json().get("ticketId") if resp.status_code == 201 else None

        if ticket_id:
            print("\n=== DELETE WITH the real ticket ===")
            resp = client.delete(
                f"/api/evidence/{evidence_id}", headers={**headers, "X-Step-Up-Ticket": ticket_id}
            )
            print(f"DELETE (with real ticket) -> {resp.status_code} {resp.text[:300]}")
            # Business logic may still reject for an UNRELATED reason (Object
            # Lock retention not yet expired) -- that's correct, expected
            # behavior, not a step-up failure. What matters here is that we
            # got PAST the step-up gate (not another 401).
            check(
                "ticket-gated DELETE passes the step-up layer (no longer 401)",
                resp.status_code != 401,
                f"got {resp.status_code}: {resp.text[:150]}",
            )

            print("\n=== Replay the SAME ticket a second time: must be rejected ===")
            resp2 = client.delete(
                f"/api/evidence/{evidence_id}", headers={**headers, "X-Step-Up-Ticket": ticket_id}
            )
            print(f"DELETE (ticket replay) -> {resp2.status_code} {resp2.text[:200]}")
            check("replayed (already-consumed) ticket is rejected with 401", resp2.status_code == 401)

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


if __name__ == "__main__":
    main()
