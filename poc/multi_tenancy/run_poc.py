"""PoC: real cross-org isolation, using the REAL FastAPI app booted against a
real Postgres + real MinIO + real OpenSearch + real Keycloak (two real
Organizations, two real JWTs) -- not in-memory fakes, not hand-minted tokens.

Exercises the actual production startup path (wire_dependencies_async(), the
same function FastAPI's own lifespan calls when DATABASE_URL is set) so any
gap between "what production actually wires" and "what the code assumes" is
caught, per CLAUDE.md Section F.

Run: source ~/venv/bin/activate && python poc/multi_tenancy/run_poc.py
(env vars must already be exported -- see run_poc.sh)
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

from src.external.fastapi_app import create_app  # noqa: E402

KC_BASE = "http://localhost:18081"
ISSUER = f"{KC_BASE}/realms/kronos"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"

ANALYST_TOKEN = Path("/tmp/analyst_token.txt").read_text().strip()
CASELEAD_BETA_TOKEN = Path("/tmp/caselead_token.txt").read_text().strip()
CASELEAD_ACME_TOKEN = Path("/tmp/caselead_acme_token.txt").read_text().strip()

PASS = []
FAIL = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def main() -> None:
    app = create_app(
        keycloak_issuer=ISSUER,
        keycloak_audience="kronos-backend",
        keycloak_jwks_url=JWKS_URL,
    )

    with TestClient(app) as client:
        # --- 0. Confirm real startup wiring actually succeeded (not silently
        # swallowed into the in-memory fallback) ---
        import src.external.dependencies as deps

        case_repo = deps.get_case_repository()
        evidence_repo = deps.get_evidence_repository()
        print(f"\ncase_repository wired as: {type(case_repo).__name__}")
        print(f"evidence_repository wired as: {type(evidence_repo).__name__}")
        check(
            "evidence_repository is the real Postgres-backed implementation",
            type(evidence_repo).__name__ == "PostgresEvidenceRepository",
        )
        # This is the finding: wire_dependencies_async() never passes
        # case_repository= to configure_dependencies(), so it silently stays
        # whatever the module-level default is (InMemoryCaseRepository),
        # even though a real Postgres is up, reachable, and evidence_repo
        # DID wire to it correctly. Recorded as PASS/FAIL either way so this
        # PoC keeps working (and re-catches a regression) if it's ever fixed.
        case_repo_is_postgres = type(case_repo).__name__ == "PostgresCaseRepository"
        check(
            "case_repository is ALSO Postgres-backed (expected to FAIL today -- see README)",
            case_repo_is_postgres,
        )

        acme_headers = {"Authorization": f"Bearer {CASELEAD_ACME_TOKEN}"}
        beta_headers = {"Authorization": f"Bearer {CASELEAD_BETA_TOKEN}"}
        analyst_headers = {"Authorization": f"Bearer {ANALYST_TOKEN}"}

        # --- 1. acme's case-lead creates a case in acme ---
        resp = client.post(
            "/api/cases",
            headers=acme_headers,
            json={"title": "Acme Incident 001", "description": "PoC case for acme"},
        )
        print(f"\ncreate case (acme) -> {resp.status_code} {resp.text[:300]}")
        check("acme case-lead can create a case in their own org", resp.status_code == 201)
        acme_case = resp.json()
        acme_case_id = acme_case["id"] if resp.status_code == 201 else None

        # --- 2. beta's case-lead tries to read acme's case by ID (IDOR-style) ---
        if acme_case_id:
            resp = client.get(f"/api/cases/{acme_case_id}", headers=beta_headers)
            print(f"\nbeta reads acme's case by ID -> {resp.status_code} {resp.text[:200]}")
            check(
                "beta CANNOT read acme's case by ID (expect 404, not 200)",
                resp.status_code == 404,
                f"got {resp.status_code}",
            )

            # --- 3. beta's case-lead tries to delete acme's case ---
            resp = client.delete(f"/api/cases/{acme_case_id}", headers=beta_headers)
            print(f"beta deletes acme's case -> {resp.status_code} {resp.text[:200]}")
            check(
                "beta CANNOT delete acme's case (expect 404, not 204)",
                resp.status_code == 404,
            )

            # Confirm it's still there for acme afterward (delete really didn't happen)
            resp = client.get(f"/api/cases/{acme_case_id}", headers=acme_headers)
            check(
                "acme's case still exists after beta's delete attempt",
                resp.status_code == 200,
            )

        # --- 4. beta lists cases -- must not include acme's case ---
        resp = client.get("/api/cases", headers=beta_headers)
        beta_case_ids = {c["id"] for c in resp.json().get("items", [])} if resp.status_code == 200 else set()
        print(f"\nbeta's case list: {resp.status_code}, {len(beta_case_ids)} case(s)")
        check(
            "acme's case_id does not appear in beta's case list",
            acme_case_id not in beta_case_ids,
        )

        # --- 5. beta creates its OWN case, then acme must not see it either ---
        resp = client.post(
            "/api/cases", headers=beta_headers, json={"title": "Beta Incident 001", "description": "x"}
        )
        beta_case_id = resp.json()["id"] if resp.status_code == 201 else None
        print(f"\ncreate case (beta) -> {resp.status_code}")
        check("beta case-lead can create a case in their own org", resp.status_code == 201)

        if beta_case_id:
            resp = client.get(f"/api/cases/{beta_case_id}", headers=acme_headers)
            check(
                "acme CANNOT read beta's case by ID either (isolation is symmetric)",
                resp.status_code == 404,
            )

        # --- 6. analyst (acme, wrong role) cannot create a case at all (RBAC, not org) ---
        resp = client.post(
            "/api/cases", headers=analyst_headers, json={"title": "Should be rejected", "description": "x"}
        )
        print(f"\nanalyst (wrong role) creates case -> {resp.status_code}")
        check("analyst role cannot create a case (RBAC, separate from org isolation)", resp.status_code == 403)

        # --- 7. Evidence isolation (real Postgres-backed repo, unlike cases) ---
        if acme_case_id:
            resp = client.post(
                "/api/evidence/upload/request",
                headers=acme_headers,
                json={
                    "filename": "acme-evidence.txt",
                    "contentType": "text/plain",
                    "sizeBytes": 100,
                    "caseId": acme_case_id,
                },
            )
            print(f"\nacme requests evidence upload -> {resp.status_code} {resp.text[:300]}")
            if resp.status_code == 201:
                evidence_id = resp.json()["evidenceId"]
                resp = client.get(f"/api/cases/{acme_case_id}/evidence", headers=beta_headers)
                print(f"beta lists acme's case evidence -> {resp.status_code} {resp.text[:200]}")
                check(
                    "beta CANNOT list evidence under acme's case",
                    resp.status_code in (403, 404),
                )

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


if __name__ == "__main__":
    main()
