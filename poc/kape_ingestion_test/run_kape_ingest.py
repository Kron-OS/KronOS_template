"""Real end-to-end KAPE ingestion test against the live dev-stack backend:
real login -> real case creation -> real upload/finalize of the KAPE-shaped
ZIP and E01 fixtures (tests/fixtures/samples/real/kape/, see that
directory's NOTICE.md for provenance) -> autonomous pipeline -> caller
polls to COMPLETE and then runs fetch_kape_documents.py to verify every
inner record's real source_path/file.path against real OpenSearch.

Reuses poc/full_ingestion_test/login.py's real scripted PKCE flow verbatim
(same dev Keycloak, same case-lead account).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "full_ingestion_test"))
import auth_helpers  # noqa: E402

# Must be the canonical LAN HTTPS origin (matches KC_HOSTNAME), not
# http://localhost:8080 -- real, reproduced finding (poc/tls_lan_https/):
# Keycloak's login form always posts to the single pinned KC_HOSTNAME
# origin regardless of where the flow started, so starting anywhere else
# loses the session-restart cookie across that domain jump ("Restart
# login cookie not found", a real 400 reproduced and root-caused, not
# assumed). See frontend/src/keycloak.ts's resolveKeycloakUrl() for the
# same fix applied to the real frontend.
auth_helpers.KC = "https://192.168.5.13:8443"
# Real, reproduced regression fix (poc/tls_lan_https/): the login form
# now redirects mid-flow to the LAN HTTPS Keycloak origin, which needs the
# stack's own step-ca root trusted or httpx raises CERTIFICATE_VERIFY_FAILED.
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "http://localhost:8000"
REPO_ROOT = Path(__file__).resolve().parents[2]
KAPE_DIR = REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "kape"

FILES = [
    ("kape-zip", KAPE_DIR / "kape_triage.zip", "application/zip"),
    ("kape-e01", KAPE_DIR / "kape_triage.E01", "application/octet-stream"),
]


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def main() -> None:
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="kape-ingest-1"
    )
    log(f"login OK (mfa_path={mfa_path})")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=120)

    resp = client.post(
        "/api/cases",
        json={
            "title": "KAPE ingestion test — zip + E01",
            "description": (
                "Real upload/finalize of a KAPE-shaped zip and a real EWF (E01) "
                "image, verifying ZipArchiveParser recursion and Plaso's "
                "whole-image routing, both with real source_path provenance."
            ),
            "classification": "UNCLASSIFIED",
        },
    )
    log("create_case ->", resp.status_code, resp.text[:400])
    resp.raise_for_status()
    case_id = resp.json()["id"]
    log(f"case_id={case_id}")

    results = []
    for label, path, content_type in FILES:
        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        log(f"--- {label}: {path.name} ({len(data)} bytes, sha256={sha256[:12]}...) ---")

        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": path.name,
                "contentType": content_type,
                "sizeBytes": len(data),
                "caseId": case_id,
            },
        )
        log(f"{label} upload/request ->", resp.status_code, resp.text[:300])
        resp.raise_for_status()
        upload = resp.json()
        evidence_id = upload["evidenceId"]

        # verify=auth_helpers.CA_BUNDLE: same real fix as
        # poc/full_ingestion_test/run_ingest.py -- presignedUrl is now the
        # LAN-HTTPS MinIO proxy, needs the step-ca root trusted.
        put_resp = httpx.put(upload["presignedUrl"], content=data, timeout=120, verify=auth_helpers.CA_BUNDLE)
        log(f"{label} PUT to MinIO ->", put_resp.status_code)
        put_resp.raise_for_status()

        resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": sha256},
        )
        log(f"{label} finalize ->", resp.status_code, resp.text[:300])
        resp.raise_for_status()

        results.append(
            {"label": label, "evidence_id": evidence_id, "filename": path.name, "sha256": sha256}
        )

    out_path = Path(__file__).parent / "evidence_ids.json"
    out_path.write_text(json.dumps({"case_id": case_id, "evidence": results}, indent=2))
    log(f"wrote {out_path}")
    print(json.dumps({"case_id": case_id, "evidence": results}))


if __name__ == "__main__":
    main()
