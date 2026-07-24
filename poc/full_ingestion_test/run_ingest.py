"""Real end-to-end ingestion test against the live dev-stack backend
(localhost:8000): login (login.py) -> create case -> upload+finalize one
real sample per registered parser -> print evidence IDs for the poll step.

Samples, one per ParserRegistry entry (src/external/dependencies.py
registration order), all real forensic artifacts (Plaso's own test corpus,
or --for chrome_history, no real sample existed anywhere in the repo--
a hand-built-but-schema-correct SQLite DB, see poc/full_ingestion_test/History):
  - cloudtrail:  tests/fixtures/samples/real/aws_cloudtrail.jsonl
  - nginx:       tests/fixtures/samples/real/apache_access.log
  - chrome-hist: poc/full_ingestion_test/History
  - evtx-rs:     tests/fixtures/samples/real/system.evtx
  - plaso:       tests/fixtures/samples/real/CMD.EXE-087B4001.pf (Windows prefetch)
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
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
SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "samples" / "real"

FILES = [
    ("cloudtrail", SAMPLES_DIR / "aws_cloudtrail.jsonl", "application/x-ndjson"),
    ("nginx", SAMPLES_DIR / "apache_access.log", "text/plain"),
    ("chrome-history", Path(__file__).parent / "History", "application/x-sqlite3"),
    ("evtx-rs", SAMPLES_DIR / "system.evtx", "application/octet-stream"),
    ("plaso", SAMPLES_DIR / "CMD.EXE-087B4001.pf", "application/octet-stream"),
]


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def main() -> None:
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="ingest-test-1"
    )
    log(f"login OK (mfa_path={mfa_path})")
    access_token = tokens["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    resp = client.post(
        "/api/cases",
        json={
            "title": "Full ingestion test — all 5 parsers",
            "description": (
                "Real login + upload/finalize per parser type, verified against OpenSearch."
            ),
            "classification": "UNCLASSIFIED",
        },
    )
    log("create_case ->", resp.status_code, resp.text[:500])
    resp.raise_for_status()
    case = resp.json()
    case_id = case["id"]
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
        presigned_url = upload["presignedUrl"]

        # verify=auth_helpers.CA_BUNDLE: presigned_url is now
        # https://192.168.5.13:9444/... (nginx's TLS-terminated MinIO
        # proxy, per MINIO_PUBLIC_ENDPOINT in docker-compose.dev.yml) --
        # needs the same step-ca root trust_dev_stack_step_ca() set up for
        # login, or this PUT hits CERTIFICATE_VERIFY_FAILED same as the
        # login flow did (see poc/tls_lan_https/).
        put_resp = httpx.put(presigned_url, content=data, timeout=60, verify=auth_helpers.CA_BUNDLE)
        log(f"{label} PUT to MinIO ->", put_resp.status_code)
        put_resp.raise_for_status()

        resp = client.post(
            f"/api/evidence/upload/finalize/{evidence_id}",
            json={"client_sha256": sha256},
        )
        log(f"{label} finalize ->", resp.status_code, resp.text[:300])
        resp.raise_for_status()

        results.append({"label": label, "evidence_id": evidence_id, "filename": path.name})

    out_path = Path(__file__).parent / "evidence_ids.json"
    out_path.write_text(json.dumps({"case_id": case_id, "evidence": results}, indent=2))
    log(f"wrote {out_path}")
    print(json.dumps({"case_id": case_id, "evidence": results}))


if __name__ == "__main__":
    main()
