"""Real end-to-end ingestion for C1's field-mapping/rule-coverage gate.

Reuses the exact real-login/upload/finalize pattern already proven in
poc/full_ingestion_test/run_ingest.py (login.py + auth_helpers.py), against
one real sample per log-type-relevant parser:

  - evtx-rs      -> tests/fixtures/samples/real/system.evtx        (windows)
  - cloudtrail   -> tests/fixtures/samples/real/aws_cloudtrail.jsonl (cloudtrail)
  - nginx        -> tests/fixtures/samples/real/apache_access.log  (apache_access/others_web)
  - suricata-eve -> tests/fixtures/samples/real/suricata/eve.json  (network)

Creates ONE new case (so we get one predictable index-pattern
kronos-kronos-dev-case-{case_id}-* to build SA mappings/detectors against),
uploads+finalizes all 4, then polls until every item reaches COMPLETE.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
import auth_helpers  # noqa: E402

auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "http://localhost:8000"
REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "samples" / "real"

FILES = [
    ("evtx-rs", SAMPLES_DIR / "system.evtx", "application/octet-stream"),
    ("cloudtrail", SAMPLES_DIR / "aws_cloudtrail.jsonl", "application/x-ndjson"),
    ("nginx", SAMPLES_DIR / "apache_access.log", "text/plain"),
    ("suricata-eve", SAMPLES_DIR / "suricata" / "eve.json", "application/json"),
]


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def main() -> None:
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="c1-sa-mapping-1"
    )
    log(f"login OK (mfa_path={mfa_path})")
    access_token = tokens["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    resp = client.post(
        "/api/cases",
        json={
            "title": "C1 SA field-mapping + rule-coverage gate",
            "description": "Real samples per log type (windows/cloudtrail/apache_access/network) for OpenSearch Security Analytics coverage measurement.",
            "classification": "UNCLASSIFIED",
        },
    )
    log("create_case ->", resp.status_code, resp.text[:500])
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
        presigned_url = upload["presignedUrl"]

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

    # Poll to COMPLETE.
    for i in range(60):
        resp = client.get(f"/api/cases/{case_id}/evidence")
        resp.raise_for_status()
        body = resp.json()
        items = body["items"] if isinstance(body, dict) else body
        states = {e["filename"]: e["state"] for e in items}
        log(f"poll {i}: {states}")
        if all(s in ("COMPLETE", "ERROR") for s in states.values()):
            break
        time.sleep(5)

    final_path = Path(__file__).parent / "final_states.json"
    final_path.write_text(json.dumps(states, indent=2))
    log(f"wrote {final_path}")
    print(json.dumps({"case_id": case_id, "states": states}))


if __name__ == "__main__":
    main()
