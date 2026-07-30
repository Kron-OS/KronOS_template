"""Extend the post-detector-creation re-ingest test (see ingest_post_detector.py's
docstring, "Finding 5") from windows-only to cloudtrail and network, to get real
post-detector-creation findings for those log types too.

Empirically confirmed (this C1 pass, README "Finding 5"/"Finding 6"): OpenSearch
Security Analytics doc-level monitors only evaluate documents indexed AFTER the
monitor's own creation/watermark time -- the original ingest_samples.py uploads
(evidence_ids.json) all landed BEFORE the cloudtrail/network detectors existed,
so those detectors legitimately see 0 eligible historical documents, regardless
of whether their rules would otherwise match. This re-uploads the SAME real
aws_cloudtrail.jsonl and eve.json samples as NEW evidence into the SAME case
(same index pattern, already covered by kronos-poc-cloudtrail-detector /
kronos-poc-network-detector) to get real, fresh, post-detector-creation
findings for those two log types.
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
    ("cloudtrail", SAMPLES_DIR / "aws_cloudtrail.jsonl", "application/x-ndjson", "aws_cloudtrail_post_detector.jsonl"),
    ("suricata-eve", SAMPLES_DIR / "suricata" / "eve.json", "application/json", "eve_post_detector.json"),
]


def log(*a: object) -> None:
    print(*a, file=sys.stderr)


def main() -> None:
    case_id = json.loads((Path(__file__).parent / "evidence_ids.json").read_text())["case_id"]
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="c1-sa-mapping-postdet2"
    )
    log(f"login OK (mfa_path={mfa_path})")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    results = []
    for label, path, content_type, upload_name in FILES:
        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": upload_name,
                "contentType": content_type,
                "sizeBytes": len(data),
                "caseId": case_id,
            },
        )
        log(f"{label} upload/request ->", resp.status_code, resp.text[:300])
        resp.raise_for_status()
        upload = resp.json()
        evidence_id = upload["evidenceId"]
        put_resp = httpx.put(upload["presignedUrl"], content=data, timeout=60, verify=auth_helpers.CA_BUNDLE)
        log(f"{label} PUT to MinIO ->", put_resp.status_code)
        put_resp.raise_for_status()

        resp = client.post(f"/api/evidence/upload/finalize/{evidence_id}", json={"client_sha256": sha256})
        log(f"{label} finalize ->", resp.status_code, resp.text[:300])
        resp.raise_for_status()
        results.append({"label": label, "evidence_id": evidence_id, "filename": upload_name})

    for i in range(60):
        resp = client.get(f"/api/cases/{case_id}/evidence")
        resp.raise_for_status()
        body = resp.json()
        items = body["items"] if isinstance(body, dict) else body
        states = {
            r["filename"]: next((e["state"] for e in items if e["filename"] == r["filename"]), "?")
            for r in results
        }
        log(f"poll {i}: {states}")
        if all(s in ("COMPLETE", "ERROR") for s in states.values()):
            break
        time.sleep(5)

    print(json.dumps({"case_id": case_id, "results": results, "states": states}))


if __name__ == "__main__":
    main()
