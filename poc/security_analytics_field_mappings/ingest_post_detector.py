"""Real test of a hypothesis formed while measuring C1: OpenSearch Security
Analytics doc-level monitors (what a Detector creates internally) appear to
evaluate only NEWLY-INDEXED documents after the monitor's own creation/
watermark, not pre-existing historical data already in the index pattern --
confirmed empirically (poc/security_analytics_field_mappings/README.md,
"Finding 5"): 0 findings after 80s/8 scheduled 1-min runs against data that a
raw query_string proves DOES match real rule logic.

This re-uploads the SAME real system.evtx sample as NEW evidence into the
SAME case (same index pattern, so the already-created detector's
`indices` input still covers it) to see whether newly-arriving real
forensic data DOES produce findings, isolating "detector/mapping doesn't
work" from "detector only sees forward-looking data".
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
SAMPLE = REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "system.evtx"


def log(*a: object) -> None:
    print(*a, file=sys.stderr)


def main() -> None:
    case_id = json.loads((Path(__file__).parent / "evidence_ids.json").read_text())["case_id"]
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="c1-sa-mapping-postdet"
    )
    log(f"login OK (mfa_path={mfa_path})")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    data = SAMPLE.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": "system_post_detector.evtx",
            "contentType": "application/octet-stream",
            "sizeBytes": len(data),
            "caseId": case_id,
        },
    )
    log("upload/request ->", resp.status_code, resp.text[:300])
    resp.raise_for_status()
    upload = resp.json()
    evidence_id = upload["evidenceId"]
    put_resp = httpx.put(upload["presignedUrl"], content=data, timeout=60, verify=auth_helpers.CA_BUNDLE)
    log("PUT to MinIO ->", put_resp.status_code)
    put_resp.raise_for_status()

    resp = client.post(f"/api/evidence/upload/finalize/{evidence_id}", json={"client_sha256": sha256})
    log("finalize ->", resp.status_code, resp.text[:300])
    resp.raise_for_status()

    for i in range(60):
        resp = client.get(f"/api/cases/{case_id}/evidence")
        resp.raise_for_status()
        body = resp.json()
        items = body["items"] if isinstance(body, dict) else body
        this = next((e for e in items if e["filename"] == "system_post_detector.evtx"), None)
        state = this["state"] if this else "?"
        log(f"poll {i}: {state}")
        if state in ("COMPLETE", "ERROR"):
            break
        time.sleep(5)

    print(json.dumps({"case_id": case_id, "evidence_id": evidence_id, "state": state}))


if __name__ == "__main__":
    main()
