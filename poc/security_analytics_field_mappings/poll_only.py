"""Resume poll-to-COMPLETE for the case already created by ingest_samples.py
(avoids re-uploading after fixing the response-shape bug in the first run)."""

from __future__ import annotations

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


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def main() -> None:
    case_id = json.loads((Path(__file__).parent / "evidence_ids.json").read_text())["case_id"]
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="c1-sa-mapping-poll"
    )
    log(f"login OK (mfa_path={mfa_path})")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    states: dict[str, str] = {}
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

    (Path(__file__).parent / "final_states.json").write_text(json.dumps(states, indent=2))
    print(json.dumps({"case_id": case_id, "states": states}))


if __name__ == "__main__":
    main()
