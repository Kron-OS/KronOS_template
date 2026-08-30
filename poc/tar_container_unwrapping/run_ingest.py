"""Real end-to-end tar-container-unwrapping test against the live dev-stack
backend: real login -> real case creation -> real upload/finalize of
forensic2.E01 (actually a tar of a real raw ext4 disk image + a placeholder
memory.dmp, see build_fixture.py) -> autonomous pipeline. Reuses
poc/kape_ingestion_test/'s harness pattern verbatim (same real scripted
PKCE login, same dev Keycloak/case-lead account).
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

# kronos.local is the sole authorized domain for this app (docs/lan-dev-access.md).
auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "http://localhost:8000"
# Gap Audit Milestone ZZZ: relocated to tests/fixtures/samples/real/ -- see
# that directory's own NOTICE.md.
FIXTURE = Path(__file__).resolve().parents[2] / "tests/fixtures/samples/real/tar_container/forensic2.E01"


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def main() -> None:
    if not FIXTURE.exists():
        raise SystemExit(f"{FIXTURE} missing -- run build_fixture.py first")

    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="tar-unwrap-1"
    )
    log(f"login OK (mfa_path={mfa_path})")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=120)

    resp = client.post(
        "/api/cases",
        json={
            "title": "Tar-container-unwrapping test (roadmap E1)",
            "description": (
                "Real upload/finalize of a tar archive (misleadingly named "
                "forensic2.E01, exactly mirroring the real incident) "
                "containing a real raw ext4 disk image (image.dd) and a "
                "placeholder memory.dmp -- verifying TarArchiveParser's "
                "recursive unwrap + PlasoParser's new raw-disk-image "
                "routing, both with real source_path provenance."
            ),
            "classification": "UNCLASSIFIED",
        },
    )
    log("create_case ->", resp.status_code, resp.text[:400])
    resp.raise_for_status()
    case_id = resp.json()["id"]
    log(f"case_id={case_id}")

    data = FIXTURE.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    log(f"forensic2.E01 (actually tar): {len(data)} bytes, sha256={sha256[:12]}...")

    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": FIXTURE.name,
            "contentType": "application/octet-stream",
            "sizeBytes": len(data),
            "caseId": case_id,
        },
    )
    log("upload/request ->", resp.status_code, resp.text[:300])
    resp.raise_for_status()
    upload = resp.json()
    evidence_id = upload["evidenceId"]

    put_resp = httpx.put(
        upload["presignedUrl"], content=data, timeout=120, verify=auth_helpers.CA_BUNDLE
    )
    log("PUT to MinIO ->", put_resp.status_code)
    put_resp.raise_for_status()

    resp = client.post(
        f"/api/evidence/upload/finalize/{evidence_id}",
        json={"client_sha256": sha256},
    )
    log("finalize ->", resp.status_code, resp.text[:400])
    resp.raise_for_status()

    out = {"case_id": case_id, "evidence_id": evidence_id, "sha256": sha256, "filename": FIXTURE.name}
    out_path = Path(__file__).parent / "evidence_id.json"
    out_path.write_text(json.dumps(out, indent=2))
    log(f"wrote {out_path}")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
