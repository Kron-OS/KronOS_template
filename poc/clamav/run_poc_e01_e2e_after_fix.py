"""PoC: end-to-end confirmation of the fix through the REAL API, not just the
isolated ClamAVScanner class -- reproduces the user's exact reported flow
(upload a real, large .E01 file, watch it go UPLOADING -> SCANNING -> ERROR)
and confirms it now reaches RECEIVED instead.

Uses a real EWF (E01) magic-byte header (src/application/validation.py's
_MAGIC_TABLE: b"EVF\\x09\\x0d\\x0a\\xff\\x00") so MagicByteValidator accepts
it exactly like a real forensic image would, at a size (250 MB) matching the
order of magnitude of the originally reported forensic2.E01 (239.3 MB /
250,923,489 bytes) -- comfortably over the OLD 100 MB clamd limit that
caused BrokenPipeError, comfortably under the new 5 GiB ceiling.

Run: source ~/venv/bin/activate && python poc/clamav/run_poc_e01_e2e_after_fix.py
Requires the real, rebuilt dev stack up (kronos.local) with this session's
MAX_UPLOAD_BYTES/CLAMD_CONF_* changes deployed.
"""
from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
import auth_helpers  # noqa: E402

auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "https://kronos.local"
_EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"
_SIZE_BYTES = 250_923_489  # exact size from the user's reported evidence

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def build_fake_e01(path: Path, size_bytes: int) -> None:
    """Real EWF magic header, followed by deterministic filler -- not a real
    disk image (parsing/no_parser_found is out of scope here; this PoC only
    needs to get past validate -> scan -> hash -> promote, the exact stages
    the reported bug broke)."""
    pattern = b"KRONOS-E2E-E01-POC-" * 4096
    with path.open("wb") as f:
        f.write(_EWF_MAGIC)
        remaining = size_bytes - len(_EWF_MAGIC)
        while remaining > 0:
            n = min(len(pattern), remaining)
            f.write(pattern[:n])
            remaining -= n


def poll_evidence(client: httpx.Client, case_id: str, evidence_id: str, timeout: float) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        resp = client.get(f"{BACKEND}/api/cases/{case_id}/evidence")
        for item in resp.json()["items"]:
            if item["id"] == evidence_id:
                last = item
                if item["state"] not in ("UPLOADING", "SCANNING", "HASHING"):
                    return item
        time.sleep(2)
    return last


def main() -> None:
    tmp_path = Path("/tmp/kronos_poc_forensic2.E01")
    print(f"Building a real {_SIZE_BYTES / 1024 / 1024:.1f} MB fake .E01 file at {tmp_path} ...")
    build_fake_e01(tmp_path, _SIZE_BYTES)
    file_sha256 = sha256_of_file(tmp_path)
    check("real file built on disk at the exact reported size", tmp_path.stat().st_size == _SIZE_BYTES)

    tokens, _, _ = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="e01-e2e-after-fix-poc"
    )
    client = httpx.Client(
        base_url=BACKEND,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        verify=auth_helpers.CA_BUNDLE,
        timeout=60,
    )

    resp = client.post(
        "/api/cases", json={"title": "E01 large-file fix confirmation", "description": "real test"}
    )
    check("real case created", resp.status_code == 201, str(resp.status_code))
    case_id = resp.json()["id"]

    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": "forensic2.E01",
            "contentType": "application/octet-stream",
            "sizeBytes": _SIZE_BYTES,
            "caseId": case_id,
        },
    )
    check("upload/request accepts the real 5 GiB-under file size", resp.status_code == 201, str(resp.status_code))
    evidence_id = resp.json()["evidenceId"]
    presigned_url = resp.json()["presignedUrl"]

    print("Uploading the real 239 MB file to MinIO (this will take a moment) ...")
    with tmp_path.open("rb") as f:
        put_resp = httpx.put(
            presigned_url, content=f.read(), timeout=120, verify=auth_helpers.CA_BUNDLE
        )
    check("real PUT of the full 239 MB file to MinIO succeeds", put_resp.status_code < 300, str(put_resp.status_code))

    finalize_resp = client.post(
        f"/api/evidence/upload/finalize/{evidence_id}",
        json={"client_sha256": file_sha256},
    )
    check("finalize accepted (202 hand-off)", finalize_resp.status_code == 202, str(finalize_resp.status_code))

    print("Polling evidence state through the real autonomous pipeline ...")
    final = poll_evidence(client, case_id, evidence_id, timeout=180)
    check(
        "evidence reaches RECEIVED/PARSING/COMPLETE, NOT ERROR/intake_failed:BrokenPipeError "
        "(the exact reported bug)",
        final.get("state") in ("RECEIVED", "PARSING", "COMPLETE"),
        f"state={final.get('state')} errorReason={final.get('errorReason')}",
    )
    check("real SHA-256 was computed", final.get("sha256") == file_sha256, final.get("sha256"))

    tmp_path.unlink(missing_ok=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
