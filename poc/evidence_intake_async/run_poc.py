"""PoC: verifies the async intake pipeline (start_intake/process_intake split)
against the real, live dev stack -- real login, real Postgres, real MinIO,
real ClamAV, real Celery worker consuming q.intake.

Confirms the reported bug's exact hypothesis and the fix, end to end:

1. A "premature finalize" (client calls finalize before the object is
   actually visible in MinIO) now gets a clean 422 and evidence stays in
   UPLOADING -- not silently orphaned in SCANNING with a raw 500, which is
   what the old synchronous finalize_upload did (confirmed by reading
   src/application/evidence_intake.py before this fix: only ValidationError
   was caught around the scan/hash steps). The client can just call
   finalize again after the real upload completes -- no separate recovery
   needed for this case.
2. A terminal error (a real EICAR upload) lands on ERROR with
   isRetryable=false, and POST /retry-intake correctly refuses it (422) --
   retrying the exact same infected bytes can never produce a different
   verdict.
3. A genuinely transient failure (ClamAV briefly stopped mid-flight) lands
   on ERROR with a retryable reason instead of orphaning evidence in
   SCANNING forever, and POST /retry-intake successfully completes intake
   from the same still-quarantined object once ClamAV is back -- no
   re-upload needed.

Run: source ~/venv/bin/activate && python poc/evidence_intake_async/run_poc.py
Requires the real, rebuilt dev stack up (kronos.local), with celery-worker
consuming q.intake (docker-compose.dev.yml).
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
import auth_helpers  # noqa: E402

auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "https://kronos.local"
_JSON_CONTENT = b'{"Records": []}'
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def poll_evidence(
    client: httpx.Client,
    case_id: str,
    evidence_id: str,
    timeout: float = 30.0,
    stop_on_error: bool = True,
) -> dict:
    """Poll until evidence leaves the "still working" states.

    stop_on_error=False keeps polling THROUGH an ERROR state too -- real
    finding: Celery's own automatic task-level retry (process_intake's
    max_retries=3) can still flip ERROR back to RECEIVED on a later
    attempt, so a caller specifically testing that self-recovery must not
    stop the moment it first observes ERROR, or it will report a false
    failure for a retry that just hasn't happened yet.
    """
    deadline = time.time() + timeout
    last = {}
    settled_states = ("PARSING", "COMPLETE", "RECEIVED") if not stop_on_error else None
    while time.time() < deadline:
        resp = client.get(f"{BACKEND}/api/cases/{case_id}/evidence")
        for item in resp.json()["items"]:
            if item["id"] == evidence_id:
                last = item
                if settled_states is not None:
                    if item["state"] in settled_states:
                        return item
                elif item["state"] not in ("UPLOADING", "SCANNING", "HASHING"):
                    return item
        time.sleep(1)
    return last


def main() -> None:
    tokens, _, _ = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="evidence-intake-async-poc"
    )
    client = httpx.Client(
        base_url=BACKEND,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        verify=auth_helpers.CA_BUNDLE,
        timeout=30,
    )

    resp = client.post(
        "/api/cases",
        json={"title": "evidence_intake_async PoC", "description": "real test"},
    )
    check("real case created", resp.status_code == 201, str(resp.status_code))
    case_id = resp.json()["id"]

    # -------------------------------------------------------------------
    # 1. Premature finalize: object not yet visible in MinIO
    # -------------------------------------------------------------------
    print("\n=== 1. Premature finalize (object not yet in MinIO) ===")
    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": "cloudtrail.json",
            "contentType": "application/json",
            "sizeBytes": len(_JSON_CONTENT),
            "caseId": case_id,
        },
    )
    evidence_id = resp.json()["evidenceId"]
    presigned_url = resp.json()["presignedUrl"]

    # Call finalize BEFORE actually PUTting the file -- the exact reported bug.
    premature_resp = client.post(
        f"/api/evidence/upload/finalize/{evidence_id}",
        json={"client_sha256": sha256_of(_JSON_CONTENT)},
    )
    check(
        "premature finalize returns a clean 422 (not a raw 500)",
        premature_resp.status_code == 422,
        f"status={premature_resp.status_code} body={premature_resp.text[:200]}",
    )

    state_resp = client.get(f"/api/cases/{case_id}/evidence")
    state = next(i for i in state_resp.json()["items"] if i["id"] == evidence_id)["state"]
    check(
        "evidence still in UPLOADING, not orphaned in SCANNING",
        state == "UPLOADING",
        state,
    )

    # Now actually upload, then retry the SAME finalize call.
    put_resp = httpx.put(presigned_url, content=_JSON_CONTENT, timeout=30, verify=auth_helpers.CA_BUNDLE)
    check("real PUT to MinIO succeeds", put_resp.status_code < 300, str(put_resp.status_code))

    retry_resp = client.post(
        f"/api/evidence/upload/finalize/{evidence_id}",
        json={"client_sha256": sha256_of(_JSON_CONTENT)},
    )
    check(
        "finalize succeeds once the object is really there (202, hand-off)",
        retry_resp.status_code == 202,
        str(retry_resp.status_code),
    )
    final = poll_evidence(client, case_id, evidence_id)
    check(
        "evidence reaches RECEIVED (or further -- the autonomous pipeline "
        "keeps going into PARSING on its own, per CLAUDE.md §E)",
        final.get("state") in ("RECEIVED", "PARSING", "COMPLETE"),
        final.get("state"),
    )

    # -------------------------------------------------------------------
    # 2. Terminal error: real EICAR -- not retryable
    # -------------------------------------------------------------------
    print("\n=== 2. Terminal error (real EICAR) — must NOT be retryable ===")
    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": "eicar.txt",
            "contentType": "text/plain",
            "sizeBytes": len(_EICAR),
            "caseId": case_id,
        },
    )
    eicar_id = resp.json()["evidenceId"]
    httpx.put(resp.json()["presignedUrl"], content=_EICAR, timeout=30, verify=auth_helpers.CA_BUNDLE)
    client.post(
        f"/api/evidence/upload/finalize/{eicar_id}",
        json={"client_sha256": sha256_of(_EICAR)},
    )
    eicar_final = poll_evidence(client, case_id, eicar_id)
    check("EICAR lands on ERROR", eicar_final.get("state") == "ERROR", eicar_final.get("state"))
    check(
        "error reason is infected:*",
        str(eicar_final.get("errorReason", "")).startswith("infected:"),
        eicar_final.get("errorReason"),
    )
    check("isRetryable is false for a terminal reason", eicar_final.get("isRetryable") is False)

    retry_eicar = client.post(f"/api/evidence/{eicar_id}/retry-intake")
    check(
        "retry-intake refuses a terminal reason (422)",
        retry_eicar.status_code == 422,
        f"status={retry_eicar.status_code} body={retry_eicar.text[:200]}",
    )

    # -------------------------------------------------------------------
    # 3. Transient error: ClamAV briefly down -- retryable, retry succeeds
    # -------------------------------------------------------------------
    print("\n=== 3. Transient error (real ClamAV briefly stopped) — retryable ===")
    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": "cloudtrail2.json",
            "contentType": "application/json",
            "sizeBytes": len(_JSON_CONTENT),
            "caseId": case_id,
        },
    )
    transient_id = resp.json()["evidenceId"]
    httpx.put(resp.json()["presignedUrl"], content=_JSON_CONTENT, timeout=30, verify=auth_helpers.CA_BUNDLE)

    print("stopping docker-clamav-1 ...")
    subprocess.run(["docker", "stop", "docker-clamav-1"], check=True, capture_output=True)
    try:
        client.post(
            f"/api/evidence/upload/finalize/{transient_id}",
            json={"client_sha256": sha256_of(_JSON_CONTENT)},
        )
        transient_final = poll_evidence(client, case_id, transient_id, timeout=60)
        check(
            "evidence lands on ERROR (not orphaned in SCANNING) while ClamAV is down",
            transient_final.get("state") == "ERROR",
            transient_final.get("state"),
        )
        check(
            "error reason is retryable (not a terminal one)",
            transient_final.get("isRetryable") is True,
            transient_final.get("errorReason"),
        )
    finally:
        print("restarting docker-clamav-1 ...")
        subprocess.run(["docker", "start", "docker-clamav-1"], check=True, capture_output=True)
        # Real finding: a fixed 8s sleep here was not enough -- clamd reloads
        # its ~86 MB virus database on every restart, observed taking ~15s
        # in this run (confirmed via docker logs timestamps), not the couple
        # of seconds it takes to just accept TCP connections again. Poll
        # real connectivity instead of guessing a sleep duration.
        import socket as _socket

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with _socket.create_connection(("localhost", 3310), timeout=2):
                    break
            except OSError:
                time.sleep(2)
        else:
            print("WARNING: clamav did not become reachable within 60s")

    retry_resp = client.post(f"/api/evidence/{transient_id}/retry-intake")
    check(
        "retry-intake accepts a retryable reason (202)",
        retry_resp.status_code == 202,
        f"status={retry_resp.status_code} body={retry_resp.text[:200]}",
    )
    retried_final = poll_evidence(client, case_id, transient_id, timeout=90, stop_on_error=False)
    check(
        "retry-intake succeeds once ClamAV is back -- reaches RECEIVED (or further)",
        retried_final.get("state") in ("RECEIVED", "PARSING", "COMPLETE"),
        retried_final.get("state"),
    )

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
