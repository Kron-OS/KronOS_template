"""PoC: verifies the parse-stage retry pipeline (ERROR -> PARSING re-entry via
retry_parse) against the real, live dev stack -- real login, real Postgres,
real MinIO, real OpenSearch, real Celery workers.

Confirms the two things this feature adds, end to end:

1. A terminal parse-stage error (no matching parser for the uploaded
   content) lands on ERROR/no_parser_found with retryAction=None, and
   POST /retry-parse correctly refuses it (422) -- an unsupported format
   can't change on retry, so no retry is offered.
2. A genuinely transient parse-stage failure (real OpenSearch briefly
   stopped mid-flight) lands on ERROR/ingest_failed with
   retryAction="parse" instead of leaving evidence stuck in PARSING, and
   POST /retry-parse successfully re-parses the SAME already-promoted
   evidence-bucket object once OpenSearch is back -- no re-upload, no
   re-scan needed, since intake already succeeded and only indexing failed.

Run: source ~/venv/bin/activate && python poc/evidence_parse_retry/run_poc.py
Requires the real, rebuilt dev stack up (kronos.local), with celery-worker
consuming q.parse.fast/q.index and this session's retry_parse code deployed.
"""
from __future__ import annotations

import hashlib
import socket
import subprocess
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
_JSON_CONTENT = b'{"Records": [{"eventTime": "2024-01-15T10:30:00Z", "eventName": "Describe", "eventSource": "ec2.amazonaws.com", "userIdentity": {"userName": "alice", "accountId": "123"}}]}'
# Content no registered parser will claim, but that DOES pass intake
# validation -- must be a real fight through _detect_parser, not
# MagicByteValidator. .csv is one of MagicByteValidator's _TEXT_EXTENSIONS
# (no magic-byte check at all), but no parser's supports() ever checks
# .csv (nginx wants .log/.txt, cloudtrail/suricata want .json/.jsonl,
# chrome_history/evtx/zip/plaso all key on binary magic bytes) -- verified
# by reading every parser's supports() in src/external/parsers/, not
# guessed. A first attempt using "mystery.bin" instead hit
# MagicByteValidator's own rejection (validation_failed) before ever
# reaching parser detection -- the real, intended terminal reason for that
# case, but not the no_parser_found path this scenario needs to exercise.
_UNRECOGNIZED_CONTENT = b"col_a,col_b,col_c\nnot,any,known,forensic,format\n"

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
    timeout: float = 60.0,
    stop_states: tuple[str, ...] = ("ERROR", "COMPLETE"),
) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        resp = client.get(f"{BACKEND}/api/cases/{case_id}/evidence")
        for item in resp.json()["items"]:
            if item["id"] == evidence_id:
                last = item
                if item["state"] in stop_states:
                    return item
        time.sleep(1)
    return last


def upload_and_finalize(client: httpx.Client, case_id: str, filename: str, content: bytes) -> str:
    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": filename,
            "contentType": "application/octet-stream",
            "sizeBytes": len(content),
            "caseId": case_id,
        },
    )
    evidence_id = resp.json()["evidenceId"]
    presigned_url = resp.json()["presignedUrl"]
    put_resp = httpx.put(presigned_url, content=content, timeout=30, verify=auth_helpers.CA_BUNDLE)
    check(f"real PUT to MinIO succeeds ({filename})", put_resp.status_code < 300, str(put_resp.status_code))
    client.post(
        f"/api/evidence/upload/finalize/{evidence_id}",
        json={"client_sha256": sha256_of(content)},
    )
    return evidence_id


def main() -> None:
    tokens, _, _ = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="evidence-parse-retry-poc"
    )
    client = httpx.Client(
        base_url=BACKEND,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        verify=auth_helpers.CA_BUNDLE,
        timeout=30,
    )

    resp = client.post(
        "/api/cases",
        json={"title": "evidence_parse_retry PoC", "description": "real test"},
    )
    check("real case created", resp.status_code == 201, str(resp.status_code))
    case_id = resp.json()["id"]

    # -------------------------------------------------------------------
    # 1. Terminal parse-stage error: no matching parser -- must NOT be
    #    retryable via retry-parse.
    # -------------------------------------------------------------------
    print("\n=== 1. Terminal parse-stage error (no_parser_found) — must NOT be retryable ===")
    unrecognized_id = upload_and_finalize(
        client, case_id, "mystery.csv", _UNRECOGNIZED_CONTENT
    )
    final = poll_evidence(client, case_id, unrecognized_id)
    check("lands on ERROR", final.get("state") == "ERROR", final.get("state"))
    check(
        "error reason is no_parser_found",
        final.get("errorReason") == "no_parser_found",
        final.get("errorReason"),
    )
    check(
        "retryAction is None (terminal)",
        final.get("retryAction") is None,
        final.get("retryAction"),
    )
    refuse_resp = client.post(f"/api/evidence/{unrecognized_id}/retry-parse")
    check(
        "retry-parse refuses a terminal reason (422)",
        refuse_resp.status_code == 422,
        f"status={refuse_resp.status_code} body={refuse_resp.text[:200]}",
    )

    # -------------------------------------------------------------------
    # 2. Transient parse-stage error: real OpenSearch briefly stopped --
    #    retryable, retry succeeds against the SAME evidence-bucket object.
    # -------------------------------------------------------------------
    print("\n=== 2. Transient parse-stage error (real OpenSearch briefly stopped) — retryable ===")
    # Stop OpenSearch BEFORE the upload -- intake (validate/scan/hash/promote)
    # needs only MinIO/Postgres, so it still completes for real and reaches
    # RECEIVED/dispatches parsing; only the parse/index stage that follows
    # actually needs OpenSearch, guaranteeing it's the one that fails (a
    # first attempt that stopped OpenSearch AFTER finalize raced with a
    # 1-record parse that finished indexing before the container was even
    # down, reaching COMPLETE and invalidating the whole scenario).
    print("stopping docker-opensearch-1 ...")
    subprocess.run(["docker", "stop", "docker-opensearch-1"], check=True, capture_output=True)
    try:
        transient_id = upload_and_finalize(client, case_id, "cloudtrail.json", _JSON_CONTENT)
        intake_done = poll_evidence(
            client,
            case_id,
            transient_id,
            timeout=30,
            stop_states=("RECEIVED", "PARSING", "COMPLETE", "ERROR"),
        )
        check(
            "intake completes for real (independent of OpenSearch) before parsing hits the outage",
            intake_done.get("state") in ("RECEIVED", "PARSING", "COMPLETE"),
            intake_done.get("state"),
        )

        # Fast parse task retries 3x/30s -- allow enough time for it to
        # actually exhaust retries against the real, still-down cluster.
        parse_final = poll_evidence(client, case_id, transient_id, timeout=180)
        check(
            "evidence lands on ERROR (not stuck in PARSING) while OpenSearch is down",
            parse_final.get("state") == "ERROR",
            parse_final.get("state"),
        )
        check(
            "error reason is ingest_failed",
            parse_final.get("errorReason") == "ingest_failed",
            parse_final.get("errorReason"),
        )
        check(
            "retryAction is parse (retryable, parse-stage)",
            parse_final.get("retryAction") == "parse",
            parse_final.get("retryAction"),
        )
    finally:
        print("restarting docker-opensearch-1 ...")
        subprocess.run(["docker", "start", "docker-opensearch-1"], check=True, capture_output=True)
        # OpenSearch takes noticeably longer than a TCP accept to actually
        # serve requests (cluster recovery) -- poll the real HTTPS port
        # instead of guessing a sleep duration (same lesson as the ClamAV
        # outage PoC in poc/evidence_intake_async/).
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                with socket.create_connection(("localhost", 9200), timeout=2):
                    break
            except OSError:
                time.sleep(3)
        else:
            print("WARNING: opensearch did not become reachable within 120s")
        # Give the cluster health past yellow/red a few more seconds after
        # the port opens before the backend's own bulk client retries succeed.
        time.sleep(15)

    retry_resp = client.post(f"/api/evidence/{transient_id}/retry-parse")
    check(
        "retry-parse accepts a retryable parse-stage reason (202)",
        retry_resp.status_code == 202,
        f"status={retry_resp.status_code} body={retry_resp.text[:200]}",
    )
    retried_final = poll_evidence(client, case_id, transient_id, timeout=90)
    check(
        "retry-parse succeeds once OpenSearch is back -- reaches COMPLETE",
        retried_final.get("state") == "COMPLETE",
        retried_final.get("state"),
    )

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
