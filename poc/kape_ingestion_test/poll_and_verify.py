"""Poll the KAPE ingestion test's evidence to COMPLETE, then fetch every real
document from OpenSearch and verify source_path/file.path + container_sha256
provenance for both the ZIP and E01 evidence -- not just doc counts.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

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
OS_BASE = "https://localhost:9200"
OS_AUTH = ("admin", "admin")
ORG_ALIAS = "kronos-dev"

_ERROR_MARKERS = ("plaso:placeholder", "no events extracted", "parsing error", "parse error")


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def poll_to_complete(client: httpx.Client, case_id: str) -> list[dict[str, Any]]:
    terminal = {"COMPLETE", "ERROR"}
    deadline = time.time() + 300
    items: list[dict[str, Any]] = []
    while time.time() < deadline:
        resp = client.get(f"/api/cases/{case_id}/evidence", params={"pageSize": 50})
        resp.raise_for_status()
        items = resp.json()["items"]
        states = {it["filename"]: it["state"] for it in items}
        log(states)
        if items and all(s in terminal for s in states.values()):
            return items
        time.sleep(5)
    raise TimeoutError("evidence did not reach a terminal state in time")


def fetch_all_docs(case_id: str) -> list[dict[str, Any]]:
    index_pattern = f"kronos-{ORG_ALIAS}-case-{case_id}-*"
    client = httpx.Client(verify=False, timeout=30)  # noqa: S501 -- self-signed dev cert
    resp = client.post(
        f"{OS_BASE}/{index_pattern}/_search",
        json={"size": 10000, "sort": [{"kronos.parser": "asc"}, {"@timestamp": "asc"}]},
        auth=OS_AUTH,
    )
    resp.raise_for_status()
    return [hit["_source"] for hit in resp.json()["hits"]["hits"]]


def main() -> None:
    with open(Path(__file__).parent / "evidence_ids.json") as f:
        prior = json.load(f)
    case_id = prior["case_id"]
    by_label = {e["label"]: e for e in prior["evidence"]}

    tokens, _, _ = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="kape-poll-1"
    )
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    final_states = poll_to_complete(client, case_id)
    (Path(__file__).parent / "final_states.json").write_text(json.dumps(final_states, indent=2))

    docs = fetch_all_docs(case_id)
    log(f"fetched {len(docs)} real documents for case_id={case_id}")

    by_parser: dict[str, int] = {}
    flagged = []
    zip_source_paths: set[str] = set()
    e01_source_paths: set[str] = set()
    zip_sha = by_label["kape-zip"]["sha256"]
    e01_sha = by_label["kape-e01"]["sha256"]
    container_mismatches = []

    for src in docs:
        parser = src.get("kronos", {}).get("parser", "UNKNOWN")
        by_parser[parser] = by_parser.get(parser, 0) + 1

        haystack = " ".join(str(src.get(k, "")) for k in ("message", "data_type")).lower()
        if any(m in haystack for m in _ERROR_MARKERS):
            flagged.append({"parser": parser, "message": src.get("message")})

        container_sha = src.get("kronos", {}).get("container_sha256")
        source_path = src.get("kronos", {}).get("source_path")
        if container_sha == zip_sha and source_path:
            zip_source_paths.add(source_path)
        elif container_sha == e01_sha and source_path:
            e01_source_paths.add(source_path)
        elif source_path and container_sha not in (zip_sha, e01_sha):
            container_mismatches.append({"parser": parser, "container_sha256": container_sha})

    log(f"by parser: {by_parser}")
    log(f"zip source_paths: {sorted(zip_source_paths)}")
    log(f"e01 source_paths: {sorted(e01_source_paths)}")
    log(f"flagged parsing-error markers: {len(flagged)}")
    log(f"container_sha256 mismatches: {len(container_mismatches)}")

    expected_zip_paths = {
        "C/Windows/System32/winevt/Logs/System.evtx",
        "C/Windows/Prefetch/CMD.EXE-087B4001.pf",
        "C/Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History",
        "C/inetpub/logs/LogFiles/W3SVC1/u_ex260723.log",
    }
    # The E01's fs:stat events include real directory-listing entries (e.g.
    # "C/Windows/System32") alongside the two real files -- just require the
    # two real file paths to be present among the discovered set, not that
    # every discovered path prefix-matches one of them.
    expected_e01_file_paths = {
        "C/Windows/System32/winevt/Logs/System.evtx",
        "C/Windows/Prefetch/CMD.EXE-087B4001.pf",
    }

    summary = {
        "case_id": case_id,
        "total_documents": len(docs),
        "by_parser": by_parser,
        "zip_source_paths_found": sorted(zip_source_paths),
        "zip_source_paths_expected_present": expected_zip_paths.issubset(zip_source_paths),
        "e01_source_paths_found": sorted(e01_source_paths),
        "e01_source_paths_expected_present": expected_e01_file_paths.issubset(e01_source_paths),
        "flagged_parsing_errors": flagged,
        "container_sha256_mismatches": container_mismatches,
        "verdict": (
            "PASS"
            if not flagged
            and not container_mismatches
            and expected_zip_paths.issubset(zip_source_paths)
            and expected_e01_file_paths.issubset(e01_source_paths)
            else "FAIL"
        ),
    }
    (Path(__file__).parent / "kape_verification.json").write_text(json.dumps(summary, indent=2))
    log("verdict:", summary["verdict"])
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
