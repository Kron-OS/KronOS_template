"""Poll the tar-unwrapping test's evidence to a terminal state, then fetch
every real document from OpenSearch and verify:
  - image.dd's real files (alpha.txt/bravo.txt/sub/charlie.txt) produced
    real timeline events with the exact real @timestamp set on each file
    (not just "some events came out") -- the literal reproduction of "zero
    events extracted" being fixed, shown as non-zero with real content.
  - memory.dmp produced ZERO records (no parser yet, roadmap E5) but did
    NOT cause an error/placeholder marker or crash the whole evidence to
    ERROR -- graceful "no parser yet" handling, not a silent vanish (the
    tar_member_no_parser log line is the trace of record).
  - every record's kronos.source_path/container_sha256 provenance is correct.
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

auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "http://localhost:8000"
OS_BASE = "https://localhost:9200"
OS_AUTH = ("admin", "admin")
ORG_ALIAS = "kronos-dev"

_ERROR_MARKERS = ("plaso:placeholder", "no events extracted", "parsing error", "parse error")

# Real, distinct mtimes set in build_fixture.py -- epoch microseconds for
# Plaso's own internal representation (see firecracker.py's
# datetime.fromtimestamp(ts_raw / 1_000_000, tz=UTC) handling).
EXPECTED_FILE_EVENTS = {
    "alpha.txt": "2024-01-15T10:00:00",
    "bravo.txt": "2024-03-22T14:30:00",
    "sub/charlie.txt": "2024-06-05T08:15:00",
}


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def poll_to_terminal(client: httpx.Client, case_id: str) -> list[dict[str, Any]]:
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
    # Real, observed race (not a KronOS bug): the evidence state flips to
    # COMPLETE the instant the celery task's own OpenSearch _bulk call
    # returns, but OpenSearch's default 1s index refresh_interval means the
    # just-indexed docs aren't always immediately searchable yet. A couple
    # of retries with a short sleep is enough in practice.
    for attempt in range(5):
        resp = client.post(
            f"{OS_BASE}/{index_pattern}/_search",
            json={"size": 10000, "sort": [{"kronos.parser": "asc"}, {"@timestamp": "asc"}]},
            auth=OS_AUTH,
        )
        resp.raise_for_status()
        hits = [hit["_source"] for hit in resp.json()["hits"]["hits"]]
        if hits:
            return hits
        log(f"fetch_all_docs: 0 hits on attempt {attempt + 1}, retrying after refresh delay")
        time.sleep(2)
    return []


def main() -> None:
    with open(Path(__file__).parent / "evidence_id.json") as f:
        prior = json.load(f)
    case_id = prior["case_id"]
    evidence_sha = prior["sha256"]

    tokens, _, _ = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="tar-unwrap-poll-1"
    )
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    final_states = poll_to_terminal(client, case_id)
    (Path(__file__).parent / "final_states.json").write_text(json.dumps(final_states, indent=2))

    docs = fetch_all_docs(case_id)
    log(f"fetched {len(docs)} real documents for case_id={case_id}")

    by_parser: dict[str, int] = {}
    flagged = []
    found_source_paths: dict[str, list[dict[str, Any]]] = {}
    container_mismatches = []

    for src in docs:
        parser = src.get("kronos", {}).get("parser", "UNKNOWN")
        by_parser[parser] = by_parser.get(parser, 0) + 1

        haystack = " ".join(str(src.get(k, "")) for k in ("message", "data_type")).lower()
        if any(m in haystack for m in _ERROR_MARKERS):
            flagged.append({"parser": parser, "message": src.get("message")})

        container_sha = src.get("kronos", {}).get("container_sha256")
        source_path = src.get("kronos", {}).get("source_path")
        if source_path:
            if container_sha != evidence_sha:
                container_mismatches.append({"parser": parser, "container_sha256": container_sha})
            found_source_paths.setdefault(source_path, []).append(
                {"timestamp": src.get("@timestamp"), "data_type": src.get("data_type")}
            )

    log(f"by parser: {by_parser}")
    log(f"distinct source_paths: {sorted(found_source_paths)}")
    log(f"flagged parsing-error markers: {len(flagged)}")
    log(f"container_sha256 mismatches: {len(container_mismatches)}")

    # image.dd's real files must show up with the exact real path, tagged
    # with image.dd/<container>'s own source_path prefix (TarArchiveParser
    # stamps "image.dd/<in-image path>").
    real_file_hits = {}
    for rel_path, expected_ts in EXPECTED_FILE_EVENTS.items():
        expected_source_path = f"image.dd/{rel_path}"
        matches = found_source_paths.get(expected_source_path, [])
        ts_match = any(str(m["timestamp"]).startswith(expected_ts) for m in matches)
        real_file_hits[rel_path] = {
            "expected_source_path": expected_source_path,
            "event_count": len(matches),
            "correct_timestamp_present": ts_match,
        }

    memory_dmp_records = by_parser  # memory.dmp has no parser -> contributes 0 to every parser bucket
    memory_dmp_no_records = not any(
        sp.startswith("memory.dmp") for sp in found_source_paths
    )

    all_files_recovered = all(
        h["event_count"] > 0 and h["correct_timestamp_present"] for h in real_file_hits.values()
    )

    summary = {
        "case_id": case_id,
        "total_documents": len(docs),
        "by_parser": by_parser,
        "real_file_hits": real_file_hits,
        "all_image_dd_files_recovered_with_correct_timestamps": all_files_recovered,
        "memory_dmp_produced_zero_records": memory_dmp_no_records,
        "flagged_parsing_errors": flagged,
        "container_sha256_mismatches": container_mismatches,
        "final_evidence_state": final_states[0]["state"] if final_states else None,
        "verdict": (
            "PASS"
            if all_files_recovered
            and memory_dmp_no_records
            and not flagged
            and not container_mismatches
            and final_states
            and final_states[0]["state"] == "COMPLETE"
            else "FAIL"
        ),
    }
    (Path(__file__).parent / "verification.json").write_text(json.dumps(summary, indent=2))
    log("verdict:", summary["verdict"])
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
