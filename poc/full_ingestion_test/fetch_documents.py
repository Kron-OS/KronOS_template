"""Fetch the real indexed documents for the ingestion-test case straight from
OpenSearch and save them to disk, so ingestion/parsing correctness can be
verified from actual content -- not just the `kronos.parser` doc-count
aggregation run_ingest.py's poll step already checks.

Counting documents is not the same as verifying they parsed correctly: a
parser can emit a "placeholder"/error record (real example: Plaso's own
`kronos-plaso-worker.py` emits a `data_type: "plaso:placeholder"` event with
message "Plaso: no events extracted from ..." when extraction produces
nothing -- see docker/plaso/kronos-plaso-worker.py:203-212) and that still
counts as a document in the aggregation, hiding a real parsing failure
behind a healthy-looking doc count. This script pulls every real document
and flags anything that looks like a failure marker rather than real
forensic content.

Usage: reads case_id from evidence_ids.json (written by run_ingest.py)
unless one is passed as the first CLI arg.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import httpx

OS_BASE = "https://localhost:9200"
OS_AUTH = ("admin", "admin")
ORG_ALIAS = "kronos-dev"

# Heuristics for "this document represents a parsing failure, not real
# content" -- deliberately broad (case-insensitive substring, not an exact
# match) since different parsers/tools phrase failures differently and a
# missed real failure is worse than one false-positive flag to eyeball.
_ERROR_MARKERS = ("plaso:placeholder", "no events extracted", "parsing error", "parse error")


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def fetch_all(client: httpx.Client, case_id: str) -> list[dict[str, Any]]:
    """Return every document across the case's (possibly many monthly)
    indices. 223 real docs in the run this was built against -- well under
    OpenSearch's default 10000 result-window, so a single non-scrolled
    search is sufficient; would need `scroll`/`search_after` past that."""
    index_pattern = f"kronos-{ORG_ALIAS}-case-{case_id}-*"
    resp = client.post(
        f"{OS_BASE}/{index_pattern}/_search",
        json={"size": 10000, "sort": [{"kronos.parser": "asc"}, {"@timestamp": "asc"}]},
        auth=OS_AUTH,
    )
    resp.raise_for_status()
    body = resp.json()
    return [
        {"_index": hit["_index"], "_id": hit["_id"], "_source": hit["_source"]}
        for hit in body["hits"]["hits"]
    ]


def flag_errors(docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the subset of docs whose content looks like a parse failure
    marker rather than real forensic data."""
    flagged = []
    for doc in docs:
        src = doc["_source"]
        # Deliberately only the normalized `message`/`data_type` fields, not
        # raw `event.original` -- real CloudTrail/nginx content legitimately
        # contains the word "error" (HTTP error codes, AWS errorCode/
        # errorMessage) and would false-positive on the raw text.
        haystack = " ".join(str(src.get(k, "")) for k in ("message", "data_type")).lower()
        if any(marker in haystack for marker in _ERROR_MARKERS):
            flagged.append(
                {
                    "_index": doc["_index"],
                    "_id": doc["_id"],
                    "parser": src.get("kronos", {}).get("parser"),
                    "message": src.get("message"),
                    "data_type": src.get("data_type"),
                }
            )
    return flagged


def main() -> None:
    case_id = sys.argv[1] if len(sys.argv) > 1 else None
    if case_id is None:
        with open(Path(__file__).parent / "evidence_ids.json") as f:
            case_id = json.load(f)["case_id"]

    client = httpx.Client(verify=False, timeout=30)  # noqa: S501 -- self-signed dev cert
    docs = fetch_all(client, case_id)
    log(f"fetched {len(docs)} real documents for case_id={case_id}")

    by_parser: dict[str, int] = {}
    for doc in docs:
        parser = doc["_source"].get("kronos", {}).get("parser", "UNKNOWN")
        by_parser[parser] = by_parser.get(parser, 0) + 1
    log(f"by parser: {by_parser}")

    flagged = flag_errors(docs)
    log(f"flagged as parsing-error/placeholder markers: {len(flagged)}")
    for f in flagged:
        log(f"  [{f['parser']}] {f['_index']}/{f['_id']}: {f['message'] or f['data_type']}")

    out_dir = Path(__file__).parent
    (out_dir / "documents.json").write_text(json.dumps(docs, indent=2, default=str))
    log(f"wrote {out_dir / 'documents.json'} ({len(docs)} docs)")

    summary = {
        "case_id": case_id,
        "total_documents": len(docs),
        "by_parser": by_parser,
        "flagged_parsing_errors": flagged,
        "verdict": "FAIL" if flagged else "PASS",
    }
    (out_dir / "ingestion_verification.json").write_text(json.dumps(summary, indent=2))
    log(f"wrote {out_dir / 'ingestion_verification.json'} -- verdict: {summary['verdict']}")

    print(json.dumps(summary))


if __name__ == "__main__":
    main()
