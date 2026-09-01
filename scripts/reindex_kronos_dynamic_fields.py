"""Retroactively re-derive indexed fields for documents already written
under the pre-Milestone-UUUU mapping (dynamic: false).

Gap Audit Milestone UUUU fixed OpenSearchClient.ensure_index_template()
to push the new dynamic:true + strings_as_keyword catch-all onto every
already-existing kronos-* index automatically, on every ingest -- that
alone makes every FUTURE write into an existing index auto-indexed. It
does NOT retroactively fix documents that were already written before the
mapping was fixed: their unmapped fields were dropped from the index at
write time (though still intact in _source, per the deliberate
dynamic:false design -- nothing was ever silently lost).

_update_by_query re-processes each document's still-intact _source
against the index's CURRENT mapping when it writes the document back --
no re-parse of the original evidence file needed. Verified live against a
real dev-stack index before this script existed
(poc/opensearch_auto_index_fields/).

This is a real, potentially large/slow operation against already-live
production data -- deliberately NOT run automatically on every ingest
(mirrors poc/ecs_schema_hardening/'s own established precedent: "no
reindex was performed... not appropriate to do unattended"). Run this
once, explicitly, after upgrading to a build that includes Milestone
UUUU's mapping fix, only if you want historical (already-parsed) evidence
to become filterable on fields that were previously dropped.

Usage:
    ~/venv/bin/python3 scripts/reindex_kronos_dynamic_fields.py [--dry-run]
        [--index-pattern kronos-*] [--opensearch-url https://localhost:9200]
        [--username admin] [--password admin]
"""
from __future__ import annotations

import argparse
import sys

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="List affected indices, change nothing")
    parser.add_argument("--index-pattern", default="kronos-*")
    parser.add_argument("--opensearch-url", default="https://localhost:9200")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument(
        "--verify-certs",
        action="store_true",
        help="Verify TLS certs (off by default for the dev-stack self-signed cert)",
    )
    args = parser.parse_args()

    client = httpx.Client(
        base_url=args.opensearch_url,
        auth=(args.username, args.password),
        verify=args.verify_certs,
        timeout=120,
    )

    resp = client.get(f"/_cat/indices/{args.index_pattern}", params={"format": "json"})
    resp.raise_for_status()
    indices = [entry["index"] for entry in resp.json()]

    if not indices:
        print(f"No indices match '{args.index_pattern}'. Nothing to do.")
        return

    print(f"{len(indices)} real index(es) match '{args.index_pattern}':")
    for name in indices:
        print(f"  - {name}")

    if args.dry_run:
        print("\n--dry-run: no changes made.")
        return

    print()
    failures = []
    for name in indices:
        resp = client.post(
            f"/{name}/_update_by_query",
            params={"refresh": "true", "conflicts": "proceed"},
            json={"query": {"match_all": {}}},
        )
        if resp.status_code != 200:
            failures.append((name, resp.status_code, resp.text[:300]))
            print(f"[FAIL] {name}: status={resp.status_code} body={resp.text[:200]}")
            continue
        body = resp.json()
        print(
            f"[OK] {name}: updated={body.get('updated', 0)} "
            f"total={body.get('total', 0)} failures={len(body.get('failures', []))}"
        )
        if body.get("failures"):
            failures.append((name, 200, str(body["failures"])[:300]))

    if failures:
        print(f"\n{len(failures)} index(es) had real failures:")
        for name, status, detail in failures:
            print(f"  - {name}: status={status} {detail}")
        sys.exit(1)

    print(f"\nDone. {len(indices)} index(es) re-processed against their current mapping.")


if __name__ == "__main__":
    main()
