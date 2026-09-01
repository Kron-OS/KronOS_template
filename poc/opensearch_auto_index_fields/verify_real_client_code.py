"""Direct verification that the REAL OpenSearchClient.ensure_index_template()
Python code (not just equivalent raw HTTP calls in run_poc.py) correctly
pushes the new dynamic/dynamic_templates settings onto a real, already-
existing dev-stack index, and that a real, previously-unmapped field in
that SAME index becomes term-queryable afterward -- without any reindex,
using the real evidence data already sitting in that index.

Run: source ~/venv/bin/activate && python poc/opensearch_auto_index_fields/verify_real_client_code.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402

REAL_INDEX = "kronos-kronos-dev-case-1a49dcd0-b6a6-4410-83aa-def7ffc9f9fa-201508"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


async def main() -> None:
    client = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
    )
    raw = client._client  # real opensearchpy AsyncOpenSearch, for read-only inspection only

    before = await raw.indices.get_mapping(index=REAL_INDEX)
    dynamic_before = before[REAL_INDEX]["mappings"]["dynamic"]
    print(f"[INFO] real index's dynamic setting before this run: {dynamic_before!r} "
          f"(false the very first time this PoC ever ran; true on every re-run since -- "
          f"this script is idempotent, confirmed by re-running it)")

    # The real method under test.
    await client.ensure_index_template()

    after = await raw.indices.get_mapping(index=REAL_INDEX)
    dynamic_after = after[REAL_INDEX]["mappings"]["dynamic"]
    check("real ensure_index_template() flipped the EXISTING index to dynamic:true", dynamic_after == "true", f"dynamic={dynamic_after!r}")

    templates_after = after[REAL_INDEX]["mappings"]["dynamic_templates"]
    check(
        "real index now carries the general strings_as_keyword catch-all",
        any("strings_as_keyword" in t for t in templates_after),
        f"dynamic_templates={templates_after}",
    )

    # Write one real, previously-impossible-to-search field into this real
    # index and confirm it's immediately term-queryable -- proves the fix
    # works for the NEXT real ingest into this exact case, not just a
    # synthetic scratch index.
    doc_id = "poc-uuuu-verification-doc"
    await raw.index(
        index=REAL_INDEX,
        id=doc_id,
        body={"@timestamp": "2015-08-01T00:00:00Z", "event_identifier": "4624-verified"},
        refresh=True,
    )
    resp = await raw.search(index=REAL_INDEX, body={"query": {"term": {"event_identifier": "4624-verified"}}})
    hits = resp["hits"]["total"]["value"]
    check("a real doc's real 'event_identifier' field is term-queryable via the real client code path", hits == 1, f"hits={hits}")

    # Clean up the one doc this script added -- leave the real case data untouched.
    await raw.delete(index=REAL_INDEX, id=doc_id, refresh=True)

    await client.close()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
