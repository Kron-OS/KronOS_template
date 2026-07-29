"""PoC: exercise the real src/adapter/opensearch/client.py against a real
OpenSearch 2.11.1 node (kronos-poc-opensearch container), using the
opensearch-py version pip actually resolves from pyproject.toml's
`opensearch-py>=2.6` constraint.

This does NOT reimplement the client - it imports and calls the exact
class KronOS ships (OpenSearchClient), to check whether the code as
written actually works against opensearch-py's installed version and a
real server, not just "looks right".

Run: source ~/venv/bin/activate && python poc/opensearch/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402

INDEX = "kronos-poc-testorg-case-0000-202607"


async def main() -> None:
    import opensearchpy

    print(f"opensearch-py version: {opensearchpy.__version__}")

    client = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 19200}],
        http_auth=None,
        use_ssl=False,
        verify_certs=False,
        timeout=30,
    )

    print("\n--- ensure_index_template() ---")
    try:
        await client.ensure_index_template()
        print("OK")
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {type(exc).__name__}: {exc}")

    print("\n--- ensure_ism_policy() ---")
    try:
        await client.ensure_ism_policy()
        print("OK")
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {type(exc).__name__}: {exc}")

    print("\n--- ensure_tenant_role() ---")
    try:
        await client.ensure_tenant_role(org_id="test-org-id", org_alias="testorg")
        print("OK")
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {type(exc).__name__}: {exc}")

    print("\n--- bulk_index() with a plain ECS-shaped doc ---")
    doc = {
        "@timestamp": "2026-07-21T10:00:00Z",
        "message": "PoC: plain log doc ingested directly (not via Plaso)",
        "event": {"kind": "event", "category": "process", "type": "info", "outcome": "success"},
        "host": {"name": "poc-host", "os": {"name": "linux"}},
        "kronos": {
            "evidence_id": "00000000-0000-0000-0000-000000000001",
            "case_id": "00000000-0000-0000-0000-00000000000c",
            "org_id": "test-org-id",
            "sha256": "deadbeef",
            "parser": "poc-manual",
            "parser_version": "0",
            "record_index": 0,
            "ingest_timestamp": "2026-07-21T10:00:00Z",
        },
    }
    try:
        indexed = await client.bulk_index([(INDEX, "poc-doc-1", doc)])
        print(f"bulk_index returned indexed_count={indexed}")
    except Exception as exc:  # noqa: BLE001
        print(f"FAILED: {type(exc).__name__}: {exc}")

    # Give ES a moment then verify the doc is actually queryable (refresh + get).
    await client._client.indices.refresh(index=INDEX)
    got = await client._client.get(index=INDEX, id="poc-doc-1")
    print("\n--- GET back the indexed doc ---")
    print(got["_source"])

    search = await client._client.search(index=INDEX, body={"query": {"match_all": {}}})
    print(f"\n--- search hit count: {search['hits']['total']} ---")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
