"""PoC: reproduce bulk_index silent partial-failure bug against real OpenSearch 2.11.1.

This script demonstrates:
1. The current bug: bulk_index returns a reduced count with NO exception when some docs fail.
2. The fixed behavior: bulk_index raises StorageError with per-document failure details.

Run against the live dev stack:
  source ~/venv/bin/activate
  python poc/opensearch_bulk_partial_failure/run_poc.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.opensearch.client import OpenSearchClient
from src.exceptions import StorageError


INDEX_NAME = "kronos-poc-partial-failure"


async def setup_index_with_strict_mapping(client: OpenSearchClient) -> None:
    """Create an index with a strict mapping that will reject mismatched types."""
    mapping = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
        },
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date", "format": "strict_date_time"},  # Strict format
                "message": {"type": "text"},
                "event": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "keyword"},
                    },
                },
                "kronos": {
                    "type": "object",
                    "properties": {
                        "evidence_id": {"type": "keyword"},
                        "case_id": {"type": "keyword"},
                        "org_id": {"type": "keyword"},
                        "record_index": {"type": "long"},  # Strict: must be integer, no coercion
                    },
                },
            },
        },
    }

    # Delete index if it exists from a prior run
    try:
        await client._client.indices.delete(index=INDEX_NAME)
        print(f"Cleaned up stale index: {INDEX_NAME}")
    except Exception:
        pass

    # Create the index with strict mapping
    await client._client.indices.create(index=INDEX_NAME, body=mapping)
    print(f"Created index {INDEX_NAME} with strict mapping")


async def demonstrate_current_bug(client: OpenSearchClient) -> None:
    """Show the current bug: partial failures are silently swallowed."""
    print("\n=== DEMONSTRATING CURRENT BUG ===\n")

    # Document 1: valid (event.code is keyword, record_index is integer)
    doc1 = {
        "@timestamp": "2026-07-29T10:00:00Z",
        "message": "Doc 1: valid",
        "event": {"code": "SUCCESS"},
        "kronos": {
            "evidence_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "case_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "org_id": "test-org",
            "record_index": 1,
        },
    }

    # Document 2: INVALID - @timestamp has invalid date format (will fail strict parsing)
    doc2 = {
        "@timestamp": "not-a-valid-date",  # BUG: not strict_date_time format
        "message": "Doc 2: WILL FAIL - invalid @timestamp format",
        "event": {"code": "INVALID"},
        "kronos": {
            "evidence_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "case_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "org_id": "test-org",
            "record_index": 2,
        },
    }

    # Document 3: valid
    doc3 = {
        "@timestamp": "2026-07-29T10:02:00Z",
        "message": "Doc 3: valid",
        "event": {"code": "COMPLETED"},
        "kronos": {
            "evidence_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "case_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "org_id": "test-org",
            "record_index": 3,
        },
    }

    print("Sending bulk request with 3 documents (doc2 will fail)...")
    documents = [
        (INDEX_NAME, "doc-1", doc1),
        (INDEX_NAME, "doc-2", doc2),
        (INDEX_NAME, "doc-3", doc3),
    ]

    # Call bulk_index (now with the FIX)
    print("\nCalling bulk_index() [FIXED CODE]...")
    try:
        success_count = await client.bulk_index(documents)
        print(f"✗ BUG NOT FIXED: bulk_index returned {success_count} (out of {len(documents)}) with NO EXCEPTION")
        print(f"  Expected: should have raised StorageError on partial failure")
        print(f"  Actual: returned {success_count} silently → timeline records are lost!")
    except StorageError as exc:
        print(f"✓ FIXED: bulk_index raised StorageError as expected:")
        print(f"  Message: {exc}")
        print(f"  Context details:")
        for key, value in exc.context.items():
            if key == "failed_documents":
                print(f"    {key}:")
                for failed_doc in value:
                    print(f"      - doc_id={failed_doc['doc_id']}, index={failed_doc['index_name']}, status={failed_doc['status']}")
                    if failed_doc["error"]:
                        print(f"        error_type={failed_doc['error'].get('type')}")
                        print(f"        reason={failed_doc['error'].get('reason')[:80]}...")
            else:
                print(f"    {key}: {value}")
    except Exception as exc:
        print(f"✗ UNEXPECTED ERROR: {type(exc).__name__}: {exc}")

    # Now let's check what actually happened by querying the index
    await client._client.indices.refresh(index=INDEX_NAME)
    search_result = await client._client.search(index=INDEX_NAME, body={"query": {"match_all": {}}})
    indexed_count = search_result["hits"]["total"]["value"]
    print(f"\n  Actual docs in index: {indexed_count} (2 succeeded, 1 failed per the exception)")

    # Print the raw _bulk response to show the error structure
    print("\n--- Raw _bulk API response structure (for reference) ---")
    body: list[dict] = []
    for index, doc_id, doc_body in documents:
        body.append({"index": {"_index": index, "_id": doc_id}})
        body.append(doc_body)

    raw_response = await client._client.bulk(body=body)
    print(json.dumps(raw_response, indent=2, default=str))


async def main() -> None:
    import opensearchpy

    print(f"opensearch-py version: {opensearchpy.__version__}")

    client = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
        timeout=30,
    )

    try:
        # Verify cluster is up
        info = await client._client.info()
        print(f"OpenSearch version: {info['version']['number']}")

        # Setup and run the PoC
        await setup_index_with_strict_mapping(client)
        await demonstrate_current_bug(client)

    finally:
        # Cleanup
        try:
            await client._client.indices.delete(index=INDEX_NAME)
            print(f"\nCleaned up test index: {INDEX_NAME}")
        except Exception:
            pass
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
