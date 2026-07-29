"""PoC: link real Plaso output to real OpenSearch, using KronOS's actual
code for every step except the subprocess plumbing.

Input: poc/plaso/output.jsonl - the REAL stdout of docker/plaso/
kronos-plaso-worker.py, produced by a REAL log2timeline+psort run
(plaso==20260512) against a real Windows Prefetch sample
(tests/fixtures/samples/real/CMD.EXE-087B4001.pf). See poc/plaso/README.md.

Pipeline exercised, using the actual src/ classes (not reimplementations):
  FirecrackerLauncher._stream_records()   -> TimelineRecord (real domain model)
  _annotate_records() (parsing_orchestration.py) -> document_id assigned
  ECSNormalizer.to_document()             -> OpenSearch document dict
  OpenSearchClient.bulk_index()           -> real bulk index call

The only thing substituted is the subprocess.Popen object itself (a stand-in
exposing .stdout/.stderr/.wait()/.returncode over the already-captured JSONL
lines) - per CLAUDE.md B.5, mocking the external dependency (the subprocess)
is fine; mocking the business logic under test is not, and none of it is
mocked here.

Run: source ~/venv/bin/activate && python poc/plaso_opensearch/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.application.parsing_orchestration import _annotate_records  # noqa: E402
from src.application.timeline_normalization import ECSNormalizer, build_index_name  # noqa: E402
from src.external.sandbox.firecracker import FirecrackerLauncher  # noqa: E402

EVIDENCE_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
CASE_ID = uuid.UUID("00000000-0000-0000-0000-00000000000c")
ORG_ID = uuid.UUID("00000000-0000-0000-0000-0000000000aa")
ORG_ALIAS = "testorg"


class _FakeStderr:
    def read(self) -> str:
        return ""


class _FakeProc:
    """Stand-in for subprocess.Popen: real captured stdout, nothing else faked."""

    def __init__(self, lines: list[str]) -> None:
        self.stdout = iter(lines)
        self.stderr = _FakeStderr()
        self.returncode = 0

    def wait(self) -> None:
        return None


async def main() -> None:
    jsonl_path = Path(__file__).resolve().parents[1] / "plaso" / "output.jsonl"
    lines = jsonl_path.read_text().splitlines(keepends=True)
    print(f"Loaded {len(lines)} real psort JSONL lines from {jsonl_path}")

    launcher = FirecrackerLauncher()
    proc = _FakeProc(lines)

    records = [
        r
        async for r in launcher._stream_records(  # noqa: SLF001
            proc,
            evidence_id=str(EVIDENCE_ID),
            case_id=str(CASE_ID),
            org_id=str(ORG_ID),
            org_alias=ORG_ALIAS,
            sha256="93ec53e941b285d1d2a11e1224ab2d5c7a1b8ac493ab8dec407f518c5655ae75",
            parser_name="plaso",
            parser_version="20260512",
        )
    ]
    print(f"\n--- FirecrackerLauncher._stream_records() produced {len(records)} TimelineRecords ---")
    for r in records:
        print(f"  timestamp={r.timestamp.isoformat()}  message={r.message[:80] if r.message else None}")

    now_year = records[0].timestamp.year if records else None
    real_forensic_year = any(r.timestamp.year < 2020 for r in records)
    print(
        f"\nSanity check: any record timestamp predates 2020 (i.e. is the real "
        f"forensic time, not 'now')? {real_forensic_year}"
    )

    annotated = [
        r
        async for r in _annotate_records(
            _aiter(records), EVIDENCE_ID, parser_name="plaso", org_alias=ORG_ALIAS
        )
    ]
    print(f"\n--- _annotate_records() assigned document_id to {len(annotated)} records ---")

    normalizer = ECSNormalizer()
    client = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 19200}],
        http_auth=None,
        use_ssl=False,
        verify_certs=False,
        timeout=30,
    )

    docs = []
    for r in annotated:
        index = build_index_name(ORG_ALIAS, str(CASE_ID), r.timestamp)
        body = normalizer.to_document(r)
        docs.append((index, r.document_id, body))

    indexed = await client.bulk_index(docs)
    print(f"\n--- bulk_index() indexed {indexed}/{len(docs)} real Plaso-derived documents ---")

    index_name = docs[0][0]
    await client._client.indices.refresh(index=index_name)
    search = await client._client.search(index=index_name, body={"query": {"match_all": {}}})
    print(f"--- search hit count in {index_name}: {search['hits']['total']} ---")
    hit = search["hits"]["hits"][0]["_source"]
    print("--- one indexed document's @timestamp and kronos block ---")
    print({"@timestamp": hit["@timestamp"], "kronos": hit["kronos"], "message": hit.get("message")})

    await client.close()


async def _aiter(items: list):
    for item in items:
        yield item


if __name__ == "__main__":
    asyncio.run(main())
