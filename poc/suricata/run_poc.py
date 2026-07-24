#!/usr/bin/env python3
"""PoC: SuricataEveParser against a real Suricata EVE JSON sample.

No external service/container involved -- SuricataEveParser is a pure
in-process stdlib-json parser (same trust tier as CloudTrailParser/
NginxParser), so this is a standalone script, not a Docker-based PoC.

What this actually does:
  1. Builds a real ParserRegistry (CloudTrailParser, NginxParser,
     SuricataEveParser -- the three FAST JSON/text parsers) exactly as
     get_parser_registry() does in src/external/dependencies.py, and runs
     real detection (ParserRegistry.get_parser()) against the real fixture
     bytes, proving no cross-routing with CloudTrail/Nginx.
  2. Runs the real SuricataEveParser().parse() against the real fixture
     bytes (tests/fixtures/samples/real/suricata/eve.json -- see NOTICE.md
     for provenance) and prints every resulting TimelineRecord's real
     field values -- not a description of what should happen.

Run: python3 poc/suricata/run_poc.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.application.parser_registry import ParserRegistry  # noqa: E402
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState  # noqa: E402
from src.domain.timeline import TimelineRecord  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.parsers.cloudtrail import CloudTrailParser  # noqa: E402
from src.external.parsers.nginx import NginxParser  # noqa: E402
from src.external.parsers.suricata import SuricataEveParser  # noqa: E402

FIXTURE = REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "suricata" / "eve.json"
HEADER_BYTES = 8192  # matches _detect_parser()'s real detection window


def _make_evidence() -> Evidence:
    return Evidence(
        metadata=EvidenceMetadata(
            original_filename="eve.json",
            content_type="application/json",
            size_bytes=FIXTURE.stat().st_size,
            uploader_user_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            org_alias="poc-org",
        ),
        state=EvidenceState.UPLOADING,
    )


def _make_tenant() -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias="poc-org",
        user_id=uuid.uuid4(),
        username="poc-user",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


def _record_to_dict(r: TimelineRecord) -> dict:
    return {
        "@timestamp": r.timestamp.isoformat(),
        "message": r.message,
        "event.kind": r.event_kind,
        "event.category": r.event_category,
        "event.type": r.event_type,
        "extra": r.extra,
        "kronos.parser": r.kronos.parser,
        "kronos.parser_version": r.kronos.parser_version,
        "kronos.record_index": r.kronos.record_index,
        "kronos.sha256": r.kronos.sha256,
    }


async def main() -> None:
    print("=" * 78)
    print("STEP 1: real ParserRegistry detection (CloudTrail, Nginx, Suricata)")
    print("=" * 78)

    registry = ParserRegistry()
    registry.register(CloudTrailParser())
    registry.register(NginxParser())
    registry.register(SuricataEveParser())

    header = FIXTURE.read_bytes()[:HEADER_BYTES]
    detected = registry.get_parser(FIXTURE.name, "application/json", header)
    print(f"Fixture: {FIXTURE.relative_to(REPO_ROOT)}")
    print(f"Header bytes inspected: {len(header)}")
    print(f"registry.get_parser() -> {type(detected).__name__}")
    assert isinstance(detected, SuricataEveParser), "misrouted to the wrong parser!"

    # Cross-routing guard: confirm the *other* two real fixtures still route
    # correctly with SuricataEveParser also registered.
    cloudtrail_fixture = (
        REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "aws_cloudtrail.jsonl"
    )
    nginx_fixture = REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "apache_access.log"
    ct_detected = registry.get_parser(
        cloudtrail_fixture.name, "application/json", cloudtrail_fixture.read_bytes()[:HEADER_BYTES]
    )
    nginx_detected = registry.get_parser(
        nginx_fixture.name, "text/plain", nginx_fixture.read_bytes()[:HEADER_BYTES]
    )
    print(f"Real CloudTrail sample -> {type(ct_detected).__name__} (expected CloudTrailParser)")
    print(f"Real nginx sample -> {type(nginx_detected).__name__} (expected NginxParser)")
    assert isinstance(ct_detected, CloudTrailParser)
    assert isinstance(nginx_detected, NginxParser)

    print()
    print("=" * 78)
    print("STEP 2: real SuricataEveParser().parse() against the real fixture")
    print("=" * 78)

    evidence = _make_evidence()
    tenant = _make_tenant()
    parser = SuricataEveParser()

    data = FIXTURE.read_bytes()
    records: list[TimelineRecord] = []
    async for record in parser.parse(_bytes_stream(data), evidence, tenant):
        records.append(record)

    total_lines = len([ln for ln in data.decode().splitlines() if ln.strip()])
    print(f"Real fixture lines: {total_lines}")
    print(f"TimelineRecords yielded: {len(records)}")
    print()

    for i, r in enumerate(records):
        print(f"--- record[{i}] (real, parsed) ---")
        print(json.dumps(_record_to_dict(r), indent=2, default=str))
        print()

    print("=" * 78)
    print(f"DONE. {len(records)}/{total_lines} real EVE JSON lines parsed successfully.")
    print("=" * 78)


if __name__ == "__main__":
    asyncio.run(main())
