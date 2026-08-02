#!/usr/bin/env python3
"""Verification-first PoC: STIX 2.1 IOC ingestion + matching (roadmap M5/F2).

Drives the real, unmodified production classes:
  parse_stix21_bundle         (src/application/stix_ioc_parser.py)
  IOCFeedIngestionService     (src/application/ioc_feed_ingestion.py)
  PostgresIOCFeedRepository   (src/adapter/repository/postgres_ioc_feed.py)
  IOCMatchEnricher            (src/application/ioc_enrichment.py)
  EnrichmentPipeline          (src/application/enrichment.py)
  OpenSearchClient            (src/adapter/opensearch/client.py) -- the REAL
                              opensearch-py client against the REAL, already
                              running dev cluster (docker-opensearch-1,
                              OpenSearch 2.11.1), not InMemoryOpenSearchClient
                              -- specifically to prove the NEW
                              enrichment.ioc.* index_template.json mapping is
                              actually accepted by the real cluster.

Input: sample_bundle.json -- a real-shaped STIX 2.1 bundle (indicator object
shape confirmed against the official oasis-open/cti-python-stix2 test suite
and the OASIS STIX 2.1 specification itself -- see this dir's README.md)
containing:
  - 1 real, matchable ipv4-addr indicator
  - 1 real, matchable domain-name indicator
  - 1 real, matchable file:hashes.SHA-256 indicator
  - 1 MD5-only indicator (no matching KronOS field -- must be skipped, not crash)
  - 1 compound (AND) pattern (unsupported shape -- must be skipped, not crash)
  - 1 deliberately malformed indicator (non-string pattern -- must be
    skipped, proving "treat feed content as untrusted input" holds even for
    hostile/malformed content, not just well-formed-but-unsupported content)
  - 1 non-indicator SDO (malware) -- must be ignored, not misparsed

Run: ~/venv/bin/python3 poc/threat_intel_stix_ingest/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.repository.ioc_feed import IOCFeedRepository  # noqa: E402
from src.adapter.repository.postgres_ioc_feed import PostgresIOCFeedRepository  # noqa: E402
from src.application.enrichment import EnrichmentPipeline  # noqa: E402
from src.application.ioc_enrichment import IOCMatchEnricher  # noqa: E402
from src.application.ioc_feed_ingestion import IOCFeedIngestionService  # noqa: E402
from src.application.stix_ioc_parser import parse_stix21_bundle  # noqa: E402
from src.domain.ioc_feed import IOCType  # noqa: E402
from src.domain.timeline import KronosProvenance, TimelineRecord  # noqa: E402
from src.exceptions import ValidationError  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
POC_INDEX = "kronos-poc-threatintel-org"

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}", flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _make_record(*, sha256: str, source_ip: str | None = None, org_id: uuid.UUID) -> TimelineRecord:
    extra: dict[str, object] = {}
    if source_ip:
        extra["source.ip"] = source_ip
    return TimelineRecord(
        **{"@timestamp": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), "message": "poc-f2-event"},
        event_kind="event",
        extra=extra,
        kronos=KronosProvenance(
            evidence_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=org_id,
            sha256=sha256,
            parser="poc",
            parser_version="1.0.0",
            record_index=0,
            ingest_timestamp=datetime.now(UTC),
        ),
    )


async def main() -> int:
    log("=" * 78)
    log("PoC: STIX 2.1 IOC ingestion + matching (roadmap M5/F2)")
    log("=" * 78)

    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    await PostgresIOCFeedRepository.create_tables(engine)
    repo: IOCFeedRepository = PostgresIOCFeedRepository(engine)
    ingest_service = IOCFeedIngestionService(repo)
    org_id = uuid.uuid4()
    org_b = uuid.uuid4()

    try:
        # -------------------------------------------------------------
        # Scenario (a): parse the real STIX bundle -- defensive extraction
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (a): parse_stix21_bundle() against the real sample bundle")
        log("=" * 78)

        bundle_bytes = (Path(__file__).parent / "sample_bundle.json").read_bytes()
        indicators = parse_stix21_bundle(bundle_bytes)
        log(f"parsed {len(indicators)} matchable indicator(s) from 7 bundle objects:")
        for ind in indicators:
            log(f"  - {ind.ioc_type.value}: {ind.value!r} (confidence={ind.confidence})")

        check("exactly 3 matchable indicators extracted (ip, domain, sha256)", len(indicators) == 3)
        check(
            "ipv4-addr indicator extracted",
            any(i.ioc_type == IOCType.IP and i.value == "203.0.113.66" for i in indicators),
        )
        check(
            "domain-name indicator extracted",
            any(
                i.ioc_type == IOCType.DOMAIN and i.value == "evil-poc-example.test"
                for i in indicators
            ),
        )
        check(
            "file:hashes.SHA-256 indicator extracted",
            any(
                i.ioc_type == IOCType.FILE_HASH_SHA256
                and i.value == "3059be08a17bebc0f4edb82e52a0297f32347b556c474a3f252d3b149a7b17ba"
                for i in indicators
            ),
        )
        check(
            "MD5-only / compound / malformed indicators honestly skipped (not 6, not a crash)",
            len(indicators) == 3,
        )

        # -------------------------------------------------------------
        # Scenario (b): structurally invalid bundle -> ValidationError,
        # never silently accepted
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (b): a non-bundle payload must raise ValidationError")
        log("=" * 78)
        raised = False
        try:
            parse_stix21_bundle(b'{"type": "not-a-bundle"}')
        except ValidationError as exc:
            raised = True
            log(f"real ValidationError raised: {exc}")
        check("structurally invalid bundle raises ValidationError", raised)

        # -------------------------------------------------------------
        # Scenario (c): real ingestion into real Postgres, versioned
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (c): real ingestion into real Postgres (PostgresIOCFeedRepository)")
        log("=" * 78)

        v1 = await ingest_service.ingest_stix_bundle(org_id, "poc-feed", bundle_bytes)
        log(
            f"real IOCFeedVersion row: feed_id={v1.feed_id} version={v1.version} "
            f"indicator_count={len(v1.indicators)}"
        )
        check("first ingestion creates version 1", v1.version == 1)
        check("version has the 3 real parsed indicators", len(v1.indicators) == 3)

        v2 = await ingest_service.ingest_stix_bundle(org_id, "poc-feed", bundle_bytes)
        log(f"re-ingested same bundle: version={v2.version}")
        check("re-ingesting the same feed name creates version 2, not overwrite", v2.version == 2)

        versions = await repo.list_versions(v1.feed_id)
        check(
            "both versions survive -- append-only, version 1 never lost",
            len(versions) == 2 and versions[0].version == 1,
        )

        # -------------------------------------------------------------
        # Scenario (d): real match_indicator() lookups against real Postgres
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (d): real IOCFeedRepository.match_indicator() against real Postgres")
        log("=" * 78)

        ip_match = await repo.match_indicator(org_id, IOCType.IP, "203.0.113.66")
        log(f"IP match: {ip_match}")
        check("real IP match found", ip_match is not None and ip_match.feed_name == "poc-feed")

        case_match = await repo.match_indicator(org_id, IOCType.DOMAIN, "EVIL-POC-EXAMPLE.TEST")
        check("domain match is case-insensitive", case_match is not None)

        no_match = await repo.match_indicator(org_id, IOCType.IP, "198.51.100.200")
        check("non-matching IP returns an honest None", no_match is None)

        cross_org = await repo.match_indicator(org_b, IOCType.IP, "203.0.113.66")
        check("cross-org isolation: org B never matches org A's feed", cross_org is None)

        # -------------------------------------------------------------
        # Scenario (e): real IOCMatchEnricher via the real EnrichmentPipeline
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (e): real IOCMatchEnricher through EnrichmentPipeline")
        log("=" * 78)

        pipeline = EnrichmentPipeline([IOCMatchEnricher(repo)])

        ip_record = _make_record(sha256="0" * 64, source_ip="203.0.113.66", org_id=org_id)
        enriched_ip = await pipeline.enrich(ip_record, org_id)
        log(f"IP-matching record enriched.extra = {enriched_ip.extra}")
        check(
            "real enrichment.ioc.matched=True for source.ip hit",
            enriched_ip.extra.get("enrichment.ioc.matched") is True,
        )
        check(
            "real enrichment.ioc.feed_name attached",
            enriched_ip.extra.get("enrichment.ioc.feed_name") == "poc-feed",
        )
        check(
            "real enrichment.ioc.confidence attached from the STIX indicator's own value",
            enriched_ip.extra.get("enrichment.ioc.confidence") == 85,
        )

        hash_record = _make_record(
            sha256="3059be08a17bebc0f4edb82e52a0297f32347b556c474a3f252d3b149a7b17ba", org_id=org_id
        )
        enriched_hash = await pipeline.enrich(hash_record, org_id)
        log(f"sha256-matching record enriched.extra = {enriched_hash.extra}")
        check(
            "real enrichment.ioc.ioc_type=sha256 for evidence-file-hash match",
            enriched_hash.extra.get("enrichment.ioc.ioc_type") == "sha256",
        )

        clean_record = _make_record(sha256="f" * 64, source_ip="10.0.0.1", org_id=org_id)
        enriched_clean = await pipeline.enrich(clean_record, org_id)
        check(
            "no match -- honest no-op (record returned identical, no fabricated match)",
            enriched_clean is clean_record,
        )

        # -------------------------------------------------------------
        # Scenario (f): REAL OpenSearch -- prove the NEW enrichment.ioc.*
        # index_template.json mapping is actually accepted by the real,
        # already-running 2.11.1 cluster, and the enriched document round-
        # trips correctly.
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (f): real OpenSearchClient against the real live 2.11.1 cluster")
        log("=" * 78)

        os_client = OpenSearchClient(
            hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
            http_auth=("admin", "admin"),
            use_ssl=True,
            verify_certs=False,
        )
        try:
            await os_client.ensure_index_template()
            log("real PUT _index_template/kronos-template succeeded (new enrichment.ioc.* mapping)")

            doc_id = f"poc-f2-{uuid.uuid4()}"
            ecs_doc = {
                "@timestamp": enriched_ip.timestamp.isoformat(),
                "message": enriched_ip.message,
                "event": {"kind": enriched_ip.event_kind},
                "source": {"ip": "203.0.113.66"},
                "enrichment": {
                    "ioc": {
                        "matched": True,
                        "ioc_type": "ip",
                        "value": "203.0.113.66",
                        "feed_name": "poc-feed",
                        "confidence": 85,
                        "description": "C2 IP observed in KronOS PoC scenario",
                    }
                },
                "kronos": {"parser": "poc", "org_id": str(org_id)},
            }
            indexed_count = await os_client.bulk_index([(POC_INDEX, doc_id, ecs_doc)])
            log(f"real bulk_index() call: indexed_count={indexed_count}")
            check(
                "real bulk_index reports 1 document indexed, no partial-failure exception",
                indexed_count == 1,
            )

            # Real GET straight from opensearch-py's own client (not our
            # AbstractTimelineIndex, which has no single-doc get -- this is
            # the real underlying client OpenSearchClient wraps).
            await asyncio.sleep(1)  # real refresh_interval default is 1s
            raw = await os_client._client.get(index=POC_INDEX, id=doc_id)  # noqa: SLF001
            log(f"real GET response _source: {raw['_source']}")
            check(
                "real indexed document's enrichment.ioc.matched round-trips as boolean true",
                raw["_source"]["enrichment"]["ioc"]["matched"] is True,
            )
            check(
                "real indexed document's enrichment.ioc.confidence round-trips as 85",
                raw["_source"]["enrichment"]["ioc"]["confidence"] == 85,
            )

            # Confirm the real mapping actually applied the types declared
            # in index_template.json (not just accepted the doc by luck).
            mapping = await os_client._client.indices.get_mapping(index=POC_INDEX)  # noqa: SLF001
            ioc_mapping = mapping[list(mapping.keys())[0]]["mappings"]["properties"]["enrichment"][
                "properties"
            ]["ioc"]["properties"]
            log(f"real applied mapping for enrichment.ioc.*: {ioc_mapping}")
            check(
                "real mapping: enrichment.ioc.matched is type boolean",
                ioc_mapping["matched"]["type"] == "boolean",
            )
            check(
                "real mapping: enrichment.ioc.confidence is type long",
                ioc_mapping["confidence"]["type"] == "long",
            )
            check(
                "real mapping: enrichment.ioc.feed_name is type keyword",
                ioc_mapping["feed_name"]["type"] == "keyword",
            )

            await os_client._client.delete(index=POC_INDEX, id=doc_id)  # noqa: SLF001
            log(f"cleaned up real PoC document {doc_id} from {POC_INDEX}")
        finally:
            await os_client.close()

    finally:
        await engine.dispose()

    log("\n" + "=" * 78)
    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(f"PoC PASSED -- all {len(CHECKS)} checks passed against real Postgres + OpenSearch 2.11.1.")
    log("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
