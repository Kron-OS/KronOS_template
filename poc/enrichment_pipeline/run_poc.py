#!/usr/bin/env python3
"""Verification-first PoC: extensible enrichment pipeline, asset-context
enricher (roadmap M5/F1), against the real, already-running dev-stack
Postgres.

This script drives the real, unmodified production classes:
  Enricher / EnrichmentPipeline       (src/application/enrichment.py)
  AssetContextEnricher                (src/application/asset_enrichment.py)
  Asset                               (src/domain/asset.py)
  PostgresAssetRepository             (src/adapter/repository/postgres_asset.py)
  ParsingOrchestrationService         (src/application/parsing_orchestration.py)
  TimelineIngestionService            (src/application/timeline_ingest.py)

Scenarios:
  (a) Real asset seeded in real Postgres; a real TimelineRecord whose
      host_name matches gets real, namespaced enrichment.asset.* fields
      attached, with every ORIGINAL field byte-for-byte unchanged
      (explicit equality checks, not just "some new keys exist").
  (b) A record whose host_name has no matching asset gets an honest
      "unchanged" result -- not an error, not a fabricated match.
  (c) Cross-org isolation: an asset seeded for org A never enriches a
      record for org B, verified for real against the real Postgres rows.
  (d) Re-runnability: update the real asset's criticality in Postgres,
      re-run enrichment against the exact same original record, confirm
      the derived data reflects the update while every original field on
      that record remains identical -- proving enrichment can be
      legitimately re-run without ever touching the original forensic
      record (see src/application/enrichment.py's own module docstring
      for why this matters more than it would for, say, a parser).
  (e) Real, end-to-end: the same pipeline wired into a real
      ParsingOrchestrationService.execute_parse() call, indexing through a
      real TimelineIngestionService into a real ECS document, confirming
      the enrichment fields land at the expected nested OpenSearch path.

Run: ~/venv/bin/python3 poc/enrichment_pipeline/run_poc.py
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

from src.adapter.opensearch.client import InMemoryOpenSearchClient  # noqa: E402
from src.adapter.queue.task_queue import InMemoryTaskQueue  # noqa: E402
from src.adapter.repository.postgres_asset import PostgresAssetRepository  # noqa: E402
from src.adapter.storage.local import LocalEvidenceStorage  # noqa: E402
from src.application.asset_enrichment import AssetContextEnricher  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.enrichment import EnrichmentPipeline  # noqa: E402
from src.application.parser_registry import ParserRegistry  # noqa: E402
from src.application.parsing import ForensicParser, ParserType  # noqa: E402
from src.application.parsing_orchestration import ParsingOrchestrationService  # noqa: E402
from src.application.timeline_ingest import TimelineIngestionService  # noqa: E402
from src.domain.asset import Asset  # noqa: E402
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState  # noqa: E402
from src.domain.timeline import KronosProvenance, TimelineRecord  # noqa: E402
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository  # noqa: E402
from tests.fixtures.factories import make_tenant_context  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}", flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _make_record(host_name: str | None, org_id: uuid.UUID | None = None) -> TimelineRecord:
    return TimelineRecord(
        **{"@timestamp": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), "message": "poc-f1-event"},
        host_name=host_name,
        event_kind="event",
        kronos=KronosProvenance(
            evidence_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=org_id or uuid.uuid4(),
            sha256="a" * 64,
            parser="poc",
            parser_version="1.0.0",
            record_index=0,
            ingest_timestamp=datetime.now(UTC),
        ),
    )


class _HostNamedParser(ForensicParser):
    """Yields one TimelineRecord with a fixed host_name -- scenario (e)."""

    def __init__(self, host_name: str) -> None:
        self._host_name = host_name

    @property
    def parser_name(self) -> str:
        return "poc-parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return True

    async def parse(self, stream, evidence, tenant):  # type: ignore[no-untyped-def]
        yield TimelineRecord(
            **{"@timestamp": datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), "event.kind": "event"},
            host_name=self._host_name,
            kronos=KronosProvenance(
                evidence_id=evidence.evidence_id,
                case_id=evidence.metadata.case_id,
                org_id=evidence.metadata.org_id,
                sha256="",
                parser=self.parser_name,
                parser_version=self.parser_version,
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )


async def main() -> int:
    log("=" * 78)
    log("PoC: enrichment pipeline -- real asset-context enricher (roadmap F1)")
    log("=" * 78)

    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    await PostgresAssetRepository.create_tables(engine)
    repo = PostgresAssetRepository(engine)
    pipeline = EnrichmentPipeline([AssetContextEnricher(repo)])

    try:
        # -------------------------------------------------------------
        # Scenario (a): real match, every original field byte-for-byte
        # unchanged
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (a): real Postgres-seeded asset, real match, originals untouched")
        log("=" * 78)

        org_id = uuid.uuid4()
        asset = await repo.upsert(
            Asset(
                org_id=org_id,
                hostname="WIN-DC01",
                criticality="critical",
                owner="secops",
                environment="production",
            )
        )
        log(f"real asset row: asset_id={asset.asset_id} org_id={org_id} hostname=WIN-DC01")

        original = _make_record("WIN-DC01", org_id=org_id)
        enriched = await pipeline.enrich(original, org_id)

        log(f"enriched.extra = {enriched.extra}")
        check(
            "real enrichment.asset.criticality attached",
            enriched.extra.get("enrichment.asset.criticality") == "critical",
        )
        check(
            "real enrichment.asset.owner attached",
            enriched.extra.get("enrichment.asset.owner") == "secops",
        )
        check(
            "real enrichment.asset.environment attached",
            enriched.extra.get("enrichment.asset.environment") == "production",
        )
        check(
            "real enrichment.asset.asset_id matches the real Postgres row",
            enriched.extra.get("enrichment.asset.asset_id") == str(asset.asset_id),
        )

        # Every ORIGINAL field explicitly, individually checked -- not just
        # "some new keys appeared".
        check("original @timestamp unchanged", enriched.timestamp == original.timestamp)
        check("original message unchanged", enriched.message == original.message)
        check("original host_name unchanged", enriched.host_name == original.host_name)
        check("original event_kind unchanged", enriched.event_kind == original.event_kind)
        check("original kronos block unchanged", enriched.kronos == original.kronos)
        check("original document_id unchanged", enriched.document_id == original.document_id)
        check(
            "original input record object itself was never mutated (frozen)", original.extra == {}
        )

        # -------------------------------------------------------------
        # Scenario (b): no matching asset -- honest unchanged result
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (b): no matching asset -- honest 'no enrichment', not an error")
        log("=" * 78)

        no_match_record = _make_record("UNKNOWN-HOST")
        result_b = await pipeline.enrich(no_match_record, org_id)
        log(f"result.extra = {result_b.extra}")
        check(
            "no fabricated match -- record returned identical (is-identity)",
            result_b is no_match_record,
        )

        # -------------------------------------------------------------
        # Scenario (c): cross-org isolation, real Postgres rows
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (c): real cross-org isolation")
        log("=" * 78)

        org_b = uuid.uuid4()
        record_for_b = _make_record("WIN-DC01")
        result_c = await pipeline.enrich(record_for_b, org_b)
        log(f"org_b's own lookup of the SAME hostname 'WIN-DC01': extra={result_c.extra}")
        check("org A's real asset never enriches org B's record", result_c is record_for_b)

        # -------------------------------------------------------------
        # Scenario (d): re-runnability -- update the real asset, re-run
        # enrichment against the SAME original record
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (d): real re-runnability after a real asset-inventory update")
        log("=" * 78)

        await repo.upsert(
            Asset(
                org_id=org_id,
                hostname="WIN-DC01",
                criticality="low",
                owner="secops",
                environment="production",
            )
        )
        log("real asset row updated in Postgres: criticality critical -> low")

        re_enriched = await pipeline.enrich(original, org_id)  # SAME original record object
        log(f"re-enriched.extra = {re_enriched.extra}")
        check(
            "re-running enrichment against the SAME original record reflects the real update",
            re_enriched.extra.get("enrichment.asset.criticality") == "low",
        )
        check(
            "the FIRST enrichment result is untouched by the later update (its own frozen snapshot)",
            enriched.extra.get("enrichment.asset.criticality") == "critical",
        )
        check(
            "the original record's own fields are still identical after re-enrichment",
            re_enriched.timestamp == original.timestamp and re_enriched.kronos == original.kronos,
        )

        # -------------------------------------------------------------
        # Scenario (e): real end-to-end through ParsingOrchestrationService
        # + TimelineIngestionService -> real ECS document shape
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (e): real end-to-end through the orchestration + ingestion pipeline")
        log("=" * 78)

        tenant = make_tenant_context(org_id=org_id)
        evidence_repo = InMemoryEvidenceRepository()
        audit_repo = InMemoryAuditLogRepository()
        storage = LocalEvidenceStorage(base_dir=Path("/tmp/kronos_poc_f1_storage"))
        evidence_key = f"{tenant.org_alias}/poc-case/{uuid.uuid4()}"
        storage.write_evidence(evidence_key, b"irrelevant-bytes")
        evidence = Evidence(
            metadata=EvidenceMetadata(
                original_filename="poc.log",
                content_type="text/plain",
                size_bytes=1,
                uploader_user_id=tenant.user_id,
                case_id=uuid.uuid4(),
                org_id=org_id,
                org_alias=tenant.org_alias,
            ),
            state=EvidenceState.PARSING,
            sha256="a" * 64,
            minio_evidence_key=evidence_key,
        )
        await evidence_repo.save(evidence)

        opensearch = InMemoryOpenSearchClient()
        ingest = TimelineIngestionService(opensearch, AuditLogService(audit_repo))
        registry = ParserRegistry()
        registry.register(_HostNamedParser("WIN-DC01"))
        orchestrator = ParsingOrchestrationService(
            evidence_repository=evidence_repo,
            storage=storage,
            audit_log=AuditLogService(audit_repo),
            parser_registry=registry,
            task_queue=InMemoryTaskQueue(),
            timeline_ingest=ingest,
            enrichment_pipeline=pipeline,
        )

        await orchestrator.execute_parse(evidence.evidence_id, tenant)

        docs = [
            d for idx in opensearch.all_indices() for d in opensearch.get_documents(idx).values()
        ]
        log(f"real indexed ECS document: {docs[0] if docs else None}")
        check("real end-to-end pipeline indexed exactly 1 document", len(docs) == 1)
        if docs:
            check(
                "real indexed document has nested enrichment.asset.criticality (reflects the real update)",
                docs[0].get("enrichment", {}).get("asset", {}).get("criticality") == "low",
            )
            check(
                "real indexed document's own host.name is unaffected",
                docs[0].get("host", {}).get("name") == "WIN-DC01",
            )

    finally:
        await engine.dispose()

    log("\n" + "=" * 78)
    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(f"PoC PASSED -- all {len(CHECKS)} checks passed against real Postgres.")
    log("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
