#!/usr/bin/env python3
"""Verification-first PoC: risk scoring + alert prioritization (roadmap M5/F4).

Drives the real, unmodified production classes:
  DetectionRiskScorer     (src/application/risk_scoring.py)
  RiskFactor/RiskScoreBreakdown (src/domain/risk.py)
  Detection/highest_rule_severity (src/domain/detection.py)
  DetectionSyncService    (src/application/detection_sync.py)
  OpenSearchClient.get_documents_by_id (src/adapter/opensearch/client.py) --
                          the REAL opensearch-py AsyncOpenSearch client
                          against the REAL, already-running dev cluster
                          (docker-opensearch-1, OpenSearch 2.11.1), not
                          InMemoryOpenSearchClient -- specifically to prove
                          the NEW _mget-based read path works against the
                          real pinned server, not just an assumed shape.

Scenarios:
  (0) Confirm the real Sigma `level:` severity vocabulary against the live
      cluster's own 2077 pre-packaged Security Analytics rules -- NOT
      assumed from memory (CLAUDE.md SS F.2 step 1).
  (1) Real OpenSearch round-trip for the new get_documents_by_id: index 3
      real documents (one with both enrichment.ioc.confidence and
      enrichment.asset.criticality, one with only enrichment.asset.*, one
      with no enrichment at all), then mget them back by id alongside one
      id that was never indexed -- confirm the real response shape
      (docs[].found) and that the honest "found only" contract holds.
  (2) End-to-end: DetectionSyncService.sync_org_findings(), wired to the
      REAL OpenSearch client above, syncing 4 synthetic-but-real-shaped SA
      findings that each matched_document_ids-reference one of the real
      indexed documents from (1) (or a document id that doesn't exist),
      demonstrating the scorer runs deterministically end-to-end and that
      the SAME rule severity produces a documented, reproducible HIGHER
      score when the matched document carries higher asset
      criticality/IOC confidence -- never a fabricated delta.

Run: ~/venv/bin/python3 poc/detection_risk_scoring/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.opensearch.findings_client import FindingsClient  # noqa: E402
from src.adapter.repository.detection import InMemoryDetectionRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sync import DetectionSyncService  # noqa: E402
from src.application.risk_scoring import DetectionRiskScorer  # noqa: E402
from tests.conftest import InMemoryAuditLogRepository  # noqa: E402
from tests.fixtures.factories import make_tenant_context  # noqa: E402

OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
POC_INDEX = f"kronos-poc-risk-scoring-org-case-{uuid.uuid4().hex[:8]}-202608"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


class _StaticFindingsClient(FindingsClient):
    """Returns a fixed list of real-shaped SA finding hits (see
    tests/unit/application/test_detection_sync.py's own _real_finding_hit
    for the exact real shape this mirrors, confirmed against a live cluster
    in poc/detection_finding_sync/)."""

    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self._hits = hits

    async def fetch_org_findings(self, org_alias: str, log_types: tuple[str, ...]) -> list[dict[str, Any]]:
        return self._hits


def _real_finding_hit(
    finding_id: str, *, tags: list[str], related_doc_ids: list[str], source_index: str
) -> dict[str, Any]:
    return {
        "_index": ".opensearch-sap-network-findings-2026.08.02-1",
        "_id": finding_id,
        "_source": {
            "id": finding_id,
            "related_doc_ids": related_doc_ids,
            "correlated_doc_ids": related_doc_ids,
            "monitor_id": "poc-risk-scoring-monitor",
            "monitor_name": "kronos-poc-risk-scoring-network-detector",
            "index": source_index,
            "queries": [{"id": f"rule-{finding_id}", "name": f"rule-{finding_id}", "tags": tags}],
            "timestamp": int(datetime.now(UTC).timestamp() * 1000),
            "execution_id": None,
        },
    }


async def main() -> int:
    # ------------------------------------------------------------------
    # Scenario 0: confirm the real Sigma severity vocabulary
    # ------------------------------------------------------------------
    log("=== Scenario 0: real Sigma severity vocabulary (live 2.11.1 cluster) ===")
    async with httpx.AsyncClient(verify=False) as http:
        resp = await http.post(
            f"https://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
            "/_plugins/_security_analytics/rules/_search?pre_packaged=true",
            auth=("admin", "admin"),
            json={"query": {"match_all": {}}, "size": 2077},
        )
        check("real GET pre-packaged rules search returned 200", resp.status_code == 200)
        data = resp.json()
        hits = data["hits"]["hits"]
        levels: dict[str, int] = {}
        for h in hits:
            lvl = h["_source"].get("level")
            levels[lvl] = levels.get(lvl, 0) + 1
        log(f"real total pre-packaged rules: {len(hits)}, level distribution: {levels}")
        expected_levels = {"informational", "low", "medium", "high", "critical"}
        check(
            "real corpus contains exactly the 5 documented Sigma levels",
            set(levels.keys()) == expected_levels,
        )
        from src.domain.detection import SIGMA_SEVERITY_LEVELS

        check(
            "src/domain/detection.py's SIGMA_SEVERITY_LEVELS matches the real corpus exactly",
            set(SIGMA_SEVERITY_LEVELS) == expected_levels,
        )

    # ------------------------------------------------------------------
    # Scenario 1: real get_documents_by_id against the real live cluster
    # ------------------------------------------------------------------
    log("=== Scenario 1: real OpenSearch get_documents_by_id (_mget) round-trip ===")
    os_client = OpenSearchClient(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
    )
    doc_high = f"poc-doc-high-{uuid.uuid4()}"
    doc_low = f"poc-doc-low-{uuid.uuid4()}"
    doc_plain = f"poc-doc-plain-{uuid.uuid4()}"
    doc_missing = f"poc-doc-never-indexed-{uuid.uuid4()}"

    try:
        await os_client.ensure_index_template()
        log("real PUT _index_template/kronos-template succeeded")

        indexed = await os_client.bulk_index(
            [
                (
                    POC_INDEX,
                    doc_high,
                    {
                        "@timestamp": datetime.now(UTC).isoformat(),
                        "enrichment": {
                            "ioc": {"matched": True, "confidence": 85, "ioc_type": "ip"},
                            "asset": {"criticality": "critical", "environment": "production"},
                        },
                    },
                ),
                (
                    POC_INDEX,
                    doc_low,
                    {
                        "@timestamp": datetime.now(UTC).isoformat(),
                        "enrichment": {"asset": {"criticality": "low", "environment": "staging"}},
                    },
                ),
                (
                    POC_INDEX,
                    doc_plain,
                    {"@timestamp": datetime.now(UTC).isoformat(), "message": "no enrichment at all"},
                ),
            ]
        )
        check("real bulk_index indexed all 3 real documents", indexed == 3)

        # OpenSearch's default refresh_interval means a just-indexed doc may
        # not be immediately searchable/gettable without an explicit
        # refresh -- force one so the very next mget sees it (this is a
        # real, documented OpenSearch behavior, not a KronOS quirk).
        await os_client._client.indices.refresh(index=POC_INDEX)  # noqa: SLF001

        found = await os_client.get_documents_by_id(
            POC_INDEX, [doc_high, doc_low, doc_plain, doc_missing]
        )
        log(f"real mget result keys: {sorted(found.keys())}")
        check("real mget found exactly the 3 indexed documents", set(found.keys()) == {doc_high, doc_low, doc_plain})
        check("real mget honestly omits the never-indexed id", doc_missing not in found)
        check(
            "real mget round-trips enrichment.ioc.confidence exactly",
            found[doc_high]["enrichment"]["ioc"]["confidence"] == 85,
        )
        check(
            "real mget round-trips enrichment.asset.criticality exactly",
            found[doc_high]["enrichment"]["asset"]["criticality"] == "critical",
        )

        # ------------------------------------------------------------------
        # Scenario 2: end-to-end DetectionSyncService -> DetectionRiskScorer
        # ------------------------------------------------------------------
        log("=== Scenario 2: end-to-end risk scoring through DetectionSyncService ===")
        tenant = make_tenant_context()

        findings = [
            _real_finding_hit(
                "poc-finding-high-critical",
                tags=["high", "network", "attack.t1021.001"],
                related_doc_ids=[doc_high],
                source_index=POC_INDEX,
            ),
            _real_finding_hit(
                "poc-finding-high-low-asset",
                tags=["high", "network", "attack.t1021.001"],
                related_doc_ids=[doc_low],
                source_index=POC_INDEX,
            ),
            _real_finding_hit(
                "poc-finding-high-no-doc",
                tags=["high", "network", "attack.t1021.001"],
                related_doc_ids=[doc_missing],
                source_index=POC_INDEX,
            ),
            _real_finding_hit(
                "poc-finding-no-severity-no-doc",
                tags=["network", "attack.t1021.001"],
                related_doc_ids=[],
                source_index=POC_INDEX,
            ),
        ]

        audit_log = AuditLogService(InMemoryAuditLogRepository())
        detection_repo = InMemoryDetectionRepository()
        service = DetectionSyncService(
            findings_client=_StaticFindingsClient(findings),
            detection_repository=detection_repo,
            audit_log=audit_log,
            timeline_index=os_client,
            log_types=("network",),
            risk_scorer=DetectionRiskScorer(),
        )

        created = await service.sync_org_findings(tenant)
        check("real sync created exactly 4 new Detection rows", created == 4)

        stored = {d.finding_id: d async for d in detection_repo.stream_by_org(tenant.org_id)}

        d_critical = stored["poc-finding-high-critical"]
        d_low_asset = stored["poc-finding-high-low-asset"]
        d_no_doc = stored["poc-finding-high-no-doc"]
        d_no_severity = stored["poc-finding-no-severity-no-doc"]

        log(f"high+critical-asset+ioc85 detection: risk_score={d_critical.risk_score}")
        log(f"high+low-asset (no ioc) detection:    risk_score={d_low_asset.risk_score}")
        log(f"high severity, doc never resolved:    risk_score={d_no_doc.risk_score}")
        log(f"no severity tag, no matched doc:       risk_score={d_no_severity.risk_score}")
        for f in d_critical.risk_factors:
            log(f"  critical-case factor: {f.name} weight={f.weight} normalized={f.normalized_value} detail={f.detail!r}")

        check(
            "same rule severity + real matched-doc enrichment (critical asset, ioc 85) "
            "scores strictly higher than the same finding whose matched doc has NO enrichment at all",
            d_critical.risk_score is not None
            and d_no_doc.risk_score is not None
            and d_critical.risk_score > d_no_doc.risk_score,
        )
        check(
            "same rule severity + critical asset scores strictly higher than + low asset "
            "(documented delta, not a fabricated one)",
            d_critical.risk_score is not None
            and d_low_asset.risk_score is not None
            and d_critical.risk_score > d_low_asset.risk_score,
        )
        check(
            "finding whose matched doc never resolves falls back honestly to rule-severity-only "
            "(75.0 = 0.35*0.75/0.35*100, the documented rule_severity-only formula)",
            d_no_doc.risk_score == 75.0,
        )
        check(
            "finding with no severity tag and no matched doc is honestly un-scorable (None, not 0.0)",
            d_no_severity.risk_score is None,
        )
        check(
            "d_critical's ioc_confidence factor reflects the real indexed value (85 -> 0.85)",
            any(
                f.name == "ioc_confidence" and f.normalized_value == 0.85
                for f in d_critical.risk_factors
            ),
        )
        check(
            "d_critical's asset_criticality factor reflects the real indexed value (critical -> 1.0)",
            any(
                f.name == "asset_criticality" and f.normalized_value == 1.0
                for f in d_critical.risk_factors
            ),
        )
        check(
            "d_low_asset's asset_criticality factor reflects the real indexed value (low -> 0.25)",
            any(
                f.name == "asset_criticality" and f.normalized_value == 0.25
                for f in d_low_asset.risk_factors
            ),
        )
        check(
            "identity_privilege factor is honestly absent on every real Detection produced this run",
            all(
                any(f.name == "identity_privilege" and f.normalized_value is None for f in d.risk_factors)
                for d in stored.values()
            ),
        )

    finally:
        try:
            await os_client._client.indices.delete(index=POC_INDEX, ignore_unavailable=True)  # noqa: SLF001
            log(f"cleaned up real PoC index {POC_INDEX}")
        finally:
            await os_client.close()

    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(f"PoC PASSED -- all {len(CHECKS)} checks passed against the real, live OpenSearch 2.11.1 cluster.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
