#!/usr/bin/env python3
"""Verification-first PoC: G3 GATE -- explainability + replayability harness
(roadmap M6/G3, docs/NEXTGEN_SOC_ROADMAP.md).

Drives the real, unmodified production classes -- reusing the exact real
end-to-end patterns already established by poc/detection_risk_scoring/
(real OpenSearch 2.11.1 round-trip through DetectionSyncService) and
poc/rule_pack_lifecycle/ (real Postgres 16 round-trip through
RulePackService), not reimplementing them:

  DetectionRiskScorer, score_from_factors  (src/application/risk_scoring.py)
  Detection, DetectionRuleMatch            (src/domain/detection.py)
  DetectionSyncService                     (src/application/detection_sync.py)
  RuleCostGate                             (src/application/cost_gate.py)
  RulePackService                          (src/application/rule_pack_service.py)
  CustomRule, CostGateVerdict              (src/domain/rule_pack.py)
  BehavioralAnomalySignal                  (src/domain/anomaly.py)

Three claims proven here, each against real, live infrastructure:

  Claim 1a (F4): a Detection's frozen risk_score reproduces from its own
    frozen risk_factors tuple ALONE -- no re-fetch of the OpenSearch
    documents that originally supplied ioc_confidence/asset_criticality.
    Also proves the subtle negative: after those documents legitimately
    drift post-sync, a replay from the STORED factors is unaffected, while
    a live re-query would (correctly) see the drift -- replayability is
    defined over the frozen input, never live state.

  Claim 1b (C3): a CustomRule's frozen cost_gate_verdict reproduces from
    its own frozen sigma_yaml ALONE, re-evaluated through a brand new
    RuleCostGate instance.

  Claim 2 (G2 structural exclusion): none of the real Detection-related
    source files reference the anomaly module in any way, and
    BehavioralAnomalySignal's two non-reproducibility markers actually
    exist, actually enforce Literal[True] at construction time, and
    actually survive model_dump(mode="json") serialization.

Run: source ~/venv/bin/activate && python poc/explainability_replayability_gate/run_poc.py
Requires the real dev stack up (docker-opensearch-1 2.11.1, docker-postgres-1 16-alpine).
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

from pydantic import ValidationError  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.opensearch.findings_client import FindingsClient  # noqa: E402
from src.adapter.repository.detection import InMemoryDetectionRepository  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_rule_pack import PostgresRulePackRepository  # noqa: E402
from src.adapter.signing.cosign_verifier import CosignPackSignatureVerifier  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.cost_gate import RuleCostGate  # noqa: E402
from src.application.detection_sync import DetectionSyncService  # noqa: E402
from src.application.risk_scoring import DetectionRiskScorer, score_from_factors  # noqa: E402
from src.application.rule_pack_service import RulePackService  # noqa: E402
from src.domain.anomaly import AnomalyEntityDimension, BehavioralAnomalySignal  # noqa: E402
from src.domain.rule_pack import CostGateDecision  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from tests.conftest import InMemoryAuditLogRepository  # noqa: E402
from tests.fixtures.factories import make_tenant_context  # noqa: E402

OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
DB_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
POC_INDEX = f"kronos-poc-g3-replay-org-case-{uuid.uuid4().hex[:8]}-202608"

CHECKS: list[tuple[str, bool]] = []

# Real, working Sigma shapes reused verbatim from poc/rule_pack_lifecycle/
# (already confirmed there to be a genuinely reasonable rule vs. a
# genuinely expensive one, per src/application/cost_gate.py's own
# empirically-derived heuristics) -- new rule `id:`s only, to avoid any
# accidental collision with that PoC's own runs.
_REASONABLE_RULE = """
title: G3 PoC reasonable exact-match rule
id: 44444444-4444-4444-4444-444444444444
status: experimental
description: benign exact-match connection rule, used to prove cost-gate replay
author: kronos-g3-poc
references:
  - https://example.invalid/poc
date: 2026/08/03
logsource:
  product: zeek
  service: conn
detection:
  selection:
    id.resp_p: 4444
  condition: selection
falsepositives:
  - none, this is a PoC rule
level: medium
tags:
  - attack.t1000
"""

_EXPENSIVE_RULE = """
title: G3 PoC expensive leading-wildcard rule
id: 55555555-5555-5555-5555-555555555555
status: experimental
description: uses |contains, confirmed to compile to a leading-wildcard query
author: kronos-g3-poc
references:
  - https://example.invalid/poc
date: 2026/08/03
logsource:
  product: zeek
  service: conn
detection:
  selection:
    process.command_line|contains: 'evil'
  condition: selection
falsepositives:
  - none, this is a PoC rule
level: high
tags:
  - attack.t1000
"""

_DETECTION_RELATED_FILES = [
    "src/domain/detection.py",
    "src/application/detection_sync.py",
    "src/application/detection_triage.py",
    "src/adapter/repository/detection.py",
    "src/adapter/repository/postgres_detection.py",
    "src/external/routes/detections.py",
]


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}" + (f" -- {detail}" if detail else ""))


class _StaticFindingsClient(FindingsClient):
    """Returns a fixed list of real-shaped SA finding hits (same real shape
    poc/detection_risk_scoring/ and tests/unit/application/test_detection_sync.py
    already confirmed against a live cluster)."""

    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self._hits = hits

    async def fetch_org_findings(
        self, org_alias: str, log_types: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        return self._hits


def _real_finding_hit(
    finding_id: str, *, tags: list[str], related_doc_ids: list[str], source_index: str
) -> dict[str, Any]:
    return {
        "_index": ".opensearch-sap-network-findings-2026.08.03-1",
        "_id": finding_id,
        "_source": {
            "id": finding_id,
            "related_doc_ids": related_doc_ids,
            "correlated_doc_ids": related_doc_ids,
            "monitor_id": "poc-g3-monitor",
            "monitor_name": "kronos-poc-g3-network-detector",
            "index": source_index,
            "queries": [{"id": f"rule-{finding_id}", "name": f"rule-{finding_id}", "tags": tags}],
            "timestamp": int(datetime.now(UTC).timestamp() * 1000),
            "execution_id": None,
        },
    }


async def claim1a_f4_risk_score_replay() -> None:
    log("=== Claim 1a: F4 risk_score replays from STORED risk_factors alone (real OpenSearch) ===")
    os_client = OpenSearchClient(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
    )
    tenant = make_tenant_context()
    doc_id = f"poc-g3-doc-{uuid.uuid4()}"
    try:
        await os_client.ensure_index_template()

        indexed = await os_client.bulk_index(
            [
                (
                    POC_INDEX,
                    doc_id,
                    {
                        "@timestamp": datetime.now(UTC).isoformat(),
                        "enrichment": {
                            "ioc": {"matched": True, "confidence": 70, "ioc_type": "domain"},
                            "asset": {"criticality": "high", "environment": "production"},
                        },
                    },
                )
            ]
        )
        check("real bulk_index indexed the 1 real document", indexed == 1)
        await os_client._client.indices.refresh(index=POC_INDEX)  # noqa: SLF001

        finding = _real_finding_hit(
            "poc-g3-finding-1",
            tags=["critical", "network", "attack.t1071.001"],
            related_doc_ids=[doc_id],
            source_index=POC_INDEX,
        )
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        detection_repo = InMemoryDetectionRepository()
        service = DetectionSyncService(
            findings_client=_StaticFindingsClient([finding]),
            detection_repository=detection_repo,
            audit_log=audit_log,
            timeline_index=os_client,
            log_types=("network",),
            risk_scorer=DetectionRiskScorer(),
        )
        created = await service.sync_org_findings(tenant)
        check("real sync created exactly 1 new Detection", created == 1)

        stored = {d.finding_id: d async for d in detection_repo.stream_by_org(tenant.org_id)}
        detection = stored["poc-g3-finding-1"]
        log(f"original stored Detection.risk_score = {detection.risk_score}")
        for f in detection.risk_factors:
            log(
                f"  stored factor: {f.name} weight={f.weight} "
                f"normalized={f.normalized_value} detail={f.detail!r}"
            )

        # THE REPLAY: recompute from detection.risk_factors ALONE -- no
        # rule_severity/ioc_confidence/asset_criticality inputs at all, no
        # OpenSearch re-fetch of any kind.
        replayed_score = score_from_factors(detection.risk_factors)
        check(
            "replayed score (from stored risk_factors alone) == original stored risk_score, "
            "byte-identical",
            replayed_score == detection.risk_score,
            f"replayed={replayed_score} stored={detection.risk_score}",
        )

        # Now mutate the REAL underlying document's enrichment -- the exact
        # subtlety this claim must get right: a live re-fetch WOULD now
        # legitimately see a different value (asset criticality genuinely
        # changed), which is precisely why "replayable" must mean replaying
        # the FROZEN risk_factors, never re-querying live OpenSearch state.
        await os_client._client.update(  # noqa: SLF001
            index=POC_INDEX,
            id=doc_id,
            body={
                "doc": {
                    "enrichment": {
                        "asset": {"criticality": "low", "environment": "production"},
                        "ioc": {"matched": True, "confidence": 70, "ioc_type": "domain"},
                    }
                }
            },
        )
        await os_client._client.indices.refresh(index=POC_INDEX)  # noqa: SLF001
        live_doc = (await os_client.get_documents_by_id(POC_INDEX, [doc_id]))[doc_id]
        check(
            "sanity: the REAL underlying document's asset criticality legitimately "
            "changed post-sync (high -> low)",
            live_doc["enrichment"]["asset"]["criticality"] == "low",
        )
        replayed_after_drift = score_from_factors(detection.risk_factors)
        check(
            "replay from STORED risk_factors is UNAFFECTED by the live document's drift -- "
            "still reproduces the exact original stored score (this IS the replayability "
            "contract; re-querying live OpenSearch state would NOT reproduce it and would "
            "be testing the wrong thing)",
            replayed_after_drift == detection.risk_score,
        )
    finally:
        try:
            await os_client._client.indices.delete(
                index=POC_INDEX, ignore_unavailable=True
            )  # noqa: SLF001
            log(f"cleaned up real PoC index {POC_INDEX}")
        finally:
            await os_client.close()


async def claim1b_c3_cost_gate_replay() -> None:
    log(
        "=== Claim 1b: C3 cost_gate_verdict replays from STORED sigma_yaml alone "
        "(real Postgres) ==="
    )
    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    try:
        await PostgresRulePackRepository.create_tables(engine)
        await PostgresAuditLogRepository.create_tables(engine)
        repo = PostgresRulePackRepository(engine)
        audit_log = AuditLogService(PostgresAuditLogRepository(engine))
        cost_gate = RuleCostGate()
        signature_verifier = CosignPackSignatureVerifier()
        service = RulePackService(repo, cost_gate, signature_verifier, audit_log)

        tenant = TenantContext(
            org_id=uuid.uuid4(),
            org_alias=f"g3-poc-{uuid.uuid4().hex[:8]}",
            user_id=uuid.uuid4(),
            username="g3-poc",
            roles=frozenset({Role.ORG_ADMIN}),
            correlation_id=str(uuid.uuid4()),
        )

        accepted_rule = await service.add_custom_rule(
            tenant, "g3-poc-pack", "Reasonable rule", _REASONABLE_RULE, "network"
        )
        rejected_rule = await service.add_custom_rule(
            tenant, "g3-poc-pack", "Expensive rule", _EXPENSIVE_RULE, "network"
        )
        check(
            "accepted rule's stored cost_gate_verdict is ACCEPTED",
            accepted_rule.cost_gate_verdict.decision == CostGateDecision.ACCEPTED,
        )
        check(
            "rejected rule's stored cost_gate_verdict is REJECTED",
            rejected_rule.cost_gate_verdict.decision == CostGateDecision.REJECTED,
        )

        # THE REPLAY: re-parse + re-evaluate from stored sigma_yaml ALONE,
        # through a BRAND NEW RuleCostGate instance -- no reuse of any
        # in-memory state from the original evaluate() calls above.
        fresh_gate = RuleCostGate()
        replayed_accepted = fresh_gate.evaluate(accepted_rule.sigma_yaml)
        replayed_rejected = fresh_gate.evaluate(rejected_rule.sigma_yaml)

        check(
            "replayed verdict for the accepted rule == original stored verdict, "
            "byte-identical (decision + findings)",
            replayed_accepted == accepted_rule.cost_gate_verdict,
            f"replayed={replayed_accepted!r} stored={accepted_rule.cost_gate_verdict!r}",
        )
        check(
            "replayed verdict for the rejected rule == original stored verdict, "
            "byte-identical (decision + findings)",
            replayed_rejected == rejected_rule.cost_gate_verdict,
            f"replayed={replayed_rejected!r} stored={rejected_rule.cost_gate_verdict!r}",
        )
    finally:
        await engine.dispose()


def claim2_g2_structural_exclusion() -> None:
    log("=== Claim 2: G2 anomaly signals are structurally excluded from Detection-land ===")
    for rel_path in _DETECTION_RELATED_FILES:
        path = REPO_ROOT / rel_path
        text = path.read_text()
        check(
            f"{rel_path} contains no 'anomaly' substring (case-insensitive)",
            "anomaly" not in text.lower(),
        )

    check(
        "BehavioralAnomalySignal.NOT_REPRODUCIBLE class-level constant is True",
        BehavioralAnomalySignal.NOT_REPRODUCIBLE is True,
    )

    signal = BehavioralAnomalySignal(
        org_id=uuid.uuid4(),
        org_alias="g3-poc-org",
        detector_id="det-1",
        detector_name="poc-detector",
        entities=(AnomalyEntityDimension(name="host.name", value="host-anomalous"),),
        anomaly_grade=0.9,
        confidence=0.7,
        data_start_time=datetime.now(UTC),
        data_end_time=datetime.now(UTC),
    )
    check(
        "BehavioralAnomalySignal instance's not_reproducible field is True",
        signal.not_reproducible is True,
    )

    dumped = signal.model_dump(mode="json")
    check(
        "model_dump(mode='json') retains not_reproducible == True (survives serialization "
        "to what an actual API response body would carry)",
        dumped.get("not_reproducible") is True,
    )
    check(
        "model_dump(mode='json') correctly excludes the class-level NOT_REPRODUCIBLE "
        "ClassVar from instance data (it is not a per-instance field)",
        "NOT_REPRODUCIBLE" not in dumped,
    )

    rejected = False
    try:
        BehavioralAnomalySignal(
            org_id=uuid.uuid4(),
            org_alias="g3-poc-org",
            detector_id="det-1",
            detector_name="poc-detector",
            anomaly_grade=0.5,
            data_start_time=datetime.now(UTC),
            data_end_time=datetime.now(UTC),
            not_reproducible=False,  # type: ignore[arg-type]
        )
    except ValidationError:
        rejected = True
    check(
        "constructing a BehavioralAnomalySignal with not_reproducible=False is REJECTED "
        "by pydantic's Literal[True] validation -- the marker cannot be forged even by a "
        "caller that tries",
        rejected,
    )


async def main() -> int:
    await claim1a_f4_risk_score_replay()
    await claim1b_c3_cost_gate_replay()
    claim2_g2_structural_exclusion()

    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"GATE FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(f"GATE PASSED -- all {len(CHECKS)} checks passed against real, live infrastructure.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
