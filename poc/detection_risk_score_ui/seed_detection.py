"""One-off seed: insert a single real Detection (with a real risk_score/
risk_factors) into the real Postgres detections table for the CURRENT
kronos-dev org, via the real PostgresDetectionRepository -- so the new
frontend riskScore UI can be verified live against real data. kronos-dev
has zero real detections today (org_id churns across dev-stack
recreations; a much older PoC's own detections belong to a now-orphaned
org_id no live Keycloak org maps to anymore).
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import create_async_engine

from src.adapter.repository.postgres_detection import PostgresDetectionRepository
from src.application.risk_scoring import DetectionRiskScorer
from src.domain.detection import Detection, DetectionRuleMatch

POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
KRONOS_DEV_ORG_ID = uuid.UUID("7a2d50db-f1bf-496e-8aff-16435cef14b1")


async def main() -> None:
    engine = create_async_engine(POSTGRES_DSN)
    repo = PostgresDetectionRepository(engine)
    await PostgresDetectionRepository.create_tables(engine)

    scorer = DetectionRiskScorer()
    breakdown = scorer.score(rule_severity="critical", ioc_confidence=85, asset_criticality="high")

    detection = Detection(
        org_id=KRONOS_DEV_ORG_ID,
        org_alias="kronos-dev",
        finding_id=f"poc-riskscore-ui-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-kronos-dev-network-detector",
        source_index="kronos-kronos-dev-stream-network-202608",
        rule_matches=(
            DetectionRuleMatch(
                rule_id="rule-suspicious-outbound",
                rule_name="Suspicious Outbound Connection to Known-Bad IOC",
                tags=("attack.t1071.001", "critical"),
            ),
        ),
        matched_document_ids=(f"doc-{uuid.uuid4().hex[:8]}",),
        finding_timestamp=datetime.now(UTC),
        risk_score=breakdown.score,
        risk_factors=breakdown.factors,
    )
    saved = await repo.save(detection)
    print(f"seeded real detection {saved.detection_id} org={saved.org_id} risk_score={saved.risk_score}")
    for f in saved.risk_factors:
        print(f"  factor: {f.name} weight={f.weight} normalized_value={f.normalized_value} detail={f.detail}")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
