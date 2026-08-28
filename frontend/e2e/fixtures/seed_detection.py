"""Real detection fixture seeder for the Playwright E2E suite.

Reuses two already-proven patterns rather than re-deriving them:
- Live org_id resolution via Keycloak Admin REST
  (poc/detection_containment_ui/setup.py's get_admin_token/get_org_id) --
  org_id churns across dev-stack recreations
  (poc/detection_risk_score_ui/README.md), so a hardcoded id is a real,
  already-reproduced bug waiting to happen, not a hypothetical.
- Inserting through the real PostgresDetectionRepository + DetectionRiskScorer
  domain code (poc/detection_risk_score_ui/seed_detection.py), not
  hand-written SQL -- if the `detections` table schema ever changes, this
  stays correct automatically instead of silently drifting out of sync
  with a second, parallel INSERT statement.

Prints one JSON object to stdout so frontend/e2e/DetectionSeeder.ts can
consume it without re-deriving any of this. All diagnostic output goes to
stderr.

Run: ~/venv/bin/python3 frontend/e2e/fixtures/seed_detection.py [--org-alias kronos-dev] [--rule-name "..."]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.risk_scoring import DetectionRiskScorer  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch  # noqa: E402

# Both docker-compose.dev.yml and .test.yml publish keycloak on host 8080
# unremapped, so this is correct for either alone. Overridable (same
# reasoning as POSTGRES_DSN below) for the one case it isn't: verifying
# against an isolated, differently-port-mapped test-stack instance on a
# host that also has the real dev stack's own keycloak already holding
# 8080 -- not a real CI gap, CI only ever runs one stack at a time.
KEYCLOAK_INTERNAL_URL = os.environ.get("KRONOS_E2E_KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
# Milestone NNN: this hardcoded dev-stack-only DSN was a real, confirmed
# blocker running this script against docker-compose.test.yml for the
# first time -- that profile's Postgres uses a different password AND
# database name (kronos_test_password / kronos_test, not
# kronos_dev_password / kronos), same host port. Overridable rather than
# a second hardcoded constant, matching pythonFixture.ts's own
# KRONOS_E2E_PYTHON precedent, so CI can point this at whichever real
# stack it's running against without a second copy of this script.
POSTGRES_DSN = os.environ.get(
    "KRONOS_E2E_POSTGRES_DSN",
    "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos",
)


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}", file=sys.stderr)


def get_admin_token(client: httpx.Client) -> str:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
            "client_secret": KEYCLOAK_ADMIN_CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_org_id(client: httpx.Client, token: str, alias: str) -> str:
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations?first=0&max=1000",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    for org in resp.json():
        if org["alias"] == alias:
            return org["id"]
    raise RuntimeError(f"org alias {alias} not found")


async def seed(org_id: str, org_alias: str, rule_name: str) -> Detection:
    engine = create_async_engine(POSTGRES_DSN)
    repo = PostgresDetectionRepository(engine)
    await PostgresDetectionRepository.create_tables(engine)

    scorer = DetectionRiskScorer()
    breakdown = scorer.score(rule_severity="critical", ioc_confidence=85, asset_criticality="high")

    detection = Detection(
        org_id=uuid.UUID(org_id),
        org_alias=org_alias,
        finding_id=f"e2e-triage-{uuid.uuid4().hex[:8]}",
        detector_name=f"kronos-{org_alias}-network-detector",
        source_index=f"kronos-{org_alias}-stream-network-e2e",
        rule_matches=(
            DetectionRuleMatch(
                rule_id="rule-e2e-suspicious-outbound",
                rule_name=rule_name,
                tags=("attack.t1071.001", "critical"),
            ),
        ),
        matched_document_ids=(f"doc-{uuid.uuid4().hex[:8]}",),
        finding_timestamp=datetime.now(UTC),
        risk_score=breakdown.score,
        risk_factors=breakdown.factors,
    )
    saved = await repo.save(detection)
    await engine.dispose()
    return saved


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--org-alias", default="kronos-dev")
    parser.add_argument("--rule-name", default="E2E Suspicious Outbound Connection")
    args = parser.parse_args()

    with httpx.Client(timeout=15) as client:
        token = get_admin_token(client)
        org_id = get_org_id(client, token, args.org_alias)
        log(f"resolved live org_id={org_id} for alias={args.org_alias}")

    saved = asyncio.run(seed(org_id, args.org_alias, args.rule_name))
    log(f"seeded real detection {saved.detection_id} org={saved.org_id} risk_score={saved.risk_score}")

    print(json.dumps({"detectionId": str(saved.detection_id), "orgId": str(saved.org_id), "ruleName": args.rule_name}))


if __name__ == "__main__":
    main()
