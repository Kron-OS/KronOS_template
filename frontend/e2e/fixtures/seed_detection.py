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
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402

# Milestone PPP: KEYCLOAK_INTERNAL_URL/POSTGRES_DSN moved to the shared
# _e2e_env.py -- see that module's own docstring for why (Milestone OOO's
# real incident: this exact override existed here but not yet in the
# sibling seed_second_org.py, for a whole cycle).
from _e2e_env import (  # noqa: E402
    KEYCLOAK_INTERNAL_URL,
    OPENSEARCH_HOST,
    OPENSEARCH_PASSWORD,
    OPENSEARCH_PORT,
    OPENSEARCH_USERNAME,
    POSTGRES_DSN,
)
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.risk_scoring import DetectionRiskScorer  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch, DetectionTriageState  # noqa: E402

KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"


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


async def seed(
    org_id: str,
    org_alias: str,
    rule_name: str,
    triage_state: str = "NEW",
    query: str | None = None,
    severity: str = "critical",
) -> Detection:
    engine = create_async_engine(POSTGRES_DSN)
    repo = PostgresDetectionRepository(engine)
    await PostgresDetectionRepository.create_tables(engine)

    scorer = DetectionRiskScorer()
    breakdown = scorer.score(rule_severity=severity, ioc_confidence=85, asset_criticality="high")

    source_index = f"kronos-{org_alias}-stream-network-e2e"
    matched_doc_id = f"doc-{uuid.uuid4().hex[:8]}"

    # `triage_state` defaults to NEW (Detection's own Pydantic default) --
    # `repo.save()` is a plain initial insert, not a `with_triage_state()`
    # FSM transition, so setting it directly here to seed a detection that
    # already sits at a non-NEW state (e.g. for visual-regression coverage
    # of every real TriageStatePill color, Milestone JJJJ) is not bypassing
    # any real transition validation -- there is none to bypass at insert
    # time, the same way a real detector sync could plausibly (if rarely)
    # observe a detection already resolved elsewhere.
    detection = Detection(
        org_id=uuid.UUID(org_id),
        org_alias=org_alias,
        finding_id=f"e2e-triage-{uuid.uuid4().hex[:8]}",
        detector_name=f"kronos-{org_alias}-network-detector",
        source_index=source_index,
        rule_matches=(
            DetectionRuleMatch(
                rule_id="rule-e2e-suspicious-outbound",
                rule_name=rule_name,
                tags=("attack.t1071.001", severity),
                # Gap Audit Milestone BBBBB: real findings carry a compiled
                # OpenSearch query DSL string per matched rule (verified
                # live -- poc/detection_finding_sync/output.txt). None by
                # default here mirrors an honestly-pre-BBBBB-shaped row;
                # callers exercising the "why triggered" UI pass one.
                query=query,
            ),
        ),
        matched_document_ids=(matched_doc_id,),
        finding_timestamp=datetime.now(UTC),
        risk_score=breakdown.score,
        risk_factors=breakdown.factors,
        triage_state=DetectionTriageState(triage_state),
    )
    saved = await repo.save(detection)
    await engine.dispose()

    # Gap Audit Milestone BBBBB: index one real matching document via the
    # real OpenSearchClient (not a hand-rolled HTTP PUT) so
    # GET /{id}/matched-events -- itself a real get_documents_by_id _mget
    # call -- has genuine content to return; without this the matched
    # events UI is legitimately, honestly empty for every seeded detection,
    # which defeats the point of a spec that exercises it.
    opensearch = OpenSearchClient(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        use_ssl=True,
        verify_certs=False,
    )
    await opensearch.bulk_index(
        [
            (
                source_index,
                matched_doc_id,
                {
                    "@timestamp": datetime.now(UTC).isoformat(),
                    "event": {"kind": "event", "category": ["network"], "type": ["connection"]},
                    "message": f"E2E seeded matched event for {rule_name}",
                    "source": {"ip": "203.0.113.7", "port": 51234},
                    "destination": {"ip": "10.0.0.5", "port": 3389},
                },
            )
        ]
    )
    await opensearch.close()

    return saved


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--org-alias", default="kronos-dev")
    parser.add_argument("--rule-name", default="E2E Suspicious Outbound Connection")
    parser.add_argument(
        "--triage-state",
        default="NEW",
        choices=[s.value for s in DetectionTriageState],
        help="Seed the detection already at this triage state (Milestone JJJJ: visual-regression "
        "coverage of every real TriageStatePill color needs detections at all 4 states, not just NEW).",
    )
    parser.add_argument(
        "--query",
        default=None,
        help="Gap Audit Milestone BBBBB: real compiled OpenSearch query DSL string for the matched "
        "rule -- omit to seed an honest pre-BBBBB-shaped row (query=None).",
    )
    parser.add_argument(
        "--severity",
        default="critical",
        help="Gap Audit Milestone BBBBB: real Sigma severity tag (SIGMA_SEVERITY_LEVELS) -- for "
        "exercising the severity filter dropdown.",
    )
    args = parser.parse_args()

    with httpx.Client(timeout=15) as client:
        token = get_admin_token(client)
        org_id = get_org_id(client, token, args.org_alias)
        log(f"resolved live org_id={org_id} for alias={args.org_alias}")

    saved = asyncio.run(
        seed(
            org_id,
            args.org_alias,
            args.rule_name,
            args.triage_state,
            query=args.query,
            severity=args.severity,
        )
    )
    log(f"seeded real detection {saved.detection_id} org={saved.org_id} risk_score={saved.risk_score} "
        f"triage_state={saved.triage_state}")

    print(json.dumps({"detectionId": str(saved.detection_id), "orgId": str(saved.org_id), "ruleName": args.rule_name}))


if __name__ == "__main__":
    main()
