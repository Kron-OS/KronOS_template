"""Real setup step for the detection-containment-UI PoC (Gap Audit Milestone
MM): resolves the CURRENT kronos-dev org id live (org_id churns across
dev-stack recreations, per poc/detection_risk_score_ui/README.md's own
warning -- never hardcode an old one), seeds one real Detection into the
real Postgres `detections` table for that org (mirrors
poc/detection_risk_score_ui/seed_detection.py), creates one real throwaway
Keycloak user in that org, and produces a real, live Keycloak session for
that user via a real scripted Authorization Code + PKCE login (mirrors
poc/revoke_session_route/run_poc.py's own real_login_get_session) -- this
is the "victim" session run_poc.py's Playwright script will actually
revoke through the real UI.

Prints a single JSON object to stdout so run_poc.py can consume it without
re-deriving any of this setup.

Run: ~/venv/bin/python3 poc/detection_containment_ui/setup.py
Requires docker-keycloak-1 (26.2.5) and docker-postgres-1 (16) already
running, and a fresh nginx/step-ca leaf cert (see CLAUDE.md's own
step_up ticket flow section / docs/NEXTGEN_SOC_ROADMAP.md SS5).
"""
from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "poc" / "auth_flow"))

import httpx  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

import auth_helpers as ah  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.risk_scoring import DetectionRiskScorer  # noqa: E402
from src.domain.detection import Detection, DetectionRuleMatch  # noqa: E402

KEYCLOAK_INTERNAL_URL = "http://localhost:8080"
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"
POSTGRES_DSN = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
KRONOS_DEV_ORG_ALIAS = "kronos-dev"


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


def create_target_user(client: httpx.Client, token: str, org_id: str, username: str, password: str) -> uuid.UUID:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "username": username,
            "email": f"{username}@example.invalid",
            "firstName": "PoC",
            "lastName": "MMTarget",
            "enabled": True,
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        },
    )
    resp.raise_for_status()
    user_id = uuid.UUID(resp.headers["Location"].rsplit("/", 1)[-1])
    member_resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/organizations/{org_id}/members",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        content=f'"{user_id}"',
    )
    member_resp.raise_for_status()
    return user_id


async def seed_detection(org_id: uuid.UUID) -> uuid.UUID:
    engine = create_async_engine(POSTGRES_DSN)
    repo = PostgresDetectionRepository(engine)
    await PostgresDetectionRepository.create_tables(engine)

    scorer = DetectionRiskScorer()
    breakdown = scorer.score(rule_severity="high", ioc_confidence=70, asset_criticality="medium")

    detection = Detection(
        org_id=org_id,
        org_alias=KRONOS_DEV_ORG_ALIAS,
        finding_id=f"poc-containment-ui-{uuid.uuid4().hex[:8]}",
        detector_name="kronos-kronos-dev-auth-detector",
        source_index="kronos-kronos-dev-stream-auth-202608",
        rule_matches=(
            DetectionRuleMatch(
                rule_id="rule-anomalous-login",
                rule_name="Anomalous Login From Compromised Credentials",
                tags=("attack.t1078", "high"),
            ),
        ),
        matched_document_ids=(f"doc-{uuid.uuid4().hex[:8]}",),
        finding_timestamp=datetime.now(UTC),
        risk_score=breakdown.score,
        risk_factors=breakdown.factors,
    )
    saved = await repo.save(detection)
    await engine.dispose()
    return saved.detection_id


def main() -> None:
    run_suffix = uuid.uuid4().hex[:8]
    target_username = f"poc-mm-target-{run_suffix}"
    target_password = "PocMmTarget#2026"

    with httpx.Client(timeout=15) as client:
        admin_token = get_admin_token(client)
        org_id = uuid.UUID(get_org_id(client, admin_token, KRONOS_DEV_ORG_ALIAS))
        log(f"resolved real kronos-dev org_id={org_id}")

        target_user_id = create_target_user(client, admin_token, str(org_id), target_username, target_password)
        log(f"created real throwaway target user {target_username} ({target_user_id})")

        detection_id = asyncio.run(seed_detection(org_id))
        log(f"seeded real detection {detection_id}")

        # Real scripted Authorization Code + PKCE login for the throwaway
        # target user -- produces a real, live Keycloak session (sid) that
        # run_poc.py's Playwright script will revoke via the real UI.
        ah.trust_dev_stack_step_ca("docker-tls-init-1")
        ah.KC = "https://kronos.local:8443"
        ah.REDIRECT_URI = "https://kronos.local/poc-mm-callback"
        tokens, _new_secret, mfa_path = ah.real_browser_login(
            target_username, target_password, totp_secret=None, state="poc-mm-target-login"
        )
        assert mfa_path in ("none", "setup"), f"unexpected mfa_path for a fresh user: {mfa_path}"
        claims = ah.decode_jwt_payload(tokens["access_token"])
        target_session_id = claims["sid"]
        log(f"real target session created: sid={target_session_id}")

    print(
        json.dumps(
            {
                "org_id": str(org_id),
                "detection_id": str(detection_id),
                "target_username": target_username,
                "target_user_id": str(target_user_id),
                "target_session_id": target_session_id,
            }
        )
    )


if __name__ == "__main__":
    main()
