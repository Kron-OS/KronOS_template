"""Real StructuredArtifact fixture seeder for the Playwright E2E suite.

Inserts real StructuredArtifact rows via the real PostgresArtifactRepository
(never hand-written SQL, same reasoning as seed_detection.py) for a given
--case-id/--evidence-id. Content mirrors the actual real volatility3 output
already captured against cridex.vmem (poc/volatility_timeline_dual_emit/,
poc/volatility_pipeline_ingest/) -- the shape is real, not invented, only
the specific memory-image run itself is skipped here (already verified for
real in poc/volatility_timeline_dual_emit/, this only needs to prove the
Artifacts UI renders real data, not re-verify volatility3 itself).

Prints one JSON object to stdout. Diagnostics go to stderr.

Run: ~/venv/bin/python3 frontend/e2e/fixtures/seed_volatility_artifacts.py \
    --case-id <uuid> --evidence-id <uuid> [--org-alias kronos-dev]
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
from _e2e_env import KEYCLOAK_INTERNAL_URL, POSTGRES_DSN  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_artifact import PostgresArtifactRepository  # noqa: E402
from src.domain.artifact import StructuredArtifact  # noqa: E402
from src.domain.timeline import KronosProvenance  # noqa: E402

KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"

# Real rows, trimmed from the real captured cridex.vmem psscan output
# (poc/volatility_pipeline_ingest/artifact_verification.json) -- not
# invented field names/shapes.
_REAL_PSSCAN_ROWS = [
    {
        "PID": 908, "PPID": 652, "Wow64": False, "Handles": None, "Threads": 9,
        "ExitTime": None, "Offset(V)": 33725112, "SessionId": None,
        "CreateTime": "2012-07-22T02:42:33+00:00", "__children": [],
        "File output": "Disabled", "ImageFileName": "svchost.exe",
    },
    {
        "PID": 664, "PPID": 608, "Wow64": False, "Handles": None, "Threads": 24,
        "ExitTime": None, "Offset(V)": 33727416, "SessionId": None,
        "CreateTime": "2012-07-22T02:42:32+00:00", "__children": [],
        "File output": "Disabled", "ImageFileName": "lsass.exe",
    },
    {
        "PID": 652, "PPID": 608, "Wow64": False, "Handles": None, "Threads": 16,
        "ExitTime": None, "Offset(V)": 33729320, "SessionId": None,
        "CreateTime": "2012-07-22T02:42:32+00:00", "__children": [],
        "File output": "Disabled", "ImageFileName": "services.exe",
    },
]


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
    org_id: str, org_alias: str, case_id: str, evidence_id: str
) -> list[StructuredArtifact]:
    engine = create_async_engine(POSTGRES_DSN)
    repo = PostgresArtifactRepository(engine)
    await PostgresArtifactRepository.create_tables(engine)

    def _provenance(record_index: int) -> KronosProvenance:
        return KronosProvenance(
            evidence_id=uuid.UUID(evidence_id),
            case_id=uuid.UUID(case_id),
            org_id=uuid.UUID(org_id),
            org_alias=org_alias,
            sha256="02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d",
            parser="volatility3",
            parser_version="2.28.0",
            record_index=record_index,
            ingest_timestamp=datetime.now(UTC),
        )

    pstree = StructuredArtifact(
        kind="volatility.pstree",
        content={"plugin": "windows.pstree", "rows": []},
        kronos=_provenance(0),
    )
    psscan = StructuredArtifact(
        kind="volatility.psscan",
        content={"plugin": "windows.psscan", "rows": _REAL_PSSCAN_ROWS},
        kronos=_provenance(1),
    )
    saved = [await repo.save(pstree), await repo.save(psscan)]
    await engine.dispose()
    return saved


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--org-alias", default="kronos-dev")
    args = parser.parse_args()

    with httpx.Client(timeout=15) as client:
        token = get_admin_token(client)
        org_id = get_org_id(client, token, args.org_alias)
        log(f"resolved live org_id={org_id} for alias={args.org_alias}")

    saved = asyncio.run(seed(org_id, args.org_alias, args.case_id, args.evidence_id))
    log(
        f"seeded {len(saved)} real StructuredArtifact(s) "
        f"for case={args.case_id} evidence={args.evidence_id}"
    )

    print(
        json.dumps(
            {
                "caseId": args.case_id,
                "evidenceId": args.evidence_id,
                "artifactIds": [str(a.artifact_id) for a in saved],
            }
        )
    )


if __name__ == "__main__":
    main()
