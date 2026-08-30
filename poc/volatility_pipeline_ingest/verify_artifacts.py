"""Poll the volatility ingestion test's evidence to a terminal state, then
query Postgres's real `structured_artifacts` table directly (there is no
HTTP read API for StructuredArtifact yet -- confirmed by grepping every
route in src/external/routes/ and every frontend component, and this is
intentional per CLAUDE.md Section G.2, not a gap) to verify real rows
landed with the correct provenance, not just that the evidence reached
COMPLETE.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import asyncpg
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
import auth_helpers  # noqa: E402

auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "http://localhost:8000"
POSTGRES_DSN = os.environ.get(
    "KRONOS_POC_POSTGRES_DSN", "postgresql://kronos:kronos_dev_password@localhost:5432/kronos"
)


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def poll_to_terminal(client: httpx.Client, case_id: str, evidence_id: str, deadline_s: int) -> dict[str, Any]:
    """Real HEAVY-tier Plaso-queue analysis of a 512 MiB memory image is a
    materially larger real job than any prior spec in this initiative
    (evidence-upload-heavy-parser*.spec.ts's largest fixture is the 62 KiB
    kape_triage.E01) -- budgeted well past parse_artefact_heavy's own real
    soft_time_limit=540/time_limit=600 (src/external/celery_app.py), not
    reused from a smaller PoC's own tighter deadline.
    """
    terminal = {"COMPLETE", "ERROR"}
    deadline = time.time() + deadline_s
    last: dict[str, Any] = {}
    while time.time() < deadline:
        resp = client.get(f"/api/cases/{case_id}/evidence", params={"pageSize": 50})
        resp.raise_for_status()
        items = {it["id"]: it for it in resp.json()["items"]}
        if evidence_id in items:
            last = items[evidence_id]
            log(f"state={last['state']}")
            if last["state"] in terminal:
                return last
        time.sleep(10)
    raise TimeoutError(f"evidence {evidence_id} did not reach a terminal state within {deadline_s}s")


async def fetch_artifact_rows(evidence_id: str) -> list[dict[str, Any]]:
    conn = await asyncpg.connect(POSTGRES_DSN)
    try:
        rows = await conn.fetch(
            "SELECT artifact_id, evidence_id, case_id, org_id, kind, sha256, parser, "
            "parser_version, source_path, container_sha256, record_index, content, created_at "
            "FROM structured_artifacts WHERE evidence_id = $1 ORDER BY record_index",
            evidence_id,
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


def main() -> None:
    with open(Path(__file__).parent / "evidence_ids.json") as f:
        prior = json.load(f)
    case_id = prior["case_id"]
    evidence_id = prior["evidence_id"]

    tokens, _, _ = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="volatility-poll-1"
    )
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=60)

    final = poll_to_terminal(client, case_id, evidence_id, deadline_s=900)
    (Path(__file__).parent / "final_state.json").write_text(json.dumps(final, indent=2))
    log(f"final state: {final['state']}")

    rows = asyncio.run(fetch_artifact_rows(evidence_id))
    log(f"fetched {len(rows)} real structured_artifacts row(s) for evidence_id={evidence_id}")

    by_kind: dict[str, int] = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        # JSONB content and datetime aren't JSON-serializable as-is via
        # default json.dumps -- normalize for the summary file below.
        r["created_at"] = r["created_at"].isoformat()
        r["artifact_id"] = str(r["artifact_id"])
        r["evidence_id"] = str(r["evidence_id"])
        r["case_id"] = str(r["case_id"])
        r["org_id"] = str(r["org_id"])
        r["content"] = json.loads(r["content"]) if isinstance(r["content"], str) else r["content"]

    log(f"by kind: {by_kind}")

    # Real, already-verified finding from poc/volatility_memory_module/:
    # windows.pstree returns zero rows for this exact sample+version (a
    # real Volatility3/XP-era interop limitation, not a KronOS bug), so
    # the fallback plugin (windows.psscan, 17 real process rows) is what
    # this cridex.vmem sample is expected to actually populate.
    # StructuredArtifact.content shape (src/external/parsers/volatility.py
    # ::_build_artifact): {"plugin": <name>, "rows": [<real vol3 JSON rows>]}
    psscan_rows = [r for r in rows if r["kind"] == "volatility.psscan"]
    psscan_process_count = sum(len(r["content"].get("rows", [])) for r in psscan_rows)

    all_evidence_ids_match = all(r["evidence_id"] == evidence_id for r in rows)
    all_case_ids_match = all(r["case_id"] == case_id for r in rows)
    all_sha256_match = all(r["sha256"] == prior["sha256"] for r in rows)

    summary = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "final_evidence_state": final["state"],
        "structured_artifact_row_count": len(rows),
        "by_kind": by_kind,
        "psscan_process_count": psscan_process_count,
        "all_rows_evidence_id_matches": all_evidence_ids_match,
        "all_rows_case_id_matches": all_case_ids_match,
        "all_rows_sha256_matches_upload": all_sha256_match,
        "verdict": (
            "PASS"
            if final["state"] == "COMPLETE"
            and len(rows) > 0
            and all_evidence_ids_match
            and all_case_ids_match
            and all_sha256_match
            else "FAIL"
        ),
    }
    (Path(__file__).parent / "artifact_verification.json").write_text(
        json.dumps({"summary": summary, "rows": rows}, indent=2)
    )
    log("verdict:", summary["verdict"])
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
