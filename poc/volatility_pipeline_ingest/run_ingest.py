"""Real end-to-end VolatilityModule ingestion test against the live dev-stack
backend: real login -> real case creation -> real upload/finalize of the
real 512 MiB `cridex.vmem` sample -> autonomous pipeline (q.intake ->
q.parse.plaso -> VolatilityModule.extract_artifacts() ->
ArtifactIngestService -> Postgres) -> caller polls to COMPLETE and then runs
verify_artifacts.py to confirm real StructuredArtifact rows landed.

Closes the gap poc/volatility_memory_module/README.md's own "Gaps / honestly
out of scope this pass" section named explicitly: "Full HTTP upload ->
validate -> parse -> Postgres pipeline was not driven end-to-end... Wiring
through ArtifactIngestService/Postgres/the Celery q.parse.plaso queue for
real is the natural next verification step." Milestone VVV's own
recommendation #1 pointed at exactly this.

The real sample (`cridex.vmem`, 536,870,912 bytes) is -- deliberately, same
as the original PoC -- NOT committed to this repo (see that PoC's own
README for the real download URL/sha256). Streamed from disk for both the
sha256 pass and the presigned-PUT upload rather than loaded fully into
memory twice: this host runs with real, non-trivial memory pressure
(confirmed via `free -h` before running this -- ~1.4 GiB free, swap already
in use) alongside the always-on dev stack, so a 512 MiB `read_bytes()`
(the pattern poc/kape_ingestion_test/run_kape_ingest.py uses for its much
smaller ~25-62 KiB fixtures) was a real, avoidable risk here, not a style
preference.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "full_ingestion_test"))
import auth_helpers  # noqa: E402

# Same real, reproduced findings as poc/kape_ingestion_test/run_kape_ingest.py
# (see that file's own comments for the full rationale): kronos.local is the
# sole authorized redirect origin, and the dev stack's step-ca root must be
# trusted for httpx to accept its leaf certs.
auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "http://localhost:8000"
REPO_ROOT = Path(__file__).resolve().parents[2]

_DEFAULT_VMEM = "/home/reca/scratch/kronos-poc-volatility/cridex.vmem"
VMEM_PATH = Path(os.environ.get("KRONOS_CRIDEX_VMEM_PATH", _DEFAULT_VMEM))

_CHUNK = 8 * 1024 * 1024  # 8 MiB read chunks -- bounded memory for the sha256 pass


def log(*args: object) -> None:
    print(*args, file=sys.stderr)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if not VMEM_PATH.is_file():
        raise SystemExit(
            f"Real sample not found at {VMEM_PATH}. Download per "
            f"poc/volatility_memory_module/README.md's own instructions, or "
            f"set KRONOS_CRIDEX_VMEM_PATH."
        )

    size_bytes = VMEM_PATH.stat().st_size
    log(f"real sample: {VMEM_PATH} ({size_bytes} bytes)")
    sha256 = sha256_of(VMEM_PATH)
    log(f"real sha256: {sha256}")

    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="volatility-ingest-1"
    )
    log(f"login OK (mfa_path={mfa_path})")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client = httpx.Client(base_url=BACKEND, headers=headers, timeout=120)

    resp = client.post(
        "/api/cases",
        json={
            "title": "Volatility memory-forensics pipeline ingestion test",
            "description": (
                "Real upload/finalize of the real cridex.vmem sample, verifying "
                "VolatilityModule.extract_artifacts() -> ArtifactIngestService -> "
                "Postgres structured_artifacts, end to end through the real "
                "autonomous pipeline (closes poc/volatility_memory_module/'s own "
                "documented 'full pipeline not driven end-to-end' gap)."
            ),
            "classification": "UNCLASSIFIED",
        },
    )
    log("create_case ->", resp.status_code, resp.text[:400])
    resp.raise_for_status()
    case_id = resp.json()["id"]
    log(f"case_id={case_id}")

    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": VMEM_PATH.name,
            "contentType": "application/octet-stream",
            "sizeBytes": size_bytes,
            "caseId": case_id,
        },
    )
    log("upload/request ->", resp.status_code, resp.text[:300])
    resp.raise_for_status()
    upload = resp.json()
    evidence_id = upload["evidenceId"]

    # Stream the PUT body from disk (httpx accepts a file-like object for
    # `content`) -- same reasoning as the module docstring above.
    with VMEM_PATH.open("rb") as f:
        put_resp = httpx.put(
            upload["presignedUrl"], content=f, timeout=300, verify=auth_helpers.CA_BUNDLE
        )
    log("PUT to MinIO ->", put_resp.status_code)
    put_resp.raise_for_status()

    resp = client.post(
        f"/api/evidence/upload/finalize/{evidence_id}",
        json={"client_sha256": sha256},
    )
    log("finalize ->", resp.status_code, resp.text[:300])
    resp.raise_for_status()

    out = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "filename": VMEM_PATH.name,
        "sha256": sha256,
        "size_bytes": size_bytes,
    }
    out_path = Path(__file__).parent / "evidence_ids.json"
    out_path.write_text(json.dumps(out, indent=2))
    log(f"wrote {out_path}")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
