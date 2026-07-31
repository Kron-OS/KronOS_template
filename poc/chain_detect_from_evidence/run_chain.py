"""L3 chain PoC (roadmap M2/C5, docs/NEXTGEN_SOC_ROADMAP.md):

    evidence upload -> real Celery-driven parse -> real OpenSearch indexing
    -> a real Security Analytics detector actually firing -> C4's
    DetectionSyncService picking up that real finding -> a real Detection
    row in Postgres with the correct org_id/case_id and a real ATT&CK tag.

This is a CHAIN item: it imports and calls the real, already-separately-
verified classes each earlier item shipped (EvidenceIntakeService via the
real HTTP API, SecurityAnalyticsFindingsClient, DetectionSyncService,
PostgresDetectionRepository) -- it does not reimplement any of them, and it
is not the first real run of any of these components (see C1/C2/C4 status
notes in docs/NEXTGEN_SOC_ROADMAP.md and their own poc/ dirs).

Two genuinely FRESH pieces of evidence are uploaded into a brand-new case
created by this run (not reusing any already-parsed/already-indexed sample
sitting in OpenSearch/Postgres from an earlier PoC pass):

  - tests/fixtures/samples/real/system.evtx        (evtx-rs -> windows log type)
  - tests/fixtures/samples/real/suricata/eve.json  (SuricataEveParser -> network log type)

Both are known-good real rule-firers from C1's measurement
(poc/security_analytics_field_mappings/README.md: windows 3/1580 rules
fired incl. t1006/t1212/t1110.003; network 1/38 fired, t1021.001) -- reused
deliberately so this run measures the detect->sync->Detection link with a
sample already known to produce real findings, rather than re-litigating
C1's coverage-percentage question (which is explicitly still open for
cloudtrail and is not this item's job to resolve).

Per C2's documented, real, unresolved kronos-dev legacy-index gap
(poc/detector_provisioning/README.md): creating a detector over the
*org-wide* wildcard `kronos-kronos-dev-*` 500s on this dev org's ~40
pre-A1-mapped legacy indices. This run does NOT hit that path -- it follows
the exact same documented workaround C1 and C4 both already used: a
detector scoped to just THIS run's own new case index pattern
(`kronos-kronos-dev-case-<case_id>-*`), named with the *same*
`kronos-{org_alias}-{log_type}-detector` convention DetectionSyncService's
naming-based lookup expects (src/adapter/opensearch/findings_client.py),
so the real, unmodified DetectionSyncService can find it with zero code
changes. POST /api/cases is still exercised for real first, to prove (or
disprove, for real) that the *route-wired* C2 auto-provisioner
(ensure_org_detectors(), called from create_case()) still behaves exactly
as C2 already documented under this same known condition -- caught,
logged, and non-blocking, not a new bug.

Run: source ~/venv/bin/activate && python poc/chain_detect_from_evidence/run_chain.py
Requires the real dev stack up. If HTTPS calls to kronos.local fail with a
certificate-expired error: docker compose -f docker/docker-compose.dev.yml
up -d tls-init && docker restart docker-nginx-1, then retry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.adapter.opensearch.findings_client import SecurityAnalyticsFindingsClient  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sync import DetectionSyncService  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402

sys.path.insert(0, str(REPO_ROOT / "poc" / "auth_flow"))
import auth_helpers  # noqa: E402

auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()

BACKEND = "https://kronos.local"
OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")
DB_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

SAMPLES = {
    "windows": {
        "path": REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "system.evtx",
        "upload_name": f"chain-c5-{uuid.uuid4().hex[:8]}.evtx",
        "content_type": "application/octet-stream",
    },
    "network": {
        "path": REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "suricata" / "eve.json",
        "upload_name": f"chain-c5-{uuid.uuid4().hex[:8]}-eve.json",
        "content_type": "application/json",
    },
}

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def log(*a: object) -> None:
    print(*a, file=sys.stderr)


# ---------------------------------------------------------------------------
# Step 1: real login
# ---------------------------------------------------------------------------


def real_login() -> tuple[httpx.Client, dict]:
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state="chain-c5-poc"
    )
    claims = auth_helpers.decode_jwt_payload(tokens["access_token"])
    log(f"login OK (mfa_path={mfa_path})")
    log(f"token claims: org_id={claims.get('org_id')} sub={claims.get('sub')} roles={claims.get('roles')}")
    client = httpx.Client(
        base_url=BACKEND,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        verify=auth_helpers.CA_BUNDLE,
        timeout=60,
    )
    return client, claims


# ---------------------------------------------------------------------------
# Step 2: real case creation (exercises the real route-wired C2 auto-provisioner)
# ---------------------------------------------------------------------------


def create_fresh_case(client: httpx.Client) -> str:
    resp = client.post(
        "/api/cases",
        json={"title": f"C5 chain PoC {uuid.uuid4().hex[:8]}", "description": "L3 evidence->detect->Detection chain"},
    )
    check("real POST /api/cases succeeds (201) despite kronos-dev's known C2 legacy-index gap", resp.status_code == 201, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    case_id = resp.json()["id"]
    log(f"created fresh case {case_id}")
    return case_id


# ---------------------------------------------------------------------------
# Step 3: real, fresh evidence upload + finalize (autonomous pipeline from here)
# ---------------------------------------------------------------------------


def upload_and_finalize(client: httpx.Client, case_id: str, log_type: str) -> str:
    spec = SAMPLES[log_type]
    data = spec["path"].read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    resp = client.post(
        "/api/evidence/upload/request",
        json={
            "filename": spec["upload_name"],
            "contentType": spec["content_type"],
            "sizeBytes": len(data),
            "caseId": case_id,
        },
    )
    check(f"[{log_type}] upload/request -> 201", resp.status_code == 201, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    upload = resp.json()
    evidence_id = upload["evidenceId"]

    put_resp = httpx.put(upload["presignedUrl"], content=data, timeout=60, verify=auth_helpers.CA_BUNDLE)
    check(f"[{log_type}] real presigned PUT to MinIO succeeds", put_resp.status_code in (200, 204), f"status={put_resp.status_code}")

    resp = client.post(f"/api/evidence/upload/finalize/{evidence_id}", json={"client_sha256": sha256})
    check(f"[{log_type}] finalize_upload -> 202 (triggers the autonomous pipeline, E.1)", resp.status_code == 202, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    log(f"[{log_type}] evidence_id={evidence_id} sha256={sha256} finalize -> {resp.json()}")
    return evidence_id


def poll_until_complete(client: httpx.Client, case_id: str, evidence_ids: dict[str, str], timeout_s: int = 300) -> dict[str, str]:
    """Poll GET /api/cases/{id}/evidence -- the ONLY client responsibility
    after finalize per CLAUDE.md E.2 is SSE subscription; this PoC polls the
    same read-only listing endpoint instead of wiring SSE, since the goal
    here is a scripted proof run, not the real-time UI itself (SSE realtime
    already has its own L1 proof, poc/evidence_sse_realtime/)."""
    deadline = time.time() + timeout_s
    states: dict[str, str] = {}
    while time.time() < deadline:
        resp = client.get(f"/api/cases/{case_id}/evidence")
        resp.raise_for_status()
        items = resp.json()["items"]
        by_id = {i["id"]: i["state"] for i in items}
        states = {log_type: by_id.get(eid, "?") for log_type, eid in evidence_ids.items()}
        log(f"poll: {states}")
        if all(s in ("COMPLETE", "ERROR") for s in states.values()):
            break
        time.sleep(5)
    return states


# ---------------------------------------------------------------------------
# Step 4: real case-scoped detectors (admin creds, A3-compliant), named to
# match DetectionSyncService's naming convention exactly.
# ---------------------------------------------------------------------------


def fetch_prepackaged_rule_ids(sa_client: httpx.Client, log_type: str) -> list[str]:
    resp = sa_client.post(
        "/_plugins/_security_analytics/rules/_search",
        params={"pre_packaged": "true"},
        json={"size": 10000, "query": {"nested": {"path": "rule", "query": {"match": {"rule.category": log_type}}}}},
    )
    resp.raise_for_status()
    return [hit["_id"] for hit in resp.json().get("hits", {}).get("hits", [])]


def create_case_scoped_detector(sa_client: httpx.Client, org_alias: str, log_type: str, case_id: str) -> str:
    name = f"kronos-{org_alias}-{log_type}-detector"
    rule_ids = fetch_prepackaged_rule_ids(sa_client, log_type)
    check(f"[{log_type}] fetched real prepackaged rule ids", len(rule_ids) > 0, f"count={len(rule_ids)}")
    body = {
        "name": name,
        "detector_type": log_type,
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [
            {
                "detector_input": {
                    "description": f"C5 chain PoC case-scoped detector ({log_type})",
                    "indices": [f"kronos-kronos-dev-case-{case_id}-*"],
                    "pre_packaged_rules": [{"id": rid} for rid in rule_ids],
                    "custom_rules": [],
                }
            }
        ],
        "triggers": [],
    }
    resp = sa_client.post("/_plugins/_security_analytics/detectors", json=body)
    check(f"[{log_type}] real detector created, case-scoped index (sidesteps C2's documented kronos-dev legacy-index gap)", resp.status_code == 201, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    detector_id = resp.json()["_id"]
    log(f"[{log_type}] detector {name} id={detector_id}")
    return detector_id


def delete_detector(sa_client: httpx.Client, detector_id: str) -> None:
    sa_client.delete(f"/_plugins/_security_analytics/detectors/{detector_id}")


# ---------------------------------------------------------------------------
# Step 5: wait for the real detector to actually fire
# ---------------------------------------------------------------------------


def poll_for_findings(sa_client: httpx.Client, detector_names: list[str], case_id: str, timeout_s: int = 300) -> dict:
    """Poll for real findings tied to THIS run's own fresh case.

    Real gotcha hit while building this PoC (documented in README.md):
    `monitor_name` alone is NOT enough to isolate this run's genuinely-fresh
    findings, because DetectionSyncService's naming convention
    (kronos-{org_alias}-{log_type}-detector) is necessarily the SAME name
    an earlier, unrelated PoC run (poc/detection_finding_sync/) already used
    for `kronos-kronos-dev-network-detector` -- and per that PoC's own
    documented cleanup policy, deleting a detector does NOT delete the real
    findings it already produced, so 10 stale real findings from that
    earlier run are still sitting in `.opensearch-sap-network-findings-*`
    under the exact same monitor_name this run's new (different!) detector
    also uses. A `terms: monitor_name` query alone returned those 10 stale
    hits immediately, before this run's own detector had even had its first
    scheduled execution -- a false positive for "did MY detector fire".
    Fixed by additionally requiring the finding's own `index` field (a real,
    flat keyword field -- confirmed in findings_client.py's own docstring)
    to contain this run's actual fresh case_id -- the same signal
    DetectionSyncService._extract_case_id() itself parses out of a finding,
    so this is not inventing a new correlation mechanism, just applying the
    real one earlier in the PoC to disambiguate stale vs. fresh.
    """
    deadline = time.time() + timeout_s
    last: dict = {}
    while time.time() < deadline:
        resp = sa_client.post(
            "/.opensearch-sap-*-findings-*/_search",
            json={
                "size": 50,
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"monitor_name": detector_names}},
                            {"wildcard": {"index": f"*case-{case_id}-*"}},
                        ]
                    }
                },
            },
        )
        if resp.status_code == 404:
            last = {"hits": {"total": {"value": 0}, "hits": []}}
        else:
            resp.raise_for_status()
            last = resp.json()
        total = last.get("hits", {}).get("total", {}).get("value", 0)
        log(f"findings poll (scoped to case_id={case_id}): total={total}")
        if total > 0:
            return last
        time.sleep(15)
    return last


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


async def main() -> None:
    print("=== Step 1: real login (case-lead, kronos-dev) ===")
    client, claims = real_login()
    org_id = uuid.UUID(claims["org_id"])
    org_alias = next(iter(claims["organization"].keys()))
    user_id = uuid.UUID(claims["sub"])
    check("real JWT carries org_id/organization claims", bool(org_id) and bool(org_alias), f"org_id={org_id} org_alias={org_alias}")

    print("\n=== Step 2: real, fresh case creation ===")
    case_id = create_fresh_case(client)

    print("\n=== Step 3: real, fresh evidence upload+finalize (autonomous pipeline) ===")
    evidence_ids = {log_type: upload_and_finalize(client, case_id, log_type) for log_type in SAMPLES}

    print("\n=== Step 4: poll for real Celery-driven parse -> OpenSearch indexing ===")
    final_states = poll_until_complete(client, case_id, evidence_ids)
    for log_type, state in final_states.items():
        check(f"[{log_type}] real evidence reached COMPLETE via the autonomous pipeline (no manual parse/start call)", state == "COMPLETE", f"state={state}")

    print("\n=== Step 5: confirm real fresh documents actually landed in OpenSearch ===")
    sa_client = httpx.Client(base_url=OS_URL, auth=OS_ADMIN, verify=False, timeout=30)
    doc_counts = {}
    for log_type in SAMPLES:
        resp = sa_client.post(
            f"/kronos-{org_alias}-case-{case_id}-*/_count",
            json={"query": {"term": {"kronos.parser": "evtx-rs" if log_type == "windows" else "suricata-eve"}}},
        )
        count = resp.json().get("count", 0) if resp.status_code == 200 else 0
        doc_counts[log_type] = count
        check(f"[{log_type}] real fresh documents indexed in this case's OpenSearch index", count > 0, f"count={count}")

    print("\n=== Step 6: real case-scoped detectors, admin creds (A3), matching C1/C4 workaround for kronos-dev's known legacy-index gap ===")
    detector_ids = {}
    detector_names = []
    for log_type in SAMPLES:
        did = create_case_scoped_detector(sa_client, org_alias, log_type, case_id)
        detector_ids[log_type] = did
        detector_names.append(f"kronos-{org_alias}-{log_type}-detector")

    print("\n=== Step 7: wait for the real detector's scheduled monitor run to actually fire ===")
    findings_result = poll_for_findings(sa_client, detector_names, case_id)
    total_findings = findings_result.get("hits", {}).get("total", {}).get("value", 0)
    check("at least one real SA finding produced against the freshly-ingested evidence", total_findings > 0, f"total={total_findings}")
    real_findings = findings_result.get("hits", {}).get("hits", [])
    for f in real_findings[:5]:
        src = f["_source"]
        log(f"  real finding {f['_id']}: monitor={src.get('monitor_name')} queries={[q.get('tags') for q in src.get('queries', [])]}")

    print("\n=== Step 8: real DetectionSyncService.sync_org_findings() -- unmodified src/ code ===")
    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    await PostgresDetectionRepository.create_tables(engine)
    await PostgresAuditLogRepository.create_tables(engine)
    detection_repo = PostgresDetectionRepository(engine)
    audit_log = AuditLogService(PostgresAuditLogRepository(engine))
    findings_client = SecurityAnalyticsFindingsClient(OS_URL, "admin", "admin")
    sync_service = DetectionSyncService(findings_client, detection_repo, audit_log)

    tenant = TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=user_id,
        username="case-lead",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )
    created = await sync_service.sync_org_findings(tenant)
    check("real sync created at least one new Detection row", created > 0, f"created={created}")

    all_org_detections = [d async for d in detection_repo.stream_by_org(org_id)]
    this_case_detections = [d for d in all_org_detections if d.case_id == uuid.UUID(case_id)]
    check(
        "at least one real Detection row exists for THIS run's fresh case_id",
        len(this_case_detections) > 0,
        f"count={len(this_case_detections)} (org total={len(all_org_detections)})",
    )
    check(
        "every real Detection row's org_id == the syncing tenant's real org_id (invariant #3 -- computed, never read from the finding)",
        all(d.org_id == org_id for d in this_case_detections),
        str({str(d.org_id) for d in this_case_detections}),
    )
    check(
        "every real Detection row's case_id correctly parsed from the finding's own source index name",
        all(d.case_id == uuid.UUID(case_id) for d in this_case_detections),
        str({str(d.case_id) for d in this_case_detections}),
    )
    all_tags = sorted({tag for d in this_case_detections for tag in d.attack_tags})
    check(
        "at least one real ATT&CK tag present on this run's Detection rows (Detection.attack_tags)",
        len(all_tags) > 0,
        str(all_tags),
    )

    print("\n=== Step 9: real measured ATT&CK coverage for this run's fresh Detection rows ===")
    technique_counts: dict[str, int] = {}
    for d in this_case_detections:
        for tag in d.attack_tags:
            technique_counts[tag] = technique_counts.get(tag, 0) + 1
    print(json.dumps({"detections": len(this_case_detections), "technique_counts": technique_counts}, indent=2))

    # Idempotent re-run check, same as C4's own precedent.
    created_again = await sync_service.sync_org_findings(tenant)
    check("re-running sync creates zero new rows for the same real findings (idempotency)", created_again == 0, f"created={created_again}")

    await engine.dispose()

    print("\n=== Cleanup: remove the throwaway case-scoped detectors (not part of any committed src/ path) ===")
    for log_type, did in detector_ids.items():
        delete_detector(sa_client, did)
        log(f"deleted detector {did} ({log_type})")
    print(
        "NOTE: real findings + real Detection/audit_log rows this run created are "
        "deliberately left in place as inspectable proof, matching C4's own precedent."
    )

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)

    summary = {
        "case_id": case_id,
        "evidence_ids": evidence_ids,
        "final_states": final_states,
        "doc_counts": doc_counts,
        "detector_ids": detector_ids,
        "total_findings": total_findings,
        "detections_this_case": len(this_case_detections),
        "technique_counts": technique_counts,
    }
    (Path(__file__).parent / "run_summary.json").write_text(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
