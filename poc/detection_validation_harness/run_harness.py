"""I1 - Detection validation harness (docs/NEXTGEN_SOC_ROADMAP.md, Milestone M8).

Roadmap objective (verbatim): "Atomic Red Team / Caldera-driven continuous
validation that rules still fire; regression-tested in CI."

WHAT THIS PROVES: for N real ATT&CK techniques, each shaped like the real log
output a specific technique is documented to produce, does KronOS's real
ingestion pipeline (upload -> Celery parse -> OpenSearch index) plus a real
OpenSearch Security Analytics detector plus C4's real DetectionSyncService
still produce a real, audited `Detection` row carrying the expected ATT&CK
tag? This is a REGRESSION CHECK for the mechanism C1/C4/C5 already proved
real -- it does not re-litigate whether the mechanism is real (already
proven), it re-runs it against pinned technique-shaped samples so that a
future index-template edit / SA upgrade / mapping change that silently
breaks detection has something to fail against.

ATOMIC RED TEAM vs CALDERA DECISION (see README.md "Decision" section for
full reasoning): Atomic Red Team chosen. Real, current repo pinned at commit
1ba1dd8d9ce6f74700f7aec2e60de5632f667f03 (2026-07-20, HEAD of `master` at
research time -- ART ships no version tags/releases, confirmed via
`curl https://api.github.com/repos/redcanaryco/atomic-red-team/releases` ->
empty array; pinning a commit SHA is the only real option). Individual
technique files referenced below were fetched at that exact commit.

SAFETY BOUNDARY: no atomic is executed against any host, container, or
network. ART does not ship captured telemetry/output for its atomics (it
ships only the attack commands themselves) -- confirmed by inspecting the
repo structure. Per CLAUDE.md's brief, this harness therefore either (a)
reuses a REAL, already-captured, technique-tagged sample already used by
C1/C4/C5 (the Windows/EVTX technique -- hand-authoring a valid binary EVTX
file with arbitrary EventData is not feasible without a Windows host or an
EVTX-writing library, neither of which exists in this environment; reusing
real captured telemetry that C1 already measured firing this exact
technique's rule is a stronger, more honest proof than a fabricated binary
would be), or (b) hand-constructs a JSON-based record matching the REAL,
documented event shape (Suricata EVE JSON per suricata-8.0.6 userguide;
AWS CloudTrail record contents per AWS's own CloudTrail documentation) for
a log source KronOS already parses natively. Three techniques, three
different KronOS-ingested log sources, as scoped:

  1. windows / T1110.003 (Brute Force: Password Spraying) -- REUSED real
     tests/fixtures/samples/real/system.evtx (the same real sample C1
     measured firing this exact rule/tag; ART's own T1110.003 atomic
     exists at atomics/T1110.003/T1110.003.yaml, confirmed at the pinned
     commit, but produces no shippable telemetry of its own).
  2. network / T1021.001 (Remote Services: RDP) -- HAND-CONSTRUCTED
     Suricata EVE "flow" record: a real, publicly-routable (RFC 5737
     TEST-NET-3, 203.0.113.0/24) source IP connecting to a private
     destination on tcp/3389. Matches the real prepackaged rule
     1fc0809e-06bf-4de3-ad52-25e5263b7623 ("Publicly Accessible RDP
     Service") verbatim condition (fires whenever source IP does NOT
     start with an RFC1918/ULA prefix) -- this is the exact real Sigma
     condition read from the live cluster's own
     `_plugins/_security_analytics/rules/_search`, not guessed. ART's own
     T1021.001 atomic exists at atomics/T1021.001/T1021.001.yaml (RDP to
     DomainController via mstsc), confirmed at the pinned commit.
  3. cloudtrail / T1562.001 (Impair Defenses) -- HAND-CONSTRUCTED AWS
     CloudTrail record: eventSource=cloudtrail.amazonaws.com,
     eventName=StopLogging (disabling a CloudTrail trail is a real,
     extremely common "impair defenses" / anti-forensics action).
     Matches the real prepackaged rule 4db60cc0-36fb-42b7-9b58-a5b53019fb74
     ("AWS CloudTrail Important Change") verbatim condition, again read
     directly from the live cluster. HONESTY NOTE: ART does not ship a
     dedicated atomic for this exact action -- the more precise ATT&CK
     subtechnique for disabling cloud audit logs is T1562.008 ("Disable
     Cloud Logs"), which ART's repo does not have an atomics/T1562.008/
     directory for at all (confirmed 404 at the pinned commit) -- the rule
     itself is tagged attack.t1562.001 by its own author, not by this
     harness. `aws cloudtrail stop-logging --name <trail>` is nonetheless
     a real, standard AWS CLI action documented in AWS's own CloudTrail
     best-practices guide (the same reference this Sigma rule itself
     cites), not fabricated.

TIMESTAMP GOTCHA (C5's finding, inherited unmodified): OpenSearch Security
Analytics monitors only evaluate documents whose @timestamp falls within a
recent execution window since the monitor's own last run -- NOT by
write/arrival order. The network/cloudtrail samples are generated with
@timestamp/eventTime set to "now" at generation time (seconds before
upload), which is sufficient given the run completes within a few minutes
and detectors are scheduled at 1-minute intervals. The windows sample is
REAL historical evidence (genuine 2015-era EVTX timestamps) and cannot be
generated with a fresh timestamp -- it is re-indexed with @timestamp set to
"now" via a real `_update_by_query` immediately after indexing, mirroring
the exact, documented workaround C4/C5's own PoCs already used and
generalized as a known, inherited limitation, not invented here.

Run: source ~/venv/bin/activate && python poc/detection_validation_harness/run_harness.py
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
from datetime import UTC, datetime
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.opensearch.findings_client import SecurityAnalyticsFindingsClient  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.detection_sync import DetectionSyncService  # noqa: E402
from src.application.risk_scoring import DetectionRiskScorer  # noqa: E402
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

RUN_ID = uuid.uuid4().hex[:8]
NOW = datetime.now(UTC)
NOW_ISO_Z = NOW.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
NOW_ISO_SURICATA = NOW.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def _suricata_eve_content() -> bytes:
    """Real Suricata EVE 'flow' event shape (suricata-8.0.6 userguide,
    doc/userguide/output/eve/eve-json-format.rst -- same reference
    SuricataEveParser's own docstring cites). Public source IP
    203.0.113.77 is RFC 5737 TEST-NET-3 (reserved for documentation,
    never routable) -- deterministic, safe, and NOT one of the private
    prefixes rule 1fc0809e checks for, so its own real condition
    (`NOT (id.orig_h startswith <private prefixes>)`) evaluates true."""
    record = {
        "timestamp": NOW_ISO_SURICATA,
        "flow_id": 900000000000001,
        "event_type": "flow",
        "src_ip": "203.0.113.77",
        "src_port": 51000,
        "dest_ip": "10.0.2.15",
        "dest_port": 3389,
        "proto": "TCP",
        "app_proto": "rdp",
        "flow": {
            "pkts_toserver": 12,
            "pkts_toclient": 10,
            "bytes_toserver": 1800,
            "bytes_toclient": 1500,
            "start": NOW_ISO_SURICATA,
            "src_ip": "203.0.113.77",
            "dest_ip": "10.0.2.15",
            "src_port": 51000,
            "dest_port": 3389,
            "state": "established",
        },
    }
    return (json.dumps(record) + "\n").encode("utf-8")


def _cloudtrail_content() -> bytes:
    """Real AWS CloudTrail record shape per AWS's own "CloudTrail record
    contents" documentation (docs.aws.amazon.com/awscloudtrail/latest/
    userguide/cloudtrail-event-reference-record-contents.html).
    Account/ARN/IP values are AWS's own documented EXAMPLE placeholders
    (123456789012 / AIDACKCEVSQ6C2EXAMPLE), not fabricated. eventName
    StopLogging + eventSource cloudtrail.amazonaws.com matches real rule
    4db60cc0-36fb-42b7-9b58-a5b53019fb74's verbatim condition."""
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/Alice",
            "accountId": "123456789012",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "userName": "Alice",
        },
        "eventTime": NOW_ISO_Z,
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.23",
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": {
            "name": f"arn:aws:cloudtrail:us-east-1:123456789012:trail/kronos-i1-{RUN_ID}"
        },
        "responseElements": None,
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": False,
        "eventType": "AwsApiCall",
        "recipientAccountId": "123456789012",
        "eventCategory": "Management",
    }
    return json.dumps({"Records": [event]}).encode("utf-8")


TECHNIQUES: dict[str, dict] = {
    "windows": {
        "log_type": "windows",
        "attack_technique": "T1110.003",
        "attack_tag": "attack.t1110.003",
        "art_atomic": "atomics/T1110.003/T1110.003.yaml @ 1ba1dd8d",
        "source": "REUSED real captured telemetry (tests/fixtures/samples/real/system.evtx)",
        "content_fn": None,  # real file, read directly
        "path": REPO_ROOT / "tests" / "fixtures" / "samples" / "real" / "system.evtx",
        "upload_name": f"i1-windows-{RUN_ID}.evtx",
        "content_type": "application/octet-stream",
        "kronos_parser": "evtx-rs",
        # NOTE: all 3 techniques now get the SAME @timestamp=now fixup, run
        # AFTER detector creation (Step 8) -- see
        # fixup_timestamps_after_detector_creation()'s docstring for why a
        # per-technique flag here was the wrong granularity (real problem A).
    },
    "network": {
        "log_type": "network",
        "attack_technique": "T1021.001",
        "attack_tag": "attack.t1021.001",
        "art_atomic": "atomics/T1021.001/T1021.001.yaml @ 1ba1dd8d",
        "source": "HAND-CONSTRUCTED, real Suricata EVE 'flow' shape (suricata-8.0.6 userguide)",
        "content_fn": _suricata_eve_content,
        "upload_name": f"i1-network-{RUN_ID}-eve.json",
        "content_type": "application/json",
        "kronos_parser": "suricata-eve",
    },
    "cloudtrail": {
        "log_type": "cloudtrail",
        "attack_technique": "T1562.001 (rule's own tag; more precise ATT&CK subtechnique is T1562.008, no ART atomic exists for it)",
        "attack_tag": "attack.t1562.001",
        "art_atomic": "NONE -- confirmed absent from ART at pinned commit; see module docstring",
        "source": "HAND-CONSTRUCTED, real AWS CloudTrail record shape (AWS CloudTrail record-contents docs)",
        "content_fn": _cloudtrail_content,
        "upload_name": f"i1-cloudtrail-{RUN_ID}.json",
        "content_type": "application/json",
        "kronos_parser": "cloudtrail",
    },
}

# Alias mappings needed for SA to interpret KronOS's real ECS-shaped fields
# as the Sigma rule's own raw field names -- reused VERBATIM from
# poc/security_analytics_field_mappings/build_alias_mappings.py (C1), not
# reinvented.
ALIAS_TABLES: dict[str, dict[str, str]] = {
    "cloudtrail": {
        "aws.cloudtrail.event_name": "event.action",
        "aws.cloudtrail.event_source": "cloud.service.name",
        "aws.cloudtrail.source_ip_address": "source.ip",
        "aws.cloudtrail.error_code": "error.code",
        "aws.cloudtrail.user_identity.userName": "user.name",
        "aws.cloudtrail.user_identity.accountId": "user.id",
        "timestamp": "@timestamp",
    },
    "network": {
        "id.orig_h": "source.ip",
        "id.resp_h": "destination.ip",
        "id.resp_p": "destination.port",
        "timestamp": "@timestamp",
    },
}


def build_windows_alias_table(sa_client: httpx.Client, org_alias: str, case_id: str) -> dict[str, str]:
    """Real problem A's SECOND, deeper root cause (found while re-verifying
    the reordering fix, not guessed): this harness never applied ANY alias
    mapping for the "windows" rule_topic, unlike
    poc/security_analytics_field_mappings/build_alias_mappings.py (C1),
    which explicitly maps Sigma's raw "EventID" field (SA's default
    resolves it to "winlog.event_id") onto KronOS's real
    `event.code` field. Confirmed directly against the live cluster's own
    `_plugins/_security_analytics/mappings/view` for this run's real
    windows index: `winlog.event_id` was present in `unmapped_field_aliases`
    (168 total unmapped). Without this alias, EVERY windows Sigma rule that
    conditions on `EventID` (i.e. all 3 real T1110.003 rules C1 previously
    measured firing, `196a29c2-...` among them) cannot evaluate -- the one
    windows finding that DID fire in this harness's runs (tag `attack.t1006`)
    is a vacuous NOT-condition match on an absent field (an allowlist rule
    matching because the excluded field doesn't exist at all -- see C1's own
    README), not real rule coverage. Reused VERBATIM from C1's
    `_windows_table()` (poc/security_analytics_field_mappings/
    build_alias_mappings.py), only the discovery of a representative
    concrete index is inlined here instead of precomputed, since this
    harness's case_id is fresh each run.
    """
    resp = sa_client.post(
        f"/kronos-{org_alias}-case-{case_id}-*/_search",
        json={"size": 1, "query": {"term": {"kronos.parser": "evtx-rs"}}},
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    check("[windows] discovered a real concrete index to inspect for alias mappings", len(hits) > 0, f"hits={len(hits)}")
    concrete_index = hits[0]["_index"]

    view = sa_client.get(
        "/_plugins/_security_analytics/mappings/view",
        params={"index_name": concrete_index, "rule_topic": "windows"},
    )
    check("[windows] real GET mappings/view succeeds", view.status_code == 200, f"status={view.status_code} body={view.text[:300]}")
    view.raise_for_status()
    unmapped = view.json().get("unmapped_field_aliases", [])
    log(f"[windows] concrete_index={concrete_index} unmapped_field_aliases count={len(unmapped)} (winlog.event_id present={'winlog.event_id' in unmapped})")

    table: dict[str, str] = {
        alias: alias for alias in unmapped if alias.startswith("winlog.event_data.")
    }
    # Explicit semantic equivalents verified against evtx.py's own extra{}
    # writes (identical to C1's own verified table, not guessed here).
    table["winlog.event_id"] = "event.code"
    table["winlog.channel"] = "log.file.path"
    table["winlog.computer_name"] = "host.name"
    table["host.hostname"] = "host.name"
    table["timestamp"] = "@timestamp"
    return table


PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def log(*a: object) -> None:
    print(*a, file=sys.stderr)


def real_login() -> tuple[httpx.Client, dict]:
    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state=f"i1-harness-{RUN_ID}"
    )
    claims = auth_helpers.decode_jwt_payload(tokens["access_token"])
    log(f"login OK (mfa_path={mfa_path})")
    client = httpx.Client(
        base_url=BACKEND,
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        verify=auth_helpers.CA_BUNDLE,
        timeout=60,
    )
    return client, claims


def create_fresh_case(client: httpx.Client) -> str:
    resp = client.post(
        "/api/cases",
        json={
            "title": f"I1 detection-validation-harness {RUN_ID}",
            "description": "Regression harness: ATT&CK-technique-shaped samples -> real Detection rows",
        },
    )
    check("real POST /api/cases succeeds (201)", resp.status_code == 201, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    case_id = resp.json()["id"]
    log(f"created fresh case {case_id}")
    return case_id


def upload_and_finalize(client: httpx.Client, case_id: str, technique: str, spec: dict) -> str:
    data = spec["path"].read_bytes() if spec.get("path") else spec["content_fn"]()
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
    check(f"[{technique}] upload/request -> 201", resp.status_code == 201, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    upload = resp.json()
    evidence_id = upload["evidenceId"]

    put_resp = httpx.put(upload["presignedUrl"], content=data, timeout=60, verify=auth_helpers.CA_BUNDLE)
    check(f"[{technique}] real presigned PUT to MinIO succeeds", put_resp.status_code in (200, 204), f"status={put_resp.status_code}")

    resp = client.post(f"/api/evidence/upload/finalize/{evidence_id}", json={"client_sha256": sha256})
    check(f"[{technique}] finalize_upload -> 202 (autonomous pipeline, CLAUDE.md E.1)", resp.status_code == 202, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    log(f"[{technique}] evidence_id={evidence_id} sha256={sha256}")
    return evidence_id


def poll_until_complete(client: httpx.Client, case_id: str, evidence_ids: dict[str, str], timeout_s: int = 300) -> dict[str, str]:
    deadline = time.time() + timeout_s
    states: dict[str, str] = {}
    while time.time() < deadline:
        resp = client.get(f"/api/cases/{case_id}/evidence")
        resp.raise_for_status()
        items = resp.json()["items"]
        by_id = {i["id"]: i["state"] for i in items}
        states = {t: by_id.get(eid, "?") for t, eid in evidence_ids.items()}
        log(f"poll: {states}")
        if all(s in ("COMPLETE", "ERROR") for s in states.values()):
            break
        time.sleep(5)
    return states


def fixup_timestamps_after_detector_creation(
    sa_client: httpx.Client, org_alias: str, case_id: str, evidence_ids: dict[str, str]
) -> dict[str, int]:
    """Real _update_by_query setting @timestamp to a FRESH wall-clock value
    for ALL THREE techniques' documents, run for real AFTER the case-scoped
    detectors already exist (see README's "root cause, confirmed" section).

    This is the fix for I1's real problem A (0/3 findings fired in the
    prior captured run). Root cause, confirmed by reproducing the ordering
    bug and then fixing it (not guessed): OpenSearch Security Analytics
    monitors query candidate documents by whether their own @timestamp
    falls inside a window anchored at the monitor's *own* last-execution
    cursor (initially close to the detector's creation/enable time),
    exactly as C5 (poc/chain_detect_from_evidence/README.md, Finding #1)
    already proved. C5's own ad-hoc confirmation test re-indexed a
    document's @timestamp to "now" only AFTER its throwaway detector had
    already been running for several cycles -- so the fresh timestamp
    landed inside a window the monitor was already actively evaluating.
    The prior run of this harness did the opposite: it set @timestamp to
    "now" (Step 6, old order) BEFORE detector creation (Step 8, old
    order), and the network/cloudtrail samples were built with an even
    earlier "now" (at sample-*build* time, before upload). By the time any
    detector's monitor executed its first scheduled window, all three
    "fresh" timestamps were already older than that window's start --
    structurally invisible to it, not a data problem. Moving this step to
    run immediately AFTER detector creation and IMMEDIATELY before the
    findings poll (this function) keeps the timestamp inside the window
    the soon-to-execute monitor will actually evaluate.
    """
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    index_pattern = f"kronos-{org_alias}-case-{case_id}-*"
    updated: dict[str, int] = {}
    for t, evidence_id in evidence_ids.items():
        body = {
            "query": {"term": {"kronos.evidence_id": evidence_id}},
            "script": {"source": "ctx._source['@timestamp'] = params.now", "params": {"now": now_iso}},
        }
        resp = sa_client.post(f"/{index_pattern}/_update_by_query", json=body, params={"refresh": "true", "conflicts": "proceed"})
        check(
            f"[{t}] real _update_by_query sets @timestamp=now AFTER detector creation (fix for real problem A)",
            resp.status_code == 200,
            f"status={resp.status_code} body={resp.text[:300]}",
        )
        resp.raise_for_status()
        n = resp.json().get("updated", 0)
        updated[t] = n
        log(f"[{t}] post-detector timestamp fixup updated {n} docs (now={now_iso})")
    return updated


def apply_alias_mappings(sa_client: httpx.Client, index_pattern: str, org_alias: str, case_id: str) -> None:
    # windows added here -- real problem A's second root cause (see
    # build_windows_alias_table()'s docstring): this harness previously
    # applied NO alias mapping at all for the windows rule_topic.
    tables = dict(ALIAS_TABLES)
    tables["windows"] = build_windows_alias_table(sa_client, org_alias, case_id)
    for log_type, table in tables.items():
        alias_mappings = {"properties": {alias: {"type": "alias", "path": path} for alias, path in table.items()}}
        resp = sa_client.post(
            "/_plugins/_security_analytics/mappings",
            json={"index_name": index_pattern, "rule_topic": log_type, "partial": True, "alias_mappings": alias_mappings},
        )
        check(f"[{log_type}] real alias mapping POST accepted (reused verbatim from C1)", resp.status_code == 200, f"status={resp.status_code} body={resp.text[:300]}")


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
                    "description": f"I1 detection-validation-harness detector ({log_type})",
                    "indices": [f"kronos-kronos-dev-case-{case_id}-*"],
                    "pre_packaged_rules": [{"id": rid} for rid in rule_ids],
                    "custom_rules": [],
                }
            }
        ],
        "triggers": [],
    }
    resp = sa_client.post("/_plugins/_security_analytics/detectors", json=body)
    check(f"[{log_type}] real case-scoped detector created (201)", resp.status_code == 201, f"status={resp.status_code} body={resp.text[:300]}")
    resp.raise_for_status()
    detector_id = resp.json()["_id"]
    log(f"[{log_type}] detector {name} id={detector_id}")
    return detector_id


def delete_detector(sa_client: httpx.Client, detector_id: str) -> None:
    sa_client.delete(f"/_plugins/_security_analytics/detectors/{detector_id}")


def poll_for_findings(sa_client: httpx.Client, detector_names: list[str], case_id: str, timeout_s: int = 300) -> dict:
    deadline = time.time() + timeout_s
    last: dict = {}
    while time.time() < deadline:
        resp = sa_client.post(
            "/.opensearch-sap-*-findings-*/_search",
            json={
                "size": 100,
                "query": {"bool": {"must": [{"terms": {"monitor_name": detector_names}}, {"wildcard": {"index": f"*case-{case_id}-*"}}]}},
            },
        )
        if resp.status_code == 404:
            last = {"hits": {"total": {"value": 0}, "hits": []}}
        else:
            resp.raise_for_status()
            last = resp.json()
        total = last.get("hits", {}).get("total", {}).get("value", 0)
        log(f"findings poll (case_id={case_id}): total={total}")
        if total > 0:
            time.sleep(20)  # let a second cycle run in case other detectors haven't fired yet
            resp2 = sa_client.post(
                "/.opensearch-sap-*-findings-*/_search",
                json={
                    "size": 100,
                    "query": {"bool": {"must": [{"terms": {"monitor_name": detector_names}}, {"wildcard": {"index": f"*case-{case_id}-*"}}]}},
                },
            )
            if resp2.status_code == 200:
                return resp2.json()
            return last
        time.sleep(15)
    return last


async def main() -> None:
    print("=== Step 1: real login (case-lead, kronos-dev) ===")
    client, claims = real_login()
    org_id = uuid.UUID(claims["org_id"])
    org_alias = next(iter(claims["organization"].keys()))
    user_id = uuid.UUID(claims["sub"])
    check("real JWT carries org_id/organization claims", bool(org_id) and bool(org_alias), f"org_id={org_id} org_alias={org_alias}")

    print("\n=== Step 2: real, fresh case creation (tenant-isolated per invariant #3) ===")
    case_id = create_fresh_case(client)

    print("\n=== Step 3: real upload+finalize for each ATT&CK-technique-shaped sample ===")
    evidence_ids = {t: upload_and_finalize(client, case_id, t, spec) for t, spec in TECHNIQUES.items()}

    print("\n=== Step 4: poll for real Celery-driven parse -> OpenSearch indexing ===")
    final_states = poll_until_complete(client, case_id, evidence_ids)
    for t, state in final_states.items():
        check(f"[{t}] real evidence reached COMPLETE via the autonomous pipeline", state == "COMPLETE", f"state={state}")

    sa_client = httpx.Client(base_url=OS_URL, auth=OS_ADMIN, verify=False, timeout=30)

    print("\n=== Step 5: confirm real fresh documents indexed ===")
    doc_counts = {}
    for t, spec in TECHNIQUES.items():
        resp = sa_client.post(
            f"/kronos-{org_alias}-case-{case_id}-*/_count",
            json={"query": {"term": {"kronos.parser": spec["kronos_parser"]}}},
        )
        count = resp.json().get("count", 0) if resp.status_code == 200 else 0
        doc_counts[t] = count
        check(f"[{t}] real fresh documents indexed", count > 0, f"count={count}")

    print("\n=== Step 6: real alias mappings for cloudtrail/network (reused verbatim from C1) ===")
    apply_alias_mappings(sa_client, f"kronos-{org_alias}-case-{case_id}-*", org_alias, case_id)

    print("\n=== Step 7: real case-scoped detectors, admin creds (A3) ===")
    detector_ids: dict[str, str] = {}
    detector_names = []
    for t, spec in TECHNIQUES.items():
        did = create_case_scoped_detector(sa_client, org_alias, spec["log_type"], case_id)
        detector_ids[t] = did
        detector_names.append(f"kronos-{org_alias}-{spec['log_type']}-detector")

    print("\n=== Step 8: timestamp fixup for ALL 3 techniques, run AFTER detector creation (fix for real problem A -- see README) ===")
    fixup_timestamps_after_detector_creation(sa_client, org_alias, case_id, evidence_ids)

    print("\n=== Step 9: wait for real detector schedule cycles to fire ===")
    findings_result = poll_for_findings(sa_client, detector_names, case_id)
    real_findings = findings_result.get("hits", {}).get("hits", [])
    total_findings = findings_result.get("hits", {}).get("total", {}).get("value", 0)
    log(f"total real findings for this case: {total_findings}")

    # Per-technique: did the finding set for that technique's index contain a
    # finding whose queries[].tags include the expected real ATT&CK tag?
    per_technique_fired: dict[str, bool] = {}
    for t, spec in TECHNIQUES.items():
        expected_tag = spec["attack_tag"]
        fired = False
        for f in real_findings:
            src = f["_source"]
            if src.get("monitor_name") != f"kronos-{org_alias}-{spec['log_type']}-detector":
                continue
            for q in src.get("queries", []):
                if expected_tag in (q.get("tags") or []):
                    fired = True
        per_technique_fired[t] = fired
        check(f"[{t}] real SA finding fired with expected ATT&CK tag {expected_tag}", fired)

    for f in real_findings[:10]:
        src = f["_source"]
        log(f"  real finding {f['_id']}: monitor={src.get('monitor_name')} tags={[q.get('tags') for q in src.get('queries', [])]}")

    print("\n=== Step 10: real DetectionSyncService.sync_org_findings() -- unmodified src/ code ===")
    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    await PostgresDetectionRepository.create_tables(engine)
    await PostgresAuditLogRepository.create_tables(engine)
    detection_repo = PostgresDetectionRepository(engine)
    audit_log = AuditLogService(PostgresAuditLogRepository(engine))
    findings_client = SecurityAnalyticsFindingsClient(OS_URL, "admin", "admin")
    # Real problem B fix: DetectionSyncService requires a 4th positional
    # (timeline_index: AbstractTimelineIndex) -- confirmed via
    # src/external/dependencies.py's own get_detection_sync_service() (used
    # to resolve a finding's matched documents' enrichment fields for risk
    # scoring at sync time). Real OpenSearchClient pointed at the same
    # dev-stack OpenSearch this harness already uses elsewhere (OS_URL,
    # admin creds), mirroring the exact construction pattern
    # src/external/celery_runtime.py's own _build_task_resources() uses.
    timeline_index = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=OS_ADMIN,
        use_ssl=True,
        verify_certs=False,
    )
    sync_service = DetectionSyncService(
        findings_client=findings_client,
        detection_repository=detection_repo,
        audit_log=audit_log,
        timeline_index=timeline_index,
        risk_scorer=DetectionRiskScorer(),
    )

    tenant = TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=user_id,
        username="case-lead",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )
    created = await sync_service.sync_org_findings(tenant)
    log(f"sync created {created} new Detection rows")

    all_org_detections = [d async for d in detection_repo.stream_by_org(org_id)]
    this_case_detections = [d for d in all_org_detections if d.case_id == uuid.UUID(case_id)]
    check("real Detection rows exist for THIS run's fresh case_id", len(this_case_detections) > 0, f"count={len(this_case_detections)}")
    check(
        "every real Detection row's org_id == the syncing tenant's real org_id (invariant #3)",
        all(d.org_id == org_id for d in this_case_detections),
        str({str(d.org_id) for d in this_case_detections}),
    )

    all_tags = {tag for d in this_case_detections for tag in d.attack_tags}
    per_technique_detection_row: dict[str, bool] = {}
    for t, spec in TECHNIQUES.items():
        matched = spec["attack_tag"] in all_tags
        per_technique_detection_row[t] = matched
        check(f"[{t}] real audited Detection row carries expected ATT&CK tag {spec['attack_tag']}", matched, f"all_tags_this_case={sorted(all_tags)}")

    print("\n=== Step 11: real coverage number ===")
    n = len(TECHNIQUES)
    m = sum(1 for v in per_technique_detection_row.values() if v)
    coverage = {
        "techniques_attempted": n,
        "techniques_with_real_detection_row": m,
        "per_technique": {
            t: {
                "attack_technique": spec["attack_technique"],
                "attack_tag": spec["attack_tag"],
                "source": spec["source"],
                "sa_finding_fired": per_technique_fired[t],
                "detection_row_created": per_technique_detection_row[t],
            }
            for t, spec in TECHNIQUES.items()
        },
    }
    print(json.dumps(coverage, indent=2))

    await engine.dispose()
    await timeline_index.close()

    print("\n=== Cleanup: remove throwaway case-scoped detectors ===")
    for t, did in detector_ids.items():
        delete_detector(sa_client, did)
        log(f"deleted detector {did} ({t})")
    print("NOTE: real findings + real Detection/audit_log rows this run created are left in place as inspectable proof (matches C4/C5 precedent).")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)

    summary = {
        "run_id": RUN_ID,
        "case_id": case_id,
        "evidence_ids": evidence_ids,
        "final_states": final_states,
        "doc_counts": doc_counts,
        "detector_ids": detector_ids,
        "total_findings": total_findings,
        "coverage": coverage,
        "checks_passed": len(PASS),
        "checks_failed": len(FAIL),
        "failures": FAIL,
    }
    (Path(__file__).parent / "run_summary.json").write_text(json.dumps(summary, indent=2, default=str))

    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
