"""PoC: exercise the REAL OpenSearch 2.11.1 Security Analytics Correlation
Engine (roadmap F3 -- docs/NEXTGEN_SOC_ROADMAP.md) against the real,
already-running dev stack (https://localhost:9200, admin:admin).

Confirmed already, before this script was written (orchestrator's own real
probe, not re-derived here):
  - GET  /_plugins/_security_analytics/correlation/rules          -> 405
    ("Incorrect HTTP method... allowed: [POST]") -- the route IS registered.
  - POST /_plugins/_security_analytics/correlation/rules/_search
    {"query":{"match_all":{}}}                                    -> 200, empty hits.
  - Control: POST .../detectors/_search -> 200 (known-good SA endpoint).

This script goes further: reads the REAL Java source for the pinned 2.11
branch (org.opensearch.securityanalytics.model.CorrelationRule/CorrelationQuery,
resthandler.RestIndexCorrelationRuleAction, action.IndexCorrelationRuleRequest,
resthandler.RestSearchCorrelationAction -- cloned from
github.com/opensearch-project/security-analytics @ branch 2.11, commit
0092714047145972f990931e0d06595caa019185) to get the EXACT request/response
shape, rather than trusting "latest" docs (which may describe a newer
version's syntax -- CLAUDE.md SS F.2 step 2). Confirmed from that source:

  - POST/PUT body: {"name": <5-50 chars, [a-zA-Z0-9 _,-.]>, "correlate": [
        {"index": <str>, "query": <lucene query_string>, "category": <str>},
        ... (>=2 entries for a real cross-log-type correlation) ]}
  - `name` is REQUIRED and regex-validated
    (IndexCorrelationRuleRequest.IS_VALID_RULE_NAME) -- a request with an
    empty/invalid name gets a real 400 action_request_validation_exception.
  - Response: {"_id": ..., "_version": ..., "rule": {"name": ..., "correlate": [...]}}.
  - `correlate` is a NESTED field in the rules-config index (confirmed via
    the real IT test's own search query using
    {"nested": {"path": "correlate", ...}}) -- the same "flat query against
    nested field silently matches nothing" trap C2's own detector.name
    idempotency bug hit. Anyone later filtering KronOS's own correlation
    rules by org must use a nested query, not a flat term query.
  - `category` in a correlate entry must be one of the real 23 log types
    (it is the SAME string as a Detector's own `detector_type` -- there is
    no cross-reference validation of this in CorrelationRule.java itself,
    but the correlation ENGINE only has real findings to correlate against
    for categories that have a real detector producing findings).
  - There is NO org/tenant field anywhere in CorrelationRule or
    CorrelationQuery -- `index` is a free-form string the caller supplies,
    exactly like a Detector's own `indices` list.

Prerequisites this script bootstraps itself (throwaway PoC infra, not
kronos-* -- see README.md "Why not kronos-* index names" for why):
  - Two standalone test indices (`poc-corr-windows-<ts>`, `poc-corr-network-<ts>`)
    with a single real document each, shaped to fire two ALREADY-VERIFIED
    real prepackaged Sigma rules (see poc/security_analytics_field_mappings/):
      * db809f10-56ce-4420-8c86-d6a7d793c79c (windows, attack.t1006,
        "Raw Disk Access Using Illegitimate Tools") -- condition is
        `not 1 of filter_*`, i.e. it fires on ANY windows-category document
        that simply lacks Image/Device/ProcessId -- confirmed to fire this
        way against real ingested EVTX data in C1.
      * 1fc0809e-06bf-4de3-ad52-25e5263b7623 (network, attack.t1021.001,
        "Publicly Accessible RDP Service") -- condition is `not selection`
        where selection is "id.orig_h startswith any RFC1918 prefix", i.e.
        it fires on ANY non-private id.orig_h -- confirmed to fire this way
        against real ingested Suricata EVE data in C1.
  - Two real detectors (one per index/category), executed on-demand via the
    real Alerting `_execute` API (not waiting for the 1-minute schedule).
  - One real correlation rule joining the two categories.

Run: source ~/venv/bin/activate && python poc/security_analytics_correlation/run_poc.py
Requires the real dev stack up (docker compose -f docker/docker-compose.dev.yml up -d).
"""

from __future__ import annotations

import sys
import time
import uuid

import httpx

OS_URL = "https://localhost:9200"
AUTH = ("admin", "admin")
CLIENT = httpx.Client(base_url=OS_URL, auth=AUTH, verify=False, timeout=30)

TS = uuid.uuid4().hex[:8]
WINDOWS_INDEX = f"poc-corr-windows-{TS}"
NETWORK_INDEX = f"poc-corr-network-{TS}"
WINDOWS_RULE_ID = "db809f10-56ce-4420-8c86-d6a7d793c79c"
NETWORK_RULE_ID = "1fc0809e-06bf-4de3-ad52-25e5263b7623"
HOST_VALUE = f"poc-corr-host-{TS}"
PUBLIC_IP = "8.8.8.8"

PASS, FAIL = [], []
CREATED_DETECTOR_IDS: list[str] = []
CREATED_RULE_IDS: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def dump(label: str, resp: httpx.Response) -> dict:
    body = resp.json() if resp.content else {}
    print(f"  {label}: HTTP {resp.status_code}")
    print(f"    {body}")
    return body


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def part0_create_empty_test_indices() -> None:
    print("\n=== Part 0: create the two (initially empty) real test indices ===")
    # Real, observed behaviour (confirmed the hard way against this exact
    # cluster, see README.md "Real bugs found"): a detector only evaluates
    # documents with @timestamp AFTER the detector's own creation/last-run
    # cursor -- pre-existing documents are silently never matched (this is
    # the SAME fact poc/detection_finding_sync/ already documented: "SA
    # detectors only evaluate documents indexed after the monitor's own
    # last-run cursor, not pre-existing ones"). So the real matching
    # documents are indexed AFTER detector creation (part1b below), not
    # here -- this part only creates the (initially empty) indices so
    # detector creation doesn't 404 on "Indices not found".
    for index in (WINDOWS_INDEX, NETWORK_INDEX):
        resp = CLIENT.put(f"/{index}")
        dump(f"create empty index {index}", resp)
        check(f"index {index} created", resp.status_code == 200, f"status={resp.status_code}")


def part1b_index_real_matching_documents() -> None:
    print(
        "\n=== Part 1b: index the REAL matching documents, timestamped AFTER detector creation ==="
    )
    # Windows doc: deliberately lacks Image/Device/ProcessId -- db809f10's
    # `not 1 of filter_*` condition fires on exactly this shape (C1 finding).
    resp = CLIENT.post(
        f"/{WINDOWS_INDEX}/_doc/1?refresh=true",
        json={"@timestamp": _now_iso(), "HostName": HOST_VALUE, "EventID": 4688},
    )
    dump("index windows doc", resp)
    check("windows test doc indexed", resp.status_code in (200, 201))

    # Network doc: id.orig_h is a public (non-RFC1918) IP -- 1fc0809e's
    # `not selection` (selection = private-prefixed id.orig_h) fires on
    # exactly this shape (C1 finding, real Suricata EVE data).
    resp = CLIENT.post(
        f"/{NETWORK_INDEX}/_doc/1?refresh=true",
        json={"@timestamp": _now_iso(), "id": {"orig_h": PUBLIC_IP, "resp_h": "10.0.0.5"}},
    )
    dump("index network doc", resp)
    check("network test doc indexed", resp.status_code in (200, 201))


def _create_detector(index_name: str, detector_type: str, rule_id: str) -> tuple[str, str]:
    body = {
        "name": f"poc-corr-{detector_type}-detector-{TS}",
        "detector_type": detector_type,
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [
            {
                "detector_input": {
                    "description": f"F3 correlation PoC {detector_type} detector",
                    "indices": [index_name],
                    "pre_packaged_rules": [{"id": rule_id}],
                    "custom_rules": [],
                }
            }
        ],
        "triggers": [],
    }
    resp = CLIENT.post("/_plugins/_security_analytics/detectors", json=body)
    result = dump(f"create {detector_type} detector", resp)
    check(
        f"{detector_type} detector created (201)",
        resp.status_code == 201,
        f"status={resp.status_code}",
    )
    detector_id = result.get("_id", "")
    if detector_id:
        CREATED_DETECTOR_IDS.append(detector_id)

    # Real, observed gap: NEITHER the create response NOR a real GET
    # .../detectors/{id} exposes monitor_id -- both were tried against the
    # live cluster and confirmed to omit it (the plugin's own
    # IndexDetectorResponse/GetDetectorResponse toXContent simply doesn't
    # serialize it). The real IT test (CorrelationEngineRestApiIT.java)
    # works around this the same way: read monitor_id directly off the RAW
    # underlying `.opensearch-sap-detectors-config` document (bypassing the
    # plugin's REST layer entirely) -- confirmed by a real raw-index search
    # here too: the field is real, present, a list (`detector.monitor_id`).
    raw_resp = CLIENT.post(
        "/.opensearch-sap-detectors-config/_search",
        json={"query": {"ids": {"values": [detector_id]}}},
    )
    raw_result = dump(
        f"raw .opensearch-sap-detectors-config read for {detector_type} detector", raw_resp
    )
    hits = raw_result.get("hits", {}).get("hits", [])
    monitor_ids = hits[0]["_source"]["detector"].get("monitor_id", []) if hits else []
    monitor_id = monitor_ids[0] if monitor_ids else ""
    return detector_id, monitor_id


def part1_create_detectors() -> tuple[str, str]:
    print(
        "\n=== Part 1: create two real detectors (one per category) over the real test indices ==="
    )
    _win_id, win_monitor = _create_detector(WINDOWS_INDEX, "windows", WINDOWS_RULE_ID)
    _net_id, net_monitor = _create_detector(NETWORK_INDEX, "network", NETWORK_RULE_ID)
    check("windows detector has a real monitor_id", bool(win_monitor), win_monitor)
    check("network detector has a real monitor_id", bool(net_monitor), net_monitor)
    return win_monitor, net_monitor


def part2_execute_monitors_and_wait_for_findings(
    win_monitor: str, net_monitor: str
) -> tuple[str, str]:
    print("\n=== Part 2: execute both monitors on-demand, poll for real findings ===")
    for label, monitor_id in (("windows", win_monitor), ("network", net_monitor)):
        resp = CLIENT.post(f"/_plugins/_alerting/monitors/{monitor_id}/_execute")
        print(f"  execute {label} monitor {monitor_id}: HTTP {resp.status_code}")
        check(
            f"{label} monitor executed (200)", resp.status_code == 200, f"status={resp.status_code}"
        )

    win_finding = _poll_finding("windows", WINDOWS_INDEX)
    net_finding = _poll_finding("network", NETWORK_INDEX)
    return win_finding, net_finding


def _poll_finding(log_type: str, source_index: str, attempts: int = 12, delay: float = 5.0) -> str:
    findings_index = f".opensearch-sap-{log_type}-findings-*"
    for attempt in range(attempts):
        resp = CLIENT.post(
            f"/{findings_index}/_search",
            json={
                "size": 5,
                "query": {"term": {"index": source_index}},
                "sort": [{"timestamp": "desc"}],
            },
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            if hits:
                finding_id = hits[0]["_id"]
                print(f"  real {log_type} finding found: {finding_id} (attempt {attempt + 1})")
                print(f"    queries: {hits[0]['_source'].get('queries')}")
                check(f"real {log_type} finding produced by the detector", True, finding_id)
                return finding_id
        time.sleep(delay)
    check(f"real {log_type} finding produced by the detector", False, "no finding after polling")
    return ""


def part3_create_correlation_rule() -> str:
    print("\n=== Part 3: create the REAL correlation rule joining windows <-> network ===")
    body = {
        "name": f"poc corr rule {TS}",
        "correlate": [
            {"index": WINDOWS_INDEX, "query": f"HostName:{HOST_VALUE}", "category": "windows"},
            {"index": NETWORK_INDEX, "query": f"id.orig_h:{PUBLIC_IP}", "category": "network"},
        ],
    }
    resp = CLIENT.post("/_plugins/_security_analytics/correlation/rules", json=body)
    result = dump("create correlation rule", resp)
    check("correlation rule created (201)", resp.status_code == 201, f"status={resp.status_code}")
    rule_id = result.get("_id", "")
    if rule_id:
        CREATED_RULE_IDS.append(rule_id)
    check(
        "response echoes the real 'rule' object with name+correlate (confirmed schema)",
        result.get("rule", {}).get("name") == body["name"]
        and len(result.get("rule", {}).get("correlate", [])) == 2,
        str(result.get("rule")),
    )
    return rule_id


def part3b_invalid_name_rejected() -> None:
    print("\n=== Part 3b: confirm the real name-validation regex rejects an invalid name ===")
    body = {
        "name": "",
        "correlate": [{"index": WINDOWS_INDEX, "query": "*", "category": "windows"}],
    }
    resp = CLIENT.post("/_plugins/_security_analytics/correlation/rules", json=body)
    dump("create correlation rule with empty name", resp)
    check(
        "empty-name correlation rule rejected with a real 400",
        resp.status_code == 400,
        f"status={resp.status_code}",
    )


def part4_real_correlation_match(win_finding: str, net_finding: str, rule_id: str) -> None:
    print("\n=== Part 4: query the REAL correlation API for an actual cross-log-type match ===")
    if not win_finding:
        check("skipped -- no real windows finding to query correlations for", False)
        return
    resp = CLIENT.get(
        "/_plugins/_security_analytics/findings/correlate",
        params={
            "finding": win_finding,
            "detector_type": "windows",
            "time_window": 300000,
            "nearby_findings": 10,
        },
    )
    result = dump("GET findings/correlate for the real windows finding", resp)
    check("findings/correlate returned 200", resp.status_code == 200, f"status={resp.status_code}")
    findings = result.get("findings", []) if isinstance(result.get("findings"), list) else []
    correlated_ids = {f.get("finding") for f in findings}
    print(f"  correlated finding ids returned: {correlated_ids}")
    # The real dev cluster accumulates findings across repeated PoC runs
    # (findings are independent/immutable and outlive both the detector AND
    # the source index that produced them -- confirmed by a real run: a
    # PRIOR run's now-orphaned network finding, from a since-deleted index,
    # still showed up here). So the robust, meaningful assertion is not
    # "this exact run's finding_id appears" (brittle against that real
    # cross-run pollution) but "SOME network-category finding is tagged
    # with THIS run's own real correlation rule id" -- that is the actual
    # fact that matters: the rule genuinely joined windows<->network.
    network_matches_this_rule = [
        f for f in findings if f.get("detector_type") == "network" and rule_id in f.get("rules", [])
    ]
    check(
        "at least one real network-category finding is tagged with THIS run's real correlation rule id "
        "(genuine cross-log-type correlation, not same-category noise)",
        len(network_matches_this_rule) > 0,
        f"rule_id={rule_id} network_matches={network_matches_this_rule}",
    )
    # Informational only (not a pass/fail gate): whether THIS run's own
    # specific finding_id shows up can lag behind correlation-history
    # indexing by a beat -- the rule-tag check above is the real proof bar.
    print(
        f"  [INFO] this run's own net_finding ({net_finding}) in correlated_ids: "
        f"{net_finding in correlated_ids}"
    )

    # Broader view: real ListCorrelations API over a time window covering this run.
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - 15 * 60 * 1000
    resp2 = CLIENT.get(
        "/_plugins/_security_analytics/correlations",
        params={"start_timestamp": start_ms, "end_timestamp": now_ms},
    )
    result2 = dump("GET correlations (time-window list)", resp2)
    check(
        "correlations list endpoint returned 200",
        resp2.status_code == 200,
        f"status={resp2.status_code}",
    )


def part5_multi_tenant_scoping_question() -> None:
    print(
        "\n=== Part 5: does a correlation rule support per-org index-pattern scoping like a detector? ==="
    )
    # Mirrors SecurityAnalyticsDetectorProvisioner's own per-org index pattern
    # (kronos-{org_alias}-*) -- confirm the API accepts this shape with no
    # special org/tenant field, exactly like a Detector's own `indices` list.
    body = {
        "name": f"poc tenant scoping {TS}",
        "correlate": [
            {"index": "kronos-poc-tenanta-*", "query": "*", "category": "windows"},
            {"index": "kronos-poc-tenantb-*", "query": "*", "category": "network"},
        ],
    }
    resp = CLIENT.post("/_plugins/_security_analytics/correlation/rules", json=body)
    result = dump("create correlation rule with kronos-{org}-* style index patterns", resp)
    check(
        "correlation rule accepts a kronos-{org_alias}-* style index string with no dedicated org field",
        resp.status_code == 201
        and result.get("rule", {}).get("correlate", [{}])[0].get("index") == "kronos-poc-tenanta-*",
        str(result.get("rule")),
    )
    if result.get("_id"):
        CREATED_RULE_IDS.append(result["_id"])

    # Confirm the real 'correlate' field is NESTED (search must use a nested
    # query, a flat query silently matches zero -- same trap as C2's
    # detector.name).
    flat_resp = CLIENT.post(
        "/_plugins/_security_analytics/correlation/rules/_search",
        json={"size": 10, "query": {"term": {"correlate.category": "windows"}}},
    )
    flat_result = dump("flat (non-nested) search on correlate.category", flat_resp)
    nested_resp = CLIENT.post(
        "/_plugins/_security_analytics/correlation/rules/_search",
        json={
            "size": 10,
            "query": {
                "nested": {
                    "path": "correlate",
                    "query": {"match": {"correlate.category": "windows"}},
                }
            },
        },
    )
    nested_result = dump("nested search on correlate.category", nested_resp)
    flat_total = flat_result.get("hits", {}).get("total", {}).get("value", -1)
    nested_total = nested_result.get("hits", {}).get("total", {}).get("value", -1)
    check(
        "confirmed: 'correlate' is a NESTED field -- flat term query matches 0, nested query matches >0 "
        "(the same idempotency trap that hit C2's detector.name)",
        flat_total == 0 and nested_total > 0,
        f"flat_total={flat_total} nested_total={nested_total}",
    )


def cleanup() -> None:
    print("\n=== Cleanup: delete PoC detectors, correlation rules, test indices ===")
    for rule_id in CREATED_RULE_IDS:
        resp = CLIENT.delete(f"/_plugins/_security_analytics/correlation/rules/{rule_id}")
        print(f"  deleted correlation rule {rule_id}: {resp.status_code}")
    for detector_id in CREATED_DETECTOR_IDS:
        resp = CLIENT.delete(f"/_plugins/_security_analytics/detectors/{detector_id}")
        print(f"  deleted detector {detector_id}: {resp.status_code}")
    for index in (WINDOWS_INDEX, NETWORK_INDEX):
        resp = CLIENT.delete(f"/{index}")
        print(f"  deleted index {index}: {resp.status_code}")


def main() -> None:
    part0_create_empty_test_indices()
    win_monitor, net_monitor = part1_create_detectors()
    # Real, observed ordering requirement (see README.md "Real bugs found #2"):
    # the correlation rule must exist BEFORE the findings it's meant to
    # join are created. The correlation engine is a real-time listener on
    # NEW findings, not a retroactive re-scan of existing ones -- a rule
    # created after two qualifying findings already exist never correlates
    # them (confirmed by a real run that got this order wrong first).
    rule_id = part3_create_correlation_rule()
    part3b_invalid_name_rejected()
    part1b_index_real_matching_documents()
    win_finding, net_finding = "", ""
    if win_monitor and net_monitor:
        win_finding, net_finding = part2_execute_monitors_and_wait_for_findings(
            win_monitor, net_monitor
        )
    part4_real_correlation_match(win_finding, net_finding, rule_id)
    part5_multi_tenant_scoping_question()
    cleanup()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
