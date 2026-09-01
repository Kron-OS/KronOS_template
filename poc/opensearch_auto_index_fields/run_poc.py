"""PoC: reproduces the "unmapped field silently unsearchable" bug against a
real, live OpenSearch cluster, then proves the fix -- both for FUTURE writes
(dynamic_templates catch-all) and for documents ALREADY indexed under the
old, restrictive mapping (a real, live retroactive fix via _update_by_query,
no re-parse needed).

Real user report this closes: after parsing, a genuinely new/uncommon field
(the report's own example: `event_identifier`) could not be filtered on --
confirmed via `docker exec ... _mapping` against a real, live dev-stack
index that `dynamic: false` plus only ONE narrow dynamic_template
(`winlog.event_data.*`) means any OTHER unmapped field (a different
parser's own extra[] output, or any genuinely new field) is stored in
`_source` but never added to the Lucene index -- silently unfilterable,
exactly as `poc/ecs_schema_hardening/`'s own `_meta.dynamic_policy` string
already documented as the deliberate (if incomplete) trade-off.

`poc/ecs_schema_hardening/` already fixed the ORIGINAL text+keyword
multi-field bug (a `term` query against the bare field name silently
matching nothing) by switching to `dynamic: false` + a curated allowlist.
That PoC's own README explicitly flagged the follow-up this one closes:
"Existing indices: an index template only applies to newly-created
indices -- live kronos-* indices keep their current mapping... no reindex
was performed as part of this pass (out of scope)."

Indices are created directly (mapping body inline) rather than via a named
index template registration, to avoid colliding with the real
"kronos-template" already registered on this cluster by
OpenSearchClient.ensure_index_template() (two templates cannot claim
overlapping index_patterns) -- this PoC is about the MAPPING behavior
itself, not template-registration precedence, which is already exercised
by the real ingest pipeline on every run.

Run: source ~/venv/bin/activate && python poc/opensearch_auto_index_fields/run_poc.py
Requires the real dev-stack OpenSearch (localhost:9200).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx

OS_URL = "https://localhost:9200"
AUTH = ("admin", "admin")
REPO_ROOT = Path(__file__).resolve().parents[2]
INDEX_OLD = "kronos-poc-dynfield-old-000000"
INDEX_NEW = "kronos-poc-dynfield-new-000000"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def load_template() -> dict:
    path = REPO_ROOT / "src" / "adapter" / "opensearch" / "index_template.json"
    with path.open() as fh:
        return json.load(fh)


# The mapping this repo used BEFORE Milestone UUUU -- inlined here (not
# re-read from git history) so this PoC stays a self-contained, re-runnable
# reproduction of the real historical bug regardless of the working tree's
# current state.
OLD_MAPPING = {
    "dynamic": False,
    "dynamic_templates": [
        {
            "winlog_event_data_strings": {
                "path_match": "winlog.event_data.*",
                "match_mapping_type": "string",
                "mapping": {"type": "keyword"},
            }
        }
    ],
    "properties": {
        "@timestamp": {"type": "date"},
        "message": {"type": "text"},
    },
}


def main() -> None:
    client = httpx.Client(base_url=OS_URL, auth=AUTH, verify=False, timeout=30)
    client.delete(f"/{INDEX_OLD}")
    client.delete(f"/{INDEX_NEW}")

    # --- Step 1: reproduce the bug under the OLD (pre-Milestone-UUUU) mapping ---
    resp = client.put(f"/{INDEX_OLD}", json={"mappings": OLD_MAPPING})
    check("index created with the OLD (dynamic:false) mapping", resp.status_code == 200, f"status={resp.status_code} body={resp.text[:200]}")

    doc1_id = "doc-before-fix"
    resp = client.put(
        f"/{INDEX_OLD}/_doc/{doc1_id}?refresh=true",
        json={"@timestamp": "2015-08-01T00:00:00Z", "event_identifier": "4624", "message": "logon"},
    )
    check("doc with unmapped 'event_identifier' field accepted (201)", resp.status_code == 201, f"status={resp.status_code} body={resp.text[:300]}")

    mapping = client.get(f"/{INDEX_OLD}/_mapping").json()
    props = mapping[INDEX_OLD]["mappings"].get("properties", {})
    check("'event_identifier' NOT in the real mapping (the bug)", "event_identifier" not in props, f"properties keys={list(props.keys())}")

    resp = client.post(f"/{INDEX_OLD}/_search", json={"query": {"term": {"event_identifier": "4624"}}})
    hits_before = resp.json()["hits"]["total"]["value"]
    check("term query on unmapped field returns ZERO hits despite the doc existing (the bug, reproduced live)", hits_before == 0, f"hits={hits_before}")

    resp = client.get(f"/{INDEX_OLD}/_doc/{doc1_id}")
    check("the value IS still present in _source (not silently dropped, as designed)", resp.json()["_source"].get("event_identifier") == "4624")

    # --- Step 2: apply the FIX to that SAME, already-existing index (the "user can't update it manually" fix) ---
    new_template = load_template()
    new_mappings = new_template["template"]["mappings"]
    check("index_template.json now sets dynamic: true at root", new_mappings["dynamic"] is True, f"dynamic={new_mappings['dynamic']!r}")

    live_mapping_patch = {
        "dynamic": new_mappings["dynamic"],
        "dynamic_templates": new_mappings["dynamic_templates"],
    }
    resp = client.put(f"/{INDEX_OLD}/_mapping", json=live_mapping_patch)
    check("live _mapping PUT on the EXISTING (old-mapping) index accepted -- no reindex needed for this step", resp.status_code == 200, f"status={resp.status_code} body={resp.text[:300]}")

    # --- Step 3: a NEW document with a NEW unmapped field, written into the SAME (already-existing) index ---
    doc2_id = "doc-after-fix"
    resp = client.put(
        f"/{INDEX_OLD}/_doc/{doc2_id}?refresh=true",
        json={"@timestamp": "2015-08-01T00:01:00Z", "event_identifier": "4625", "another_new_field": "some-value"},
    )
    check("second doc (different unmapped fields) accepted", resp.status_code == 201, f"status={resp.status_code}")

    mapping2 = client.get(f"/{INDEX_OLD}/_mapping").json()
    props2 = mapping2[INDEX_OLD]["mappings"].get("properties", {})
    check("'event_identifier' now appears in the live mapping as keyword", props2.get("event_identifier", {}).get("type") == "keyword", f"event_identifier mapping={props2.get('event_identifier')}")
    check("'another_new_field' (never seen before, no hardcoded rule) also auto-mapped as keyword", props2.get("another_new_field", {}).get("type") == "keyword", f"another_new_field mapping={props2.get('another_new_field')}")

    resp = client.post(f"/{INDEX_OLD}/_search", json={"query": {"term": {"event_identifier": "4625"}}})
    hits_new_doc = resp.json()["hits"]["total"]["value"]
    check("term query on the NEW doc's field now returns a real hit", hits_new_doc == 1, f"hits={hits_new_doc}")

    # --- Step 4: retroactive fix for the FIRST doc (written before the mapping fix) ---
    # _update_by_query re-processes each document's still-intact _source
    # against the index's CURRENT (now-fixed) mapping when it writes the
    # document back -- no re-parse of the original evidence file needed.
    resp = client.post(f"/{INDEX_OLD}/_update_by_query?refresh=true&conflicts=proceed", json={"query": {"match_all": {}}})
    check("_update_by_query against the whole index succeeded", resp.status_code == 200, f"status={resp.status_code} body={resp.text[:300]}")
    updated = resp.json().get("updated", 0)
    check("_update_by_query reports real documents updated", updated >= 1, f"updated={updated}")

    time.sleep(1)  # real index refresh latency, not simulated
    resp = client.post(f"/{INDEX_OLD}/_search", json={"query": {"term": {"event_identifier": "4624"}}})
    hits_retro = resp.json()["hits"]["total"]["value"]
    check("term query on the FIRST doc's field (written BEFORE the fix) now returns a real hit -- retroactive fix confirmed live", hits_retro == 1, f"hits={hits_retro}")

    # --- Step 5: a genuinely FRESH index (created via the real, fixed template content directly) behaves the same, with zero live-patch step ---
    resp = client.put(f"/{INDEX_NEW}", json={"mappings": new_mappings})
    check("fresh index created directly with the NEW mapping content", resp.status_code == 200, f"status={resp.status_code} body={resp.text[:200]}")
    resp = client.put(
        f"/{INDEX_NEW}/_doc/doc1?refresh=true",
        json={"@timestamp": "2026-01-01T00:00:00Z", "event_identifier": "9999"},
    )
    check("doc accepted into the fresh index", resp.status_code == 201)
    resp = client.post(f"/{INDEX_NEW}/_search", json={"query": {"term": {"event_identifier": "9999"}}})
    check("fresh index auto-indexes an unmapped field with zero extra steps", resp.json()["hits"]["total"]["value"] == 1)

    # --- Step 6: confirm the ORIGINAL bug this template already fixed once is NOT reintroduced --
    # (a genuinely known, explicitly-mapped ECS field must still behave as
    # pure keyword, not the OpenSearch-default text+.keyword multi-field
    # split -- the whole reason dynamic:false existed in the first place).
    resp = client.put(
        f"/{INDEX_NEW}/_doc/doc2?refresh=true",
        json={"kronos": {"org_id": "11111111-1111-1111-1111-111111111111"}},
    )
    check("doc with an explicitly-mapped kronos.org_id accepted", resp.status_code == 201)
    resp = client.post(f"/{INDEX_NEW}/_search", json={"query": {"term": {"kronos.org_id": "11111111-1111-1111-1111-111111111111"}}})
    check("explicitly-mapped field still a real term-queryable keyword (original Sigma bug NOT reintroduced)", resp.json()["hits"]["total"]["value"] == 1)

    # --- Cleanup ---
    client.delete(f"/{INDEX_OLD}")
    client.delete(f"/{INDEX_NEW}")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
