"""PoC: reproduces the A1 silent-match bug against a real OpenSearch cluster,
then proves the hardened index_template.json fixes it.

The bug: without an explicit mapping, OpenSearch's dynamic mapping maps a
string field to `text` (analyzed) plus a `.keyword` sub-field. A Sigma-style
`term` query -- which Security Analytics compiles Sigma rules into --
expects exact-match `keyword` semantics against the bare field name. Against
a dynamically-mapped field, that query silently returns zero hits: the field
exists, is populated, and is even searchable via `.keyword` or full-text
`match`, but a `term` query on the un-suffixed name never matches. No error,
no warning -- just an empty result set, which for a detection rule means a
threat that silently never fires.

Run: source ~/venv/bin/activate && python poc/ecs_schema_hardening/run_poc.py
Requires the real dev-stack OpenSearch (kronos.local / localhost:9200).
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

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def main() -> None:
    client = httpx.Client(base_url=OS_URL, auth=AUTH, verify=False, timeout=30)
    suffix = int(time.time())
    before_index = f"kronos-poc-before-{suffix}"
    after_index = f"kronos-poc-after-{suffix}"

    doc = {
        "@timestamp": "2026-07-29T10:00:00Z",
        "message": "process created",
        "process": {"command_line": "cmd.exe /c whoami", "pid": 4242},
    }

    # -----------------------------------------------------------------
    # 1. BEFORE: an index with NO explicit mapping for process.command_line
    #    (mirrors the original index_template.json: no `dynamic` policy,
    #    no dynamic_templates -- field lands however OpenSearch's default
    #    dynamic mapping decides, which is `text` + `.keyword` for strings).
    # -----------------------------------------------------------------
    print("=== 1. BEFORE: real reproduction of the silent-match bug ===")
    client.delete(f"/{before_index}")  # idempotent cleanup from a prior run
    resp = client.put(f"/{before_index}")
    check("created 'before' index (no explicit mapping)", resp.status_code < 300, str(resp.status_code))

    resp = client.post(f"/{before_index}/_doc/1?refresh=true", json=doc)
    check("indexed the real doc", resp.status_code < 300, str(resp.status_code))

    mapping = client.get(f"/{before_index}/_mapping").json()
    field_type = (
        mapping[before_index]["mappings"]["properties"]["process"]["properties"]["command_line"]["type"]
    )
    check(
        "process.command_line was dynamically mapped as 'text', not 'keyword'",
        field_type == "text",
        field_type,
    )

    term_query = {"query": {"term": {"process.command_line": "cmd.exe /c whoami"}}}
    resp = client.post(f"/{before_index}/_search", json=term_query)
    hits_before = resp.json()["hits"]["total"]["value"]
    check(
        "Sigma-style term query returns ZERO hits despite the doc existing (the bug, captured for real)",
        hits_before == 0,
        f"hits={hits_before}",
    )

    # Prove the document really is there (not a bad query) via match_all.
    resp = client.post(f"/{before_index}/_search", json={"query": {"match_all": {}}})
    total = resp.json()["hits"]["total"]["value"]
    check("the document genuinely exists in the index", total == 1, f"total={total}")

    # -----------------------------------------------------------------
    # 2. AFTER: apply the REAL, hardened index_template.json and confirm
    #    the identical query now matches.
    # -----------------------------------------------------------------
    print("\n=== 2. AFTER: the real hardened index_template.json fixes it ===")
    template_path = REPO_ROOT / "src/adapter/opensearch/index_template.json"
    template = json.loads(template_path.read_text())

    client.delete(f"/{after_index}")
    resp = client.put(
        f"/{after_index}",
        json={"settings": template["template"]["settings"], "mappings": template["template"]["mappings"]},
    )
    check("created 'after' index using the real hardened template", resp.status_code < 300, str(resp.status_code))

    resp = client.post(f"/{after_index}/_doc/1?refresh=true", json=doc)
    check("indexed the identical doc into the hardened index", resp.status_code < 300, str(resp.status_code))

    mapping = client.get(f"/{after_index}/_mapping").json()
    field_type = (
        mapping[after_index]["mappings"]["properties"]["process"]["properties"]["command_line"]["type"]
    )
    check("process.command_line is explicitly mapped as 'keyword'", field_type == "keyword", field_type)

    resp = client.post(f"/{after_index}/_search", json=term_query)
    hits_after = resp.json()["hits"]["total"]["value"]
    check(
        "the SAME term query now returns the document (bug fixed, captured for real)",
        hits_after == 1,
        f"hits={hits_after}",
    )

    # -----------------------------------------------------------------
    # 3. Confirm dynamic:false behavior for an unexpected/unmapped field --
    #    stored (in _source) but not indexed/searchable, not a write failure.
    # -----------------------------------------------------------------
    print("\n=== 3. Confirm dynamic:false: unmapped field is stored but not searchable (not rejected) ===")
    weird_doc = {**doc, "some_totally_unexpected_field": "unexpected-value-xyz"}
    resp = client.post(f"/{after_index}/_doc/2?refresh=true", json=weird_doc)
    check(
        "a document with an unmapped field is still ACCEPTED (dynamic:false, not 'strict')",
        resp.status_code < 300,
        str(resp.status_code),
    )
    resp = client.post(
        f"/{after_index}/_search",
        json={"query": {"term": {"some_totally_unexpected_field": "unexpected-value-xyz"}}},
    )
    unmapped_hits = resp.json()["hits"]["total"]["value"]
    check(
        "the unmapped field is NOT searchable via term query (expected: dynamic:false trade-off)",
        unmapped_hits == 0,
        f"hits={unmapped_hits}",
    )
    resp = client.get(f"/{after_index}/_doc/2")
    stored_value = resp.json()["_source"].get("some_totally_unexpected_field")
    check(
        "but the raw value IS still present in _source (safe, just unindexed -- not silently dropped)",
        stored_value == "unexpected-value-xyz",
        stored_value,
    )

    # Cleanup
    client.delete(f"/{before_index}")
    client.delete(f"/{after_index}")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
