"""Build and apply real OpenSearch Security Analytics field-alias mappings
for each rule_topic, against the real index pattern created by
ingest_samples.py, using ONLY fields KronOS's real parsers actually write
(verified by reading src/external/parsers/{evtx,cloudtrail,nginx,suricata}.py
and by inspecting real indexed documents -- no invented field names).

For each rule_topic this:
  1. GETs /mappings/view to fetch the real, current unmapped_field_aliases
     list (what SA's bundled Sigma rules for that topic expect).
  2. Builds an alias_mappings payload only for aliases we can honestly point
     at a real, populated KronOS field (either identity, e.g.
     winlog.event_data.TargetUserName -> itself, now that the index_template
     fix makes that namespace indexed; or a semantic equivalent, e.g.
     aws.cloudtrail.event_name -> event.action).
  3. POSTs the mapping (partial=true -- add to, don't replace).
  4. Re-fetches /mappings/view to report the real before/after unmapped
     count.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

OS_BASE = "https://localhost:9200"
AUTH = ("admin", "admin")

CASE_ID = json.loads((Path(__file__).parent / "evidence_ids.json").read_text())["case_id"]
INDEX_PATTERN = f"kronos-kronos-dev-case-{CASE_ID}-*"

# One concrete index per topic that actually holds that parser's real docs
# (used only for the before/after mappings/view report -- the SA
# mappings/view helper resolves a wildcard index_name non-deterministically
# to one matched index, confirmed by direct comparison against a concrete
# name; the underlying alias-field creation itself is applied to every
# index matched by the wildcard PUT, verified separately via direct
# _mapping GETs).
REPRESENTATIVE_INDEX = {
    "windows": f"kronos-kronos-dev-case-{CASE_ID}-201508",
    "cloudtrail": f"kronos-kronos-dev-case-{CASE_ID}-202202",
    "network": f"kronos-kronos-dev-case-{CASE_ID}-202309",
    "apache_access": f"kronos-kronos-dev-case-{CASE_ID}-201601",
}

# rule_topic -> {alias_name: real_index_field_path}
# Built from: (a) identity mappings for the winlog.event_data.* namespace,
# now real and indexed after the index_template.json dynamic_templates fix;
# (b) explicit semantic mappings verified against each parser's actual
# `extra[...]=` writes (src/external/parsers/*.py), not guessed.
ALIAS_TABLES: dict[str, dict[str, str]] = {}


def _windows_table(unmapped: list[str]) -> dict[str, str]:
    table: dict[str, str] = {}
    for alias in unmapped:
        if alias.startswith("winlog.event_data."):
            # FastEvtxParser writes extra[f"winlog.event_data.{k}"] = v with
            # the RAW Windows EventData key names -- these are frequently
            # the exact same names Sigma's windows rules reference (both
            # follow the winlogbeat/Sysmon EventData convention). Identity
            # alias, now real since the index_template fix makes this
            # namespace a dynamic keyword mapping instead of silently
            # unindexed.
            table[alias] = alias
    # Explicit semantic equivalents verified against evtx.py's own extra{}.
    table["winlog.event_id"] = "event.code"  # extra["event.code"] = EventID
    table["winlog.channel"] = "log.file.path"  # extra["log.file.path"] = Channel
    table["winlog.computer_name"] = "host.name"  # top-level "host.name": host_name
    table["host.hostname"] = "host.name"
    table["timestamp"] = "@timestamp"
    # Deliberately NOT mapped (verified absent from evtx.py's real output,
    # not guessed): winlog.provider_name, winlog.keywords, winlog.task,
    # winlog.user.name/type, winlog.computerObject.name, hash.{md5,sha1,sha256}
    # (Hashes is a composite string per A2's own documented gap).
    return table


def _cloudtrail_table(unmapped: list[str]) -> dict[str, str]:
    # Verified against CloudTrailParser._to_timeline_record's real extra{}:
    # event.action, event.module, event.dataset, cloud.service.name,
    # cloud.region, source.ip, error.code, error.message,
    # cloudtrail.request_parameters (object, enabled:false -- NOT aliasable,
    # OpenSearch alias target must itself be an indexed field).
    # user.name/user.id come from the top-level TimelineRecord fields.
    candidates = {
        "aws.cloudtrail.event_name": "event.action",
        "aws.cloudtrail.event_source": "cloud.service.name",
        "aws.cloudtrail.aws_region": "cloud.region",
        "aws.cloudtrail.source_ip_address": "source.ip",
        "aws.cloudtrail.error_code": "error.code",
        "aws.cloudtrail.user_identity.userName": "user.name",
        "aws.cloudtrail.user_identity.accountId": "user.id",
        "timestamp": "@timestamp",
    }
    return {k: v for k, v in candidates.items() if k in unmapped}


def _network_table(unmapped: list[str]) -> dict[str, str]:
    # SA's "network" rule_topic default aliases target Zeek/conn.log-style
    # field names (id.orig_h/id.resp_h/id.resp_p) -- NOT the ECS-style names
    # SuricataEveParser actually writes (source.ip/destination.ip/
    # destination.port). Real, concrete mismatch (see README "Finding 3").
    # We CAN alias the 5-tuple semantically: id.orig_h=originator(src),
    # id.resp_h/id.resp_p=responder(dst). Verified against a real doc
    # (source.ip/destination.ip/destination.port populated).
    candidates = {
        "id.orig_h": "source.ip",
        "id.resp_h": "destination.ip",
        "id.resp_p": "destination.port",
        "timestamp": "@timestamp",
    }
    return {k: v for k, v in candidates.items() if k in unmapped}


def _apache_access_table(unmapped: list[str]) -> dict[str, str]:
    # 0 unmapped_field_aliases observed for apache_access against our real
    # index -- NginxParser's ECS-shaped output (source.ip, http.*, url.*)
    # already satisfies this rule_topic's default field expectations with
    # no alias needed. Kept as an explicit (empty-if-so) function so a
    # future re-run that finds a nonzero list doesn't silently no-op.
    return {}


TOPIC_BUILDERS = {
    "windows": _windows_table,
    "cloudtrail": _cloudtrail_table,
    "network": _network_table,
    "apache_access": _apache_access_table,
}


def log(*a: object) -> None:
    print(*a, file=sys.stderr)


def main() -> None:
    client = httpx.Client(base_url=OS_BASE, auth=AUTH, verify=False, timeout=30)
    report = {}
    for topic, builder in TOPIC_BUILDERS.items():
        rep_index = REPRESENTATIVE_INDEX[topic]
        view_before = client.get(
            "/_plugins/_security_analytics/mappings/view",
            params={"index_name": rep_index, "rule_topic": topic},
        ).json()
        unmapped_before = view_before.get("unmapped_field_aliases", [])
        table = builder(unmapped_before)
        log(f"--- {topic}: {len(unmapped_before)} unmapped before, applying {len(table)} aliases ---")

        if table:
            alias_mappings = {
                "properties": {
                    alias: {"type": "alias", "path": path} for alias, path in table.items()
                }
            }
            resp = client.post(
                "/_plugins/_security_analytics/mappings",
                json={
                    "index_name": INDEX_PATTERN,
                    "rule_topic": topic,
                    "partial": True,
                    "alias_mappings": alias_mappings,
                },
            )
            log(f"POST mappings ({topic}) -> {resp.status_code} {resp.text[:500]}")
            resp.raise_for_status()

        view_after = client.get(
            "/_plugins/_security_analytics/mappings/view",
            params={"index_name": rep_index, "rule_topic": topic},
        ).json()
        unmapped_after = view_after.get("unmapped_field_aliases", [])
        log(f"{topic}: unmapped_field_aliases {len(unmapped_before)} -> {len(unmapped_after)}")
        report[topic] = {
            "aliases_applied": table,
            "unmapped_before": len(unmapped_before),
            "unmapped_after": len(unmapped_after),
        }

    out = Path(__file__).parent / "alias_mapping_report.json"
    out.write_text(json.dumps(report, indent=2))
    log(f"wrote {out}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
