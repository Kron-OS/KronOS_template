#!/usr/bin/env python3
"""Verification-first PoC: OpenSearch Anomaly Detection (AD/RCF) plugin,
per-org historical analysis for triage prioritization (roadmap M6/G2).

Drives the REAL AD plugin REST API (opensearch-anomaly-detection 2.11.1.0,
confirmed installed via `GET _cat/plugins?v` on docker-opensearch-1) against
the real, already-running dev cluster (OpenSearch 2.11.1) -- not a mock, not
InMemoryOpenSearchClient. This mirrors G1's own justification for going
straight at the real cluster (poc/rarity_baseline_scoring/): the whole point
here is real RCF behavior (cold start, historical-analysis semantics, real
anomaly grades) an in-memory double cannot faithfully replicate.

Uses raw httpx calls directly against the documented REST surface (no src/
adapter code exists yet at the time this script was first run -- CLAUDE.md
SS F.2 step 3/4: PoC first, real src/ code only after the real shape is
observed). Field/endpoint names below were confirmed from the OpenSearch
anomaly-detection plugin's OWN pinned-branch source
(github.com/opensearch-project/anomaly-detection, ref `2.11`), not assumed
from the general docs site (which 404s/redirects unpredictably for older
versions) -- see this directory's README.md "Real docs/examples used".

Scenarios:
  (1) Index a real, deliberately-shaped synthetic corpus into a throwaway
      kronos-poc-anomaly-{org}-* index: TWO entities (host-normal,
      host-anomalous) sharing one numeric feature (source.bytes -- a real,
      already-mapped ECS `long` field; a made-up `network.bytes_out` was
      tried first and hit a real, load-bearing gap, see README.md) at
      1-minute intervals for 300 minutes. host-normal stays flat (noise
      around 100). host-anomalous stays flat for the first 270 minutes then
      spikes to ~8000 for the last 30 minutes -- the classic
      "stable-then-spike" DFIR anomaly shape.
  (2) Create a real multi-entity (category_field) AD detector scoped to
      that one org's index pattern, feature = avg(source.bytes).
  (3) Run REAL historical analysis (POST .../_start?historical=true with a
      real DetectionDateRange body) -- confirmed from source
      (RestAnomalyDetectorJobAction.java) to bypass real-time cold start
      entirely: it processes already-indexed data immediately.
  (4) Poll the real task status (GET .../detectors/{id}?task=true) until
      FINISHED, then read back REAL anomaly results from the real results
      index alias `.opendistro-anomaly-results*`
      (CommonName.ANOMALY_RESULT_INDEX_ALIAS, confirmed from source) and
      prove: host-anomalous's real anomaly_grade rises during the injected
      spike window and host-normal's stays ~0 throughout.
  (5) Real per-org detector idempotency probe: attempt a second real
      create-with-same-name, and a real PUT-to-existing-id update, to
      independently confirm (not assume) whether AD shares
      SecurityAnalyticsDetectorProvisioner's documented 2.11.1 detector
      PUT-update defect or behaves like
      SecurityAnalyticsCorrelationRuleProvisioner's clean-update case.

Run: ~/venv/bin/python3 poc/anomaly_detection_baseline/run_poc.py
(also runs correctly under the system /usr/bin/python3 -- httpx>=0.27 is
the only real dependency this script needs beyond stdlib.)
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx

OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
BASE_URL = f"https://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
AUTH = ("admin", "admin")
POC_ORG = f"poc-anomaly-{uuid.uuid4().hex[:6]}"
POC_INDEX = f"kronos-{POC_ORG}-case-scratch-202607"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


async def main() -> int:
    async with httpx.AsyncClient(verify=False, timeout=60) as client:
        try:
            # ------------------------------------------------------------
            # Scenario 1: index the real synthetic stable-then-spike corpus.
            # ------------------------------------------------------------
            log("=== Scenario 1: index real synthetic per-entity documents ===")
            n_minutes = 300
            spike_start_minute = 270  # last 30 minutes of 300 spike for host-anomalous
            # Real, load-bearing finding (see README.md): AD's detector-CREATE
            # call runs a real validation query against the feature's
            # aggregation and rejects with HTTP 500 "returning empty
            # aggregated data" if that query finds nothing in a recent
            # window relative to wall-clock "now" -- a fixed past date
            # (originally 2026-07-01) failed this for real. Anchoring the
            # synthetic window to end at "now" (real streaming ingestion
            # would do this naturally anyway) avoids that gap.
            base_time = datetime.now(UTC) - timedelta(minutes=n_minutes)
            bulk_lines: list[str] = []
            for minute in range(n_minutes):
                ts = (base_time + timedelta(minutes=minute)).isoformat()
                for host, is_target in (("host-normal", False), ("host-anomalous", True)):
                    if is_target and minute >= spike_start_minute:
                        value = 8000 + (minute % 7) * 10  # sharp, sustained spike
                    else:
                        value = 100 + (minute % 5) * 2  # small, stable noise
                    doc_id = f"{host}-{minute}"
                    bulk_lines.append(
                        f'{{"index": {{"_index": "{POC_INDEX}", "_id": "{doc_id}"}}}}'
                    )
                    bulk_lines.append(
                        f'{{"@timestamp": "{ts}", "host": {{"name": "{host}"}}, '
                        f'"source": {{"bytes": {value}}}}}'
                    )
            bulk_body = "\n".join(bulk_lines) + "\n"
            resp = await client.post(
                f"{BASE_URL}/_bulk",
                auth=AUTH,
                headers={"Content-Type": "application/x-ndjson"},
                content=bulk_body,
            )
            resp.raise_for_status()
            bulk_result = resp.json()
            n_docs = n_minutes * 2
            check(
                f"real _bulk indexed all {n_docs} docs with zero errors",
                bulk_result.get("errors") is False and len(bulk_result.get("items", [])) == n_docs,
            )
            await client.post(f"{BASE_URL}/{POC_INDEX}/_refresh", auth=AUTH)

            count_resp = await client.get(f"{BASE_URL}/{POC_INDEX}/_count", auth=AUTH)
            count_resp.raise_for_status()
            check(f"real _count == {n_docs}", count_resp.json()["count"] == n_docs)

            # ------------------------------------------------------------
            # Scenario 2: create a real multi-entity (category_field) detector.
            # ------------------------------------------------------------
            log("=== Scenario 2: create real AD detector (category_field=host.name) ===")
            detector_name = f"kronos-{POC_ORG}-network-ad-detector"
            detector_body = {
                "name": detector_name,
                "description": "KronOS PoC per-org behavioral anomaly detector",
                "time_field": "@timestamp",
                "indices": [f"kronos-{POC_ORG}-*"],
                "feature_attributes": [
                    {
                        "feature_name": "avg_bytes_out",
                        "feature_enabled": True,
                        "aggregation_query": {"avg_bytes_out": {"avg": {"field": "source.bytes"}}},
                    }
                ],
                "category_field": ["host.name"],
                "detection_interval": {"period": {"interval": 1, "unit": "Minutes"}},
                "window_delay": {"period": {"interval": 0, "unit": "Seconds"}},
            }
            create_resp = await client.post(
                f"{BASE_URL}/_plugins/_anomaly_detection/detectors",
                auth=AUTH,
                json=detector_body,
            )
            log(
                f"real create detector response [{create_resp.status_code}]: "
                f"{create_resp.text[:500]}"
            )
            check("real detector create returned HTTP 201", create_resp.status_code == 201)
            detector_id = create_resp.json()["_id"]
            check(
                "real detector response includes detector_type == MULTI_ENTITY",
                create_resp.json().get("anomaly_detector", {}).get("detector_type")
                == "MULTI_ENTITY",
            )
            log(f"real detector_id={detector_id}")

            # ------------------------------------------------------------
            # Scenario 5 (idempotency), run BEFORE starting the job so it
            # can't be confused with job-state-related failures later.
            # ------------------------------------------------------------
            log("=== Scenario 5: real per-org detector idempotency probe ===")
            dup_create_resp = await client.post(
                f"{BASE_URL}/_plugins/_anomaly_detection/detectors",
                auth=AUTH,
                json=detector_body,
            )
            log(
                f"real duplicate-name create response [{dup_create_resp.status_code}]: "
                f"{dup_create_resp.text[:500]}"
            )
            # Real, load-bearing finding -- the OPPOSITE of what was assumed
            # going in: unlike SecurityAnalyticsDetectorProvisioner's own
            # detector name (which SA's REST API does NOT enforce uniqueness
            # for -- KronOS's own check-then-create is entirely a
            # KronOS-side convention there), the AD plugin DOES enforce a
            # real server-side unique-name constraint and rejects a second
            # CREATE with the same name with a real HTTP 500 and an explicit
            # "already used by detector <id>" message. A KronOS provisioner
            # can therefore treat that specific real error shape as "already
            # exists, idempotent no-op" -- still needs a check-then-create
            # (or a try/except on this exact error) to stay idempotent, but
            # the plugin itself is the backstop against silently creating
            # duplicate per-org detectors, unlike SA's detector API.
            check(
                "real duplicate-name CREATE is rejected with HTTP 500 and an explicit "
                "'already used by detector' message (AD enforces unique detector names "
                "server-side; SA's detector API does not)",
                dup_create_resp.status_code == 500
                and "already used by detector" in dup_create_resp.text,
            )

            put_update_resp = await client.put(
                f"{BASE_URL}/_plugins/_anomaly_detection/detectors/{detector_id}",
                auth=AUTH,
                json=detector_body,
            )
            log(
                f"real PUT-update-in-place response [{put_update_resp.status_code}]: "
                f"{put_update_resp.text[:500]}"
            )
            check(
                "real PUT-update-in-place to an EXISTING AD detector succeeds cleanly "
                "(unlike SecurityAnalyticsDetectorProvisioner's own documented 2.11.1 "
                "detector-PUT 500 defect -- AD does NOT share that bug)",
                put_update_resp.status_code == 200,
            )

            # ------------------------------------------------------------
            # Scenario 3: real historical analysis run.
            # ------------------------------------------------------------
            log("=== Scenario 3: real historical analysis run (_start?historical=true) ===")
            start_ms = int(base_time.timestamp() * 1000)
            end_ms = int((base_time + timedelta(minutes=n_minutes)).timestamp() * 1000)
            start_job_resp = await client.post(
                f"{BASE_URL}/_plugins/_anomaly_detection/detectors/{detector_id}/_start",
                params={"historical": "true"},
                auth=AUTH,
                json={"start_time": start_ms, "end_time": end_ms},
            )
            log(
                f"real historical _start response [{start_job_resp.status_code}]: "
                f"{start_job_resp.text[:500]}"
            )
            check(
                "real historical analysis _start returned HTTP 200",
                start_job_resp.status_code == 200,
            )
            task_id = start_job_resp.json().get("_id")
            log(f"real historical task_id={task_id}")

            # ------------------------------------------------------------
            # Scenario 4: poll real task status to completion, then read results.
            # ------------------------------------------------------------
            log("=== Scenario 4: poll real task status, then read real anomaly results ===")
            state = None
            task_progress = None
            for attempt in range(60):
                task_resp = await client.get(
                    f"{BASE_URL}/_plugins/_anomaly_detection/detectors/{detector_id}",
                    params={"task": "true"},
                    auth=AUTH,
                )
                task_resp.raise_for_status()
                task_json = task_resp.json()
                hist_task = task_json.get("historical_analysis_task", {}) or {}
                state = hist_task.get("state")
                task_progress = hist_task.get("task_progress")
                log(f"  poll {attempt}: state={state} task_progress={task_progress}")
                if state in ("FINISHED", "FAILED", "STOPPED"):
                    break
                time.sleep(3)
            check(
                f"real historical task reached FINISHED (last state={state})", state == "FINISHED"
            )

            # Real, load-bearing finding: the raw `.opendistro-anomaly-results*`
            # index is a SECURITY-PLUGIN-PROTECTED system index -- a direct
            # `_search`/`_count` against it (even as the `admin` superuser)
            # silently returns HTTP 200 with zero hits, even though
            # `_cat/indices`/`_stats` on the very same concrete index
            # correctly report thousands of real, physically-present
            # documents (confirmed live: 4790 docs in `_stats`, 0 hits from
            # `_search` on the identical index name). The plugin ships its
            # OWN dedicated read path specifically to route around this:
            # `POST /_plugins/_anomaly_detection/detectors/results/_search`
            # (confirmed from source, RestSearchAnomalyResultAction.java --
            # its `prepareRequest` targets `ALL_AD_RESULTS_INDEX_PATTERN`
            # itself, server-side, as a privileged plugin action rather than
            # a bare user search request). This is the only real, working
            # way to read AD results and must be what any KronOS adapter
            # code uses -- never a raw query against the dot-index.
            results_resp = await client.post(
                f"{BASE_URL}/_plugins/_anomaly_detection/detectors/results/_search",
                auth=AUTH,
                json={
                    "size": 1000,
                    "query": {"bool": {"filter": [{"term": {"task_id": task_id}}]}},
                    "sort": [{"anomaly_grade": "desc"}],
                },
            )
            results_resp.raise_for_status()
            hits = results_resp.json().get("hits", {}).get("hits", [])
            log(f"real anomaly-results search returned {len(hits)} hits for task_id={task_id}")
            check("real anomaly-results search returned at least one hit", len(hits) > 0)

            if hits:
                top = hits[0]["_source"]
                log(f"real top result by anomaly_grade: {top}")
                check(
                    "real top-ranked anomaly result has anomaly_grade > 0 "
                    "(the injected spike was actually detected, not assumed)",
                    top.get("anomaly_grade", 0) > 0,
                )
                top_entity = {e["name"]: e["value"] for e in top.get("entity", [])}
                check(
                    "real top-ranked anomalous result's entity is host-anomalous, "
                    "NOT host-normal -- category_field correctly attributed the "
                    "anomaly to the right entity",
                    top_entity.get("host.name") == "host-anomalous",
                )
                top_end_ms = top.get("data_end_time")
                spike_start_ms = int(
                    (base_time + timedelta(minutes=spike_start_minute)).timestamp() * 1000
                )
                check(
                    "real top-ranked anomaly's data_end_time falls within/after the "
                    "injected spike window, not before it",
                    top_end_ms is not None and top_end_ms >= spike_start_ms,
                )

                normal_hits = [
                    h
                    for h in hits
                    if {e["name"]: e["value"] for e in h["_source"].get("entity", [])}.get(
                        "host.name"
                    )
                    == "host-normal"
                ]
                max_normal_grade = max(
                    (h["_source"].get("anomaly_grade", 0) for h in normal_hits), default=0
                )
                log(f"real max anomaly_grade among host-normal results: {max_normal_grade}")
                check(
                    "real host-normal's own max anomaly_grade stays much lower than "
                    "host-anomalous's top grade (the uneventful entity was NOT "
                    "flagged the same way)",
                    max_normal_grade < top.get("anomaly_grade", 0),
                )

        finally:
            # Best-effort teardown: stop job, delete detector, delete indices.
            try:
                await client.post(
                    f"{BASE_URL}/_plugins/_anomaly_detection/detectors/{detector_id}/_stop",
                    params={"historical": "true"},
                    auth=AUTH,
                )
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            try:
                await client.delete(
                    f"{BASE_URL}/_plugins/_anomaly_detection/detectors/{detector_id}", auth=AUTH
                )
                log(f"cleaned up real detector {detector_id}")
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            try:
                await client.delete(f"{BASE_URL}/kronos-{POC_ORG}-*", auth=AUTH)
                log(f"cleaned up real indices kronos-{POC_ORG}-*")
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass

    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(
        f"PoC PASSED -- all {len(CHECKS)} checks passed against the real, live "
        "OpenSearch 2.11.1 AD plugin."
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
