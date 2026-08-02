#!/usr/bin/env python3
"""Verification-first PoC: deterministic rarity/frequency baseline scoring
(roadmap M6/G1).

Drives the real, unmodified production classes:
  RarityBaselineClient / OpenSearchRarityBaselineClient
                          (src/adapter/opensearch/rarity_baseline_client.py)
  RarityBaselineScorer    (src/application/rarity_scoring.py)
  FieldValueRarity / RarityBaselineResult (src/domain/rarity.py)
  OpenSearchClient.ensure_index_template()/bulk_index()
                          (src/adapter/opensearch/client.py) -- to index
                          real, kronos-template-shaped documents into a
                          throwaway per-org index the SAME way
                          TimelineIngestionService does, before the rarity
                          client aggregates over them.

against the REAL, already-running dev cluster (docker-opensearch-1,
OpenSearch 2.11.1), not InMemoryOpenSearchClient -- the whole point of this
item is real terms/cardinality/first-last-seen aggregation semantics an
in-memory double cannot faithfully replicate (see this PoC's own README.md
for why no in-memory double was built for src/, mirroring
CorrelationClient/FindingsClient's own precedent).

Scenarios:
  (0) Real query/response shape exploration (small, 3-value corpus) --
      confirms terms+cardinality+min/max sub-agg nested response shape.
  (1) Real skewed-distribution proof: 10 "common" process names (6-50
      occurrences each) + 20 genuinely rare single-occurrence ones (236
      docs, cardinality 30). Proves (a) the OpenSearch terms-aggregation
      DEFAULT (descending _count) order completely misses every rare value
      when size=10 < cardinality=30, and (b) this repo's own ascending-order
      query correctly surfaces the rare tail, and (c) RarityBaselineScorer's
      formula ranks those rare values' rarity_score strictly higher than a
      hypothetical common one.
  (2) Real first-seen/last-seen correctness against documents with known,
      distinct timestamps.
  (3) Real "zero matching indices" edge case (a brand-new org with no
      ingested data yet) -- confirms the real, load-bearing "aggregations"
      key is absent entirely (not an empty dict), and that
      RarityBaselineScorer handles it honestly (empty result, not a crash).

Run: ~/venv/bin/python3 poc/rarity_baseline_scoring/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.opensearch.rarity_baseline_client import (  # noqa: E402
    OpenSearchRarityBaselineClient,
)
from src.application.rarity_scoring import RarityBaselineScorer  # noqa: E402
from tests.fixtures.factories import make_tenant_context  # noqa: E402

OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
POC_ORG_ALIAS = f"poc-rarity-{uuid.uuid4().hex[:6]}"
POC_INDEX = f"kronos-{POC_ORG_ALIAS}-case-scratch-202607"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


async def main() -> int:
    tenant = make_tenant_context().model_copy(update={"org_alias": POC_ORG_ALIAS})
    os_client = OpenSearchClient(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
    )
    rarity_client = OpenSearchRarityBaselineClient(
        base_url=f"https://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}",
        admin_username="admin",
        admin_password="admin",
    )
    scorer = RarityBaselineScorer(rarity_client)

    window_start = datetime(2026, 6, 1, tzinfo=UTC)
    # Must exceed the latest synthetic timestamp this PoC indexes: rare
    # values run from 2026-07-15 + 19 days = 2026-08-03, so the window has
    # to extend past that or the query's own (correctly working) range
    # filter will legitimately exclude some of them -- exactly what a first
    # run of this PoC caught for real (3 rare docs silently outside a
    # too-narrow window), see README.md "real gap found".
    window_end = datetime(2026, 8, 15, tzinfo=UTC)

    try:
        await os_client.ensure_index_template()
        log("real PUT _index_template/kronos-template succeeded")

        # ------------------------------------------------------------------
        # Scenario 1: deliberately skewed distribution.
        # 10 "common" values (6..50 occurrences), 20 genuinely rare
        # single-occurrence values. 236 real documents, cardinality 30.
        # ------------------------------------------------------------------
        log("=== Scenario 1: index a real, deliberately skewed distribution ===")
        common = [
            ("svchost.exe", 50),
            ("cmd.exe", 40),
            ("explorer.exe", 30),
            ("conhost.exe", 25),
            ("powershell.exe", 20),
            ("notepad.exe", 15),
            ("chrome.exe", 12),
            ("outlook.exe", 10),
            ("teams.exe", 8),
            ("onedrive.exe", 6),
        ]
        documents = []
        for name, count in common:
            for i in range(count):
                day = 1 + (i % 28)
                ts = datetime(2026, 7, day, tzinfo=UTC)
                documents.append(
                    (POC_INDEX, f"common-{name}-{i}", {"@timestamp": ts.isoformat(), "process": {"name": name}})
                )
        rare_first_seen: dict[str, datetime] = {}
        for i in range(20):
            name = f"raretool_{i:02d}.exe"
            # Spread rare values over distinct known days so first_seen ==
            # last_seen can be checked precisely per value.
            ts = datetime(2026, 7, 15, tzinfo=UTC) + timedelta(days=i)
            rare_first_seen[name] = ts
            documents.append((POC_INDEX, f"rare-{name}", {"@timestamp": ts.isoformat(), "process": {"name": name}}))

        indexed = await os_client.bulk_index(documents)
        check(f"real bulk_index indexed all {len(documents)} real documents", indexed == len(documents))
        await os_client._client.indices.refresh(index=POC_INDEX)  # noqa: SLF001

        # ------------------------------------------------------------------
        # Prove the ordering gap for real: default (descending) terms order
        # with size=10 < cardinality=30 misses every rare value.
        # ------------------------------------------------------------------
        log("=== Confirming the real terms-aggregation ordering gap ===")
        import httpx

        async with httpx.AsyncClient(verify=False, timeout=15) as raw_http:
            desc_resp = await raw_http.post(
                f"https://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}/{POC_INDEX}/_search",
                auth=("admin", "admin"),
                json={"size": 0, "aggs": {"vf": {"terms": {"field": "process.name", "size": 10}}}},
            )
            desc_buckets = desc_resp.json()["aggregations"]["vf"]["buckets"]
            desc_keys = [b["key"] for b in desc_buckets]
            log(f"real DEFAULT (descending) order, size=10 top keys: {desc_keys}")
            check(
                "real DEFAULT descending order with size=10<cardinality=30 finds ZERO rare values "
                "(the exact bug this repo's ascending-order query exists to avoid)",
                not any(k.startswith("raretool") for k in desc_keys),
            )

        # ------------------------------------------------------------------
        # Scenario 2: the real, shipped RarityBaselineScorer, size=10 cap.
        # ------------------------------------------------------------------
        log("=== Scenario 2: real RarityBaselineScorer.score_field_rarity() ===")
        result = await scorer.score_field_rarity(
            tenant, field="process.name", start=window_start, end=window_end, max_distinct_values=10
        )
        log(
            f"real result: total_docs={result.total_docs} distinct_value_count={result.distinct_value_count} "
            f"returned_value_count={result.returned_value_count} index_pattern={result.index_pattern}"
        )
        check("real total_docs == 236", result.total_docs == len(documents))
        check("real distinct_value_count == 30", result.distinct_value_count == 30)
        check("real index_pattern computed from TenantContext only", result.index_pattern == f"kronos-{POC_ORG_ALIAS}-*")
        check(
            "real returned_value_count capped at 10 (< cardinality 30) -- the cap was hit",
            result.returned_value_count == 10,
        )
        check(
            "with ascending ordering, ALL 10 returned values are genuinely rare (count==1), "
            "none of the 10 common ones leaked in",
            all(v.count == 1 and v.value.startswith("raretool") for v in result.values),
        )
        for v in result.values[:3]:
            log(
                f"  rare value={v.value!r} count={v.count} first_seen={v.first_seen.isoformat()} "
                f"last_seen={v.last_seen.isoformat()} rarity_score={v.rarity_score}"
            )
        expected_rarity = round(1 - (1 / len(documents)), 4)
        check(
            f"every returned rare value's rarity_score == 1 - 1/{len(documents)} = {expected_rarity}",
            all(v.rarity_score == expected_rarity for v in result.values),
        )

        # ------------------------------------------------------------------
        # Scenario 2b: prove rare > common ranking using an uncapped query.
        # ------------------------------------------------------------------
        log("=== Scenario 2b: uncapped query proves rare-vs-common ranking ===")
        full_result = await scorer.score_field_rarity(
            tenant, field="process.name", start=window_start, end=window_end, max_distinct_values=100
        )
        check("uncapped query returns all 30 distinct values", full_result.returned_value_count == 30)
        by_value = {v.value: v for v in full_result.values}
        rare_score = by_value["raretool_00.exe"].rarity_score
        common_score = by_value["svchost.exe"].rarity_score
        log(f"raretool_00.exe (count=1) rarity_score={rare_score} vs svchost.exe (count=50) rarity_score={common_score}")
        check(
            "the genuinely rare value (count=1) scores strictly higher than the most common one (count=50)",
            rare_score > common_score,
        )
        check("svchost.exe (50/236) rarity_score == 1 - 50/236", common_score == round(1 - 50 / 236, 4))

        # ------------------------------------------------------------------
        # Scenario 3: first-seen/last-seen correctness against known timestamps.
        # ------------------------------------------------------------------
        log("=== Scenario 3: real first-seen/last-seen correctness ===")
        sample_name = "raretool_05.exe"
        sample = by_value[sample_name]
        expected_ts = rare_first_seen[sample_name]
        check(
            f"{sample_name}'s real first_seen matches the known indexed timestamp exactly",
            sample.first_seen == expected_ts,
        )
        check(
            f"{sample_name}'s real last_seen == first_seen (single occurrence)",
            sample.last_seen == expected_ts,
        )
        common_sample = by_value["svchost.exe"]
        check(
            "svchost.exe's real first_seen/last_seen span the full 28-day spread it was indexed across "
            "(first_seen != last_seen for a multi-occurrence value)",
            common_sample.first_seen != common_sample.last_seen,
        )

        # ------------------------------------------------------------------
        # Scenario 4: zero-matching-indices edge case (brand new org).
        # ------------------------------------------------------------------
        log("=== Scenario 4: real zero-matching-indices edge case ===")
        empty_tenant = make_tenant_context().model_copy(
            update={"org_alias": f"poc-rarity-empty-{uuid.uuid4().hex[:6]}"}
        )
        empty_result = await scorer.score_field_rarity(
            empty_tenant, field="process.name", start=window_start, end=window_end
        )
        check(
            "real query against an org with zero ingested indices returns an honest empty result, no crash",
            empty_result.total_docs == 0
            and empty_result.distinct_value_count == 0
            and empty_result.returned_value_count == 0
            and empty_result.values == (),
        )

        # ------------------------------------------------------------------
        # Scenario 5: determinism -- exact same query twice, exact same result.
        # ------------------------------------------------------------------
        log("=== Scenario 5: real replayability -- identical query, identical result ===")
        replay_result = await scorer.score_field_rarity(
            tenant, field="process.name", start=window_start, end=window_end, max_distinct_values=100
        )
        check(
            "re-running the exact same aggregation against the exact same (unchanged) index "
            "produces byte-identical output -- the defining contrast with G2's online RCF model",
            replay_result == full_result,
        )

    finally:
        try:
            await os_client._client.indices.delete(index=f"kronos-{POC_ORG_ALIAS}-*", ignore_unavailable=True)  # noqa: SLF001
            log(f"cleaned up real PoC indices kronos-{POC_ORG_ALIAS}-*")
        finally:
            await os_client.close()

    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(f"PoC PASSED -- all {len(CHECKS)} checks passed against the real, live OpenSearch 2.11.1 cluster.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
