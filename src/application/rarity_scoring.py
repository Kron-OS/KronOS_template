"""RarityBaselineScorer: deterministic, fully-replayable frequency/rarity
baseline (roadmap M6/G1).

**Objective (roadmap):** "Classic DFIR least-frequency-of-occurrence via
plain OpenSearch aggregations (terms, cardinality, first-seen/last-seen on
@timestamp). No ML. Fully replayable. Ship before any ML -- it delivers most
of the value attributed to UEBA and gives a labelled baseline to measure
models against."

**Standalone by design -- NOT wired into ``DetectionRiskScorer``/
``Detection``.** Unlike F1-F4 (each of which extended an existing mechanism:
``Enricher``, ``Detection``), G1 has no existing hunting/aggregation module
to extend -- this is deliberately a fresh, read-only analytics capability
that a future hunting UI or scheduled job can call directly. G2 (next
roadmap item, OpenSearch AD/RCF anomaly detection) will be BENCHMARKED
against this class's output, not the other way around -- wiring G1 into F4's
already-shipped, already-verified risk-scoring formula would be scope creep
into that item's territory, not this one's.

**Why the rarity formula is ``1 - (count / total_docs)``, not a
percentile-rank among returned buckets.** A percentile-rank score (e.g.
"this value's count is the Nth-lowest among the K values returned") would
depend on ``max_distinct_values`` -- the size cap on how many terms-agg
buckets were actually fetched (see
``RarityBaselineClient``/``OpenSearchRarityBaselineClient``'s own module
docstring for the real, confirmed ordering/truncation behavior). Two
otherwise-identical queries that only differ in that cap could then produce
different scores for the exact same value, which fails the roadmap's own
"fully replayable" requirement for this item -- the whole reason G1 exists is
to be the opposite of G2's non-reproducible online model.
``1 - (count / total_docs)`` depends on nothing but that one value's own
real count and the query's real total document count, both independent of
how many buckets were requested or returned -- reproducible from the stored
inputs alone, exactly like ``DetectionRiskScorer``'s own hardcoded-formula
precedent (``src/application/risk_scoring.py``).

**Why this class still returns/exposes ``distinct_value_count``
(cardinality) even though it does not enter the score.** It is the honest
denominator context for a human reading the result (a value with
count=1 out of a cardinality of 3 is far less surprising than count=1 out
of a cardinality of 50,000), and it is what a caller should compare against
``returned_value_count`` to know whether the cap on this particular query
was actually hit (``src/domain/rarity.py``'s own docstring covers this).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from src.adapter.opensearch.rarity_baseline_client import RarityBaselineClient
from src.domain.rarity import FieldValueRarity, RarityBaselineResult
from src.domain.user import TenantContext

# Real algorithmic cap, not a per-deployment Settings field -- mirrors
# FindingsClient's own undocumented-as-configurable `_MAX_RESULTS = 1000`
# precedent (src/adapter/opensearch/findings_client.py): a real limit on
# this v1's single, un-paginated aggregation call, not an ops-editable knob
# that would change what "the same query" means across environments.
_DEFAULT_MAX_DISTINCT_VALUES = 1000


class RarityBaselineScorer:
    """Computes a fully-replayable rarity baseline for one ECS field within
    one org's own indices over one time window.

    Orchestrates (does not itself perform I/O beyond delegating to the
    injected ``RarityBaselineClient``): compute the org-scoped index
    pattern from the caller's own ``TenantContext`` (never from any
    caller-supplied string -- roadmap invariant #3), fetch the real
    aggregation response, then parse+score it via pure, testable logic.
    """

    def __init__(self, client: RarityBaselineClient) -> None:
        self._client = client

    async def score_field_rarity(
        self,
        tenant: TenantContext,
        *,
        field: str,
        start: datetime,
        end: datetime,
        max_distinct_values: int = _DEFAULT_MAX_DISTINCT_VALUES,
    ) -> RarityBaselineResult:
        """Return the real, reproducible rarity baseline for *field*.

        Args:
            tenant: authenticated caller context; ``org_alias`` is the ONLY
                source for the index pattern (never a parameter that could
                smuggle in another org's data).
            field: a real ECS keyword-typed field path (e.g.
                ``"process.name"``, ``"user.name"``, ``"source.ip"`` --
                caller's responsibility to pass a field that is actually
                mapped as ``keyword``/``ip`` in
                ``index_template.json``; an unmapped/non-aggregatable field
                will surface as a real OpenSearch error, not a silent
                empty result).
            start: inclusive window start.
            end: exclusive window end.
            max_distinct_values: cap on how many (rarest-first) distinct
                values are returned; see this module's docstring for why
                this cap does NOT affect any individual value's score.
        """
        safe_org = _safe_org_alias(tenant.org_alias)
        index_pattern = f"kronos-{safe_org}-*"
        start_ms = int(start.astimezone(UTC).timestamp() * 1000)
        end_ms = int(end.astimezone(UTC).timestamp() * 1000)

        raw = await self._client.fetch_field_aggregation(
            index_pattern,
            field,
            start_ms,
            end_ms,
            max_distinct_values=max_distinct_values,
        )
        return _parse_aggregation_response(
            raw,
            org_alias=tenant.org_alias,
            field=field,
            index_pattern=index_pattern,
            window_start=start,
            window_end=end,
        )


def _safe_org_alias(org_alias: str) -> str:
    """Same sanitization as ``timeline_normalization.build_index_name`` /
    ``evidence_intake.py``'s own inline copy -- duplicated here rather than
    newly shared, consistent with this codebase's existing precedent of
    three independent inline copies of this exact one-liner rather than a
    premature shared utility.
    """
    return re.sub(r"[^a-z0-9-]", "-", org_alias.lower())


def _parse_aggregation_response(
    raw: dict[str, Any],
    *,
    org_alias: str,
    field: str,
    index_pattern: str,
    window_start: datetime,
    window_end: datetime,
) -> RarityBaselineResult:
    """Pure parsing + scoring of an already-fetched raw OpenSearch response.

    No I/O -- testable without OpenSearch (see
    tests/unit/application/test_rarity_scoring.py). Handles the real,
    confirmed gap that ``"aggregations"`` is entirely ABSENT from the
    response when the wildcard index pattern matches zero real indices
    (``poc/rarity_baseline_scoring/`` -- a brand new org with no ingested
    data yet), never assuming the key exists.
    """
    total_docs = raw.get("hits", {}).get("total", {}).get("value", 0)
    aggs = raw.get("aggregations", {})
    distinct_value_count = aggs.get("distinct_value_count", {}).get("value", 0)
    buckets = aggs.get("value_frequency", {}).get("buckets", [])

    values: list[FieldValueRarity] = []
    for bucket in buckets:
        count = bucket["doc_count"]
        rarity_score = round(1 - (count / total_docs), 4) if total_docs > 0 else 0.0
        values.append(
            FieldValueRarity(
                value=bucket["key"],
                count=count,
                # value_as_string is the real ISO-8601 OpenSearch already
                # rendered (poc/rarity_baseline_scoring/output.txt) --
                # simpler and less error-prone than re-deriving a datetime
                # from the parallel epoch-millis "value" field ourselves.
                first_seen=datetime.fromisoformat(
                    bucket["first_seen"]["value_as_string"].replace("Z", "+00:00")
                ),
                last_seen=datetime.fromisoformat(
                    bucket["last_seen"]["value_as_string"].replace("Z", "+00:00")
                ),
                rarity_score=rarity_score,
            )
        )

    return RarityBaselineResult(
        org_alias=org_alias,
        field=field,
        index_pattern=index_pattern,
        window_start=window_start,
        window_end=window_end,
        total_docs=total_docs,
        distinct_value_count=distinct_value_count,
        returned_value_count=len(values),
        values=tuple(values),
    )
