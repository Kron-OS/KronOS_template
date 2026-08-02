"""Unit tests for RarityBaselineScorer (roadmap M6/G1).

Two layers tested separately, mirroring test_risk_scoring.py's own split:
1. Pure parsing/scoring logic (``_parse_aggregation_response``) against
   real, captured OpenSearch response shapes -- no I/O, no mocks needed.
2. Orchestration (``score_field_rarity``) against a fake
   ``RarityBaselineClient``, confirming tenant-scoped index pattern
   computation and correct ms-window conversion -- mirrors
   tests/unit/application/test_correlation_sync.py's own
   ``_FakeCorrelationClient`` idiom (a test-local fake subclass, not a
   shared production InMemory* double -- see this item's roadmap STATUS
   note for why no shared double was built this pass).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from src.adapter.opensearch.rarity_baseline_client import RarityBaselineClient
from src.application.rarity_scoring import RarityBaselineScorer, _parse_aggregation_response
from tests.fixtures.factories import make_tenant_context

# Real response captured against the live OpenSearch 2.11.1 cluster --
# poc/rarity_baseline_scoring/output.txt "Scenario 2" (the full skewed
# corpus: 10 common values sized 6-50, plus 20 genuinely rare
# single-occurrence values, queried with size=10 ascending).
_REAL_SKEWED_RESPONSE: dict[str, Any] = {
    "hits": {"total": {"value": 236, "relation": "eq"}},
    "aggregations": {
        "distinct_value_count": {"value": 30},
        "value_frequency": {
            "sum_other_doc_count": 216,
            "buckets": [
                {
                    "key": f"raretool_{i:02d}.exe",
                    "doc_count": 1,
                    "first_seen": {
                        "value": 1784592000000.0,
                        "value_as_string": "2026-07-20T00:00:00.000Z",
                    },
                    "last_seen": {
                        "value": 1784592000000.0,
                        "value_as_string": "2026-07-20T00:00:00.000Z",
                    },
                }
                for i in range(10)
            ],
        },
    },
}

_REAL_RESPONSE_NO_MATCHING_INDICES: dict[str, Any] = {
    "hits": {"total": {"value": 0, "relation": "eq"}},
}


class TestParseAggregationResponse:
    def test_rare_single_occurrence_values_score_higher_than_would_be_common(self) -> None:
        result = _parse_aggregation_response(
            _REAL_SKEWED_RESPONSE,
            org_alias="poc-rarity-org",
            field="process.name",
            index_pattern="kronos-poc-rarity-org-*",
            window_start=datetime(2026, 7, 1, tzinfo=UTC),
            window_end=datetime(2026, 8, 1, tzinfo=UTC),
        )
        assert result.total_docs == 236
        assert result.distinct_value_count == 30
        assert result.returned_value_count == 10
        # count=1 out of 236 total docs -> rarity 1 - 1/236 = 0.9958.
        for value in result.values:
            assert value.count == 1
            assert value.rarity_score == pytest.approx(1 - 1 / 236, abs=0.0001)
        # A hypothetical value with count=50 (the most common in the real
        # corpus this response was captured from) would score much lower --
        # confirms the formula's monotonic direction without needing that
        # bucket present in this particular (truncated, ascending) response.
        common_score = round(1 - (50 / 236), 4)
        assert all(v.rarity_score > common_score for v in result.values)

    def test_first_seen_last_seen_parsed_from_real_value_as_string(self) -> None:
        result = _parse_aggregation_response(
            _REAL_SKEWED_RESPONSE,
            org_alias="poc-rarity-org",
            field="process.name",
            index_pattern="kronos-poc-rarity-org-*",
            window_start=datetime(2026, 7, 1, tzinfo=UTC),
            window_end=datetime(2026, 8, 1, tzinfo=UTC),
        )
        first = result.values[0]
        assert first.first_seen == datetime(2026, 7, 20, tzinfo=UTC)
        assert first.last_seen == datetime(2026, 7, 20, tzinfo=UTC)
        # Single-occurrence value: first_seen == last_seen exactly -- the
        # classic "new and rare" DFIR signal.
        assert first.first_seen == first.last_seen

    def test_missing_aggregations_key_handled_honestly_as_empty_result(self) -> None:
        # Real, confirmed OpenSearch behavior: a wildcard index_pattern
        # matching zero indices omits "aggregations" entirely rather than
        # returning an empty dict (poc/rarity_baseline_scoring/output.txt
        # "Scenario 3") -- a brand-new org with no ingested data yet must
        # not crash this parser.
        result = _parse_aggregation_response(
            _REAL_RESPONSE_NO_MATCHING_INDICES,
            org_alias="brand-new-org",
            field="process.name",
            index_pattern="kronos-brand-new-org-*",
            window_start=datetime(2026, 7, 1, tzinfo=UTC),
            window_end=datetime(2026, 8, 1, tzinfo=UTC),
        )
        assert result.total_docs == 0
        assert result.distinct_value_count == 0
        assert result.returned_value_count == 0
        assert result.values == ()

    def test_returned_value_count_below_distinct_value_count_signals_truncation(self) -> None:
        result = _parse_aggregation_response(
            _REAL_SKEWED_RESPONSE,
            org_alias="poc-rarity-org",
            field="process.name",
            index_pattern="kronos-poc-rarity-org-*",
            window_start=datetime(2026, 7, 1, tzinfo=UTC),
            window_end=datetime(2026, 8, 1, tzinfo=UTC),
        )
        # cardinality (30) > returned (10): the cap was hit. Because
        # ordering is ascending, the caller can trust that only MORE common
        # values (never rarer ones) were dropped.
        assert result.returned_value_count < result.distinct_value_count

    def test_result_is_deterministic_for_identical_input(self) -> None:
        kwargs = dict(
            org_alias="poc-rarity-org",
            field="process.name",
            index_pattern="kronos-poc-rarity-org-*",
            window_start=datetime(2026, 7, 1, tzinfo=UTC),
            window_end=datetime(2026, 8, 1, tzinfo=UTC),
        )
        r1 = _parse_aggregation_response(_REAL_SKEWED_RESPONSE, **kwargs)
        r2 = _parse_aggregation_response(_REAL_SKEWED_RESPONSE, **kwargs)
        assert r1 == r2


class _FakeRarityBaselineClient(RarityBaselineClient):
    """Test-local fake -- mirrors test_correlation_sync.py's
    ``_FakeCorrelationClient`` idiom. Records the exact call arguments so
    orchestration (index pattern computation, ms conversion) can be
    asserted without a real OpenSearch dependency.
    """

    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.calls: list[tuple[str, str, int, int, int]] = []

    async def fetch_field_aggregation(
        self,
        index_pattern: str,
        field: str,
        start_ms: int,
        end_ms: int,
        *,
        max_distinct_values: int,
    ) -> dict[str, Any]:
        self.calls.append((index_pattern, field, start_ms, end_ms, max_distinct_values))
        return self._response


class TestRarityBaselineScorerOrchestration:
    @pytest.mark.asyncio
    async def test_computes_org_scoped_index_pattern_from_tenant_context_only(self) -> None:
        tenant = make_tenant_context()  # org_alias="testorg"
        client = _FakeRarityBaselineClient(_REAL_RESPONSE_NO_MATCHING_INDICES)
        scorer = RarityBaselineScorer(client)

        await scorer.score_field_rarity(
            tenant,
            field="process.name",
            start=datetime(2026, 7, 1, tzinfo=UTC),
            end=datetime(2026, 8, 1, tzinfo=UTC),
        )

        assert len(client.calls) == 1
        index_pattern, field, start_ms, end_ms, max_values = client.calls[0]
        assert index_pattern == "kronos-testorg-*"
        assert field == "process.name"
        assert start_ms == int(datetime(2026, 7, 1, tzinfo=UTC).timestamp() * 1000)
        assert end_ms == int(datetime(2026, 8, 1, tzinfo=UTC).timestamp() * 1000)
        assert max_values == 1000  # documented default cap

    @pytest.mark.asyncio
    async def test_org_alias_is_sanitized_the_same_way_as_timeline_normalization(self) -> None:
        tenant = make_tenant_context().model_copy(update={"org_alias": "Weird Org!!"})
        client = _FakeRarityBaselineClient(_REAL_RESPONSE_NO_MATCHING_INDICES)
        scorer = RarityBaselineScorer(client)

        await scorer.score_field_rarity(
            tenant,
            field="process.name",
            start=datetime(2026, 7, 1, tzinfo=UTC),
            end=datetime(2026, 8, 1, tzinfo=UTC),
        )

        index_pattern = client.calls[0][0]
        # "Weird Org!!".lower() -> "weird org!!" -> each invalid char
        # (space, "!", "!") replaced individually -> "weird-org--", then
        # the unconditional "kronos-{safe_org}-*" pattern appends its own
        # separator dash before the wildcard.
        assert index_pattern == "kronos-weird-org---*"

    @pytest.mark.asyncio
    async def test_returns_real_parsed_result_end_to_end(self) -> None:
        tenant = make_tenant_context()
        client = _FakeRarityBaselineClient(_REAL_SKEWED_RESPONSE)
        scorer = RarityBaselineScorer(client)

        result = await scorer.score_field_rarity(
            tenant,
            field="process.name",
            start=datetime(2026, 7, 1, tzinfo=UTC),
            end=datetime(2026, 8, 1, tzinfo=UTC),
            max_distinct_values=10,
        )

        assert result.org_alias == "testorg"
        assert result.total_docs == 236
        assert result.distinct_value_count == 30
        assert result.returned_value_count == 10
