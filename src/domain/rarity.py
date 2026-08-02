"""Rarity/frequency baseline domain model (roadmap M6/G1).

**Deliberately the opposite of G2 (next roadmap item).** G1 is classic DFIR
least-frequency-of-occurrence: a value's rarity is derived entirely from
plain, deterministic OpenSearch aggregations (``terms``, ``cardinality``,
``min``/``max`` on ``@timestamp``) over an unchanged index. Re-running the
exact same query against the exact same data always produces the exact same
:class:`RarityBaselineResult` -- there is no hidden state, no online model,
nothing that depends on ingestion history beyond the documents themselves.
G2 will wrap OpenSearch's Anomaly Detection/RCF plugin, which is an *online*
model that continuously updates its own state as new data arrives -- a score
from that plugin is NOT reproducible months later from the same stored
input, and must never be presented as evidentiary. G1 exists specifically to
give G2 (and any future ML) a labelled, fully-replayable baseline to be
measured against -- see docs/NEXTGEN_SOC_ROADMAP.md M6.

Mirrors ``src/domain/risk.py``'s ``RiskFactor``/``RiskScoreBreakdown`` shape:
frozen Pydantic models, zero framework imports (CLAUDE.md SS A.3), computed
by a pure application-layer class from an already-fetched OpenSearch
response (``src/application/rarity_scoring.py::RarityBaselineScorer``).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class FieldValueRarity(BaseModel):
    """One distinct field value's frequency, first/last-seen window, and rarity score.

    ``rarity_score`` is ``1 - (count / total_docs)`` (see
    ``RarityBaselineScorer`` module docstring for why this exact formula was
    chosen over a percentile-rank alternative) -- bounded ``[0, 1]``, higher
    means rarer. A value seen only once, with ``first_seen == last_seen``,
    is exactly the classic "new and rare" DFIR hunting signal.
    """

    model_config = {"frozen": True}

    value: str
    count: int = Field(ge=0)
    first_seen: datetime
    last_seen: datetime
    rarity_score: float = Field(ge=0.0, le=1.0)


class RarityBaselineResult(BaseModel):
    """The full, reproducible output of one field's rarity baseline query.

    ``distinct_value_count`` is the real ``cardinality`` aggregation result
    (the denominator context for rarity, and independent of how many
    per-value buckets were actually returned). ``returned_value_count`` is
    ``len(values)`` -- the number of distinct values this result actually
    carries a :class:`FieldValueRarity` for, which is capped by the query's
    ``max_distinct_values`` parameter (mirrors
    ``FindingsClient``'s own documented ``_MAX_RESULTS`` cap). ``values`` is
    ordered rarest-first (ascending ``count``) -- see
    ``RarityBaselineScorer`` for why terms-aggregation ordering direction is
    the single most important, most easily-gotten-wrong design decision in
    this whole feature: the OpenSearch/Elasticsearch default (descending by
    count) silently returns only the MOST common values and would make a
    "least-frequency-of-occurrence" query find nothing rare at all if the
    true cardinality exceeds ``max_distinct_values``.

    A value is only absent from ``values`` when ``returned_value_count <
    distinct_value_count`` (the cap was hit) -- and because ordering is
    ascending, any value dropped this way is honestly one of the MORE common
    ones, never a rare one, as long as ``max_distinct_values >=
    distinct_value_count`` was not itself violated by an unusually large
    single environment (a real, documented v1 limitation, same class of gap
    as ``FindingsClient``'s own un-paginated ``_MAX_RESULTS``).
    """

    model_config = {"frozen": True}

    org_alias: str
    field: str
    index_pattern: str
    window_start: datetime
    window_end: datetime
    total_docs: int = Field(ge=0)
    distinct_value_count: int = Field(ge=0)
    returned_value_count: int = Field(ge=0)
    values: tuple[FieldValueRarity, ...] = Field(default_factory=tuple)
