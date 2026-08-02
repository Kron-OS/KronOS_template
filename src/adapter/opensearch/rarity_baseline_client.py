"""Read-only client for real OpenSearch rarity/frequency aggregations
(roadmap M6/G1).

Mirrors ``CorrelationClient``/``FindingsClient``
(``src/adapter/opensearch/correlation_client.py``,
``src/adapter/opensearch/findings_client.py``) exactly: an ABC returning a
raw response dict, a concrete ``httpx``-based implementation authenticated
with the backend's own admin credentials, read-only by construction (a
plain ``_search`` with ``size: 0`` -- no write endpoint is ever touched).
Tenant isolation is enforced the SAME way ``OpenSearchClient``'s own callers
enforce it for ordinary timeline indices (``evidence_intake.py``'s
``pattern = f"kronos-{safe_org}-case-{...}-*"``): the caller
(``RarityBaselineScorer``, ``src/application/rarity_scoring.py``) computes
``kronos-{org_alias}-*`` from the authenticated ``TenantContext`` and passes
it in -- this class trusts whatever index pattern string it is given and
performs no scoping of its own, so it must never be called with anything
but a caller-computed, org-scoped pattern.

Real, confirmed query/response shape (``poc/rarity_baseline_scoring/``,
live OpenSearch 2.11.1 cluster, ``docker-opensearch-1``)::

    POST /{index_pattern}/_search
    {
      "size": 0, "track_total_hits": true,
      "query": {"range": {"@timestamp": {"gte": <ms>, "lt": <ms>, "format": "epoch_millis"}}},
      "aggs": {
        "distinct_value_count": {"cardinality": {"field": "<field>"}},
        "value_frequency": {
          "terms": {"field": "<field>", "size": <max_distinct_values>, "order": {"_count": "asc"}},
          "aggs": {
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen":  {"max": {"field": "@timestamp"}}
          }
        }
      }
    }
    -> {"hits": {"total": {"value": N, "relation": "eq"}},
        "aggregations": {
          "distinct_value_count": {"value": D},
          "value_frequency": {
            "sum_other_doc_count": X,
            "buckets": [
              {"key": "<value>", "doc_count": C,
               "first_seen": {"value": <epoch_ms float>, "value_as_string": "<iso>"},
               "last_seen":  {"value": <epoch_ms float>, "value_as_string": "<iso>"}},
              ...
            ]
          }
        }}

**Real, load-bearing gap found and confirmed for real (not assumed):** when
the wildcard ``index_pattern`` matches ZERO real indices (e.g. a brand new
org with no ingested data yet), OpenSearch returns HTTP 200 with
``hits.total.value == 0`` and the ``"aggregations"`` KEY IS ABSENT ENTIRELY
from the response body -- it is not present as an empty dict, and there is
no 404 the way a concrete (non-wildcard) missing index produces for
``FindingsClient``. ``RarityBaselineScorer`` (the caller) must therefore
never assume ``response["aggregations"]`` exists; this class returns
whatever OpenSearch actually sent, unmodified, so that gap is real and
visible at the parsing layer rather than papered over here.

**Real, load-bearing ordering gap confirmed for real:** OpenSearch's terms
aggregation defaults to ordering buckets by ``_count`` DESCENDING (most
common first). For "least-frequency-of-occurrence" hunting this is exactly
backwards -- verified live: a 236-document, 30-distinct-value corpus with
``size: 10`` and the default order returned only the 10 MOST common values
(zero of the 20 genuinely rare, single-occurrence ones); the SAME query
with ``order: {"_count": "asc"}`` returned all 10 available slots' worth of
the actual rare tail. This class always requests ascending order --
getting this wrong would silently make the whole feature find nothing rare
whenever cardinality exceeds ``max_distinct_values``, with no error anywhere.

**Known, documented limitation carried from OpenSearch's own semantics**
(not a KronOS bug): ascending ``_count`` ordering on a terms aggregation is
more expensive to compute exactly across MULTIPLE shards than the default
descending order (each shard must consider more candidate terms before
merging). The pinned ``kronos-*`` index template
(``src/adapter/opensearch/index_template.json``) sets
``number_of_shards: 1``, so this is exact today; a future move to multiple
shards per index would need this re-verified (e.g. via ``shard_size``
tuning), not assumed to still be exact.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class RarityBaselineClient(ABC):
    """Read-only access to real terms/cardinality/first-last-seen aggregations."""

    @abstractmethod
    async def fetch_field_aggregation(
        self,
        index_pattern: str,
        field: str,
        start_ms: int,
        end_ms: int,
        *,
        max_distinct_values: int,
    ) -> dict[str, Any]:
        """Return the RAW OpenSearch aggregation response for *field* over
        [start_ms, end_ms) within *index_pattern*.

        *index_pattern* MUST already be org-scoped by the caller (e.g.
        ``kronos-{org_alias}-*``) -- this method performs no tenant scoping
        of its own (see module docstring). The response may lack an
        ``"aggregations"`` key entirely when *index_pattern* matches zero
        real indices; callers must handle that, not assume it is present.
        """


class OpenSearchRarityBaselineClient(RarityBaselineClient):
    """Real OpenSearch 2.11.1 terms/cardinality/first-last-seen aggregation reader."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def fetch_field_aggregation(
        self,
        index_pattern: str,
        field: str,
        start_ms: int,
        end_ms: int,
        *,
        max_distinct_values: int,
    ) -> dict[str, Any]:
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "range": {"@timestamp": {"gte": start_ms, "lt": end_ms, "format": "epoch_millis"}}
            },
            "aggs": {
                "distinct_value_count": {"cardinality": {"field": field}},
                "value_frequency": {
                    # Ascending order is the entire point -- see module
                    # docstring's "real, load-bearing ordering gap".
                    "terms": {
                        "field": field,
                        "size": max_distinct_values,
                        "order": {"_count": "asc"},
                    },
                    "aggs": {
                        "first_seen": {"min": {"field": "@timestamp"}},
                        "last_seen": {"max": {"field": "@timestamp"}},
                    },
                },
            },
        }
        # verify=False: same self-signed internal step-ca cert as every
        # other admin-credentialed SA/OpenSearch adapter in this repo
        # (settings.opensearch_url is https://opensearch:9200 even
        # docker-internally).
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            resp = await client.post(
                f"{self._base_url}/{index_pattern}/_search",
                auth=self._auth,
                json=body,
            )
            resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        logger.info(
            "rarity_aggregation_fetched",
            extra={
                "index_pattern": index_pattern,
                "field": field,
                "total_docs": result.get("hits", {}).get("total", {}).get("value"),
            },
        )
        return result
