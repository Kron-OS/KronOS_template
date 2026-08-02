"""Read-only client for real OpenSearch Anomaly Detection (AD/RCF) results
(roadmap M6/G2).

Mirrors ``RarityBaselineClient``/``CorrelationClient``/``FindingsClient``
exactly: an ABC returning a raw response dict, a concrete ``httpx``-based
implementation authenticated with the backend's own admin credentials,
read-only by construction. Parsing into domain objects happens one layer
up (``src/application/anomaly_scoring.py::BehavioralAnomalyScorer``), not
here -- this class's only job is the real HTTP call.

**Real, load-bearing gap confirmed against the live 2.11.1 cluster
(``poc/anomaly_detection_baseline/README.md`` "Finding 2"), not assumed:**
the raw results index (``.opendistro-anomaly-results*``) is a
security-plugin-PROTECTED system index -- a direct ``_search``/``_count``
against it, even as the ``admin`` superuser, silently returns real HTTP 200
with zero hits, even when ``_cat/indices``/``_stats`` on the identical
concrete index report thousands of real, physically-present documents.
This class therefore NEVER queries that index directly; it always uses
the AD plugin's own dedicated, privileged read path,
``POST /_plugins/_anomaly_detection/detectors/results/_search``
(confirmed real and working live -- returned the actual results this
PoC's own historical-analysis runs produced), which internally targets the
protected index as a plugin-owned action rather than an ordinary user
search request (confirmed from source,
``RestSearchAnomalyResultAction.java``).

Real, confirmed result-document shape
(``poc/anomaly_detection_baseline/output.txt``)::

    POST /_plugins/_anomaly_detection/detectors/results/_search
    {"size": <n>, "query": {"bool": {"filter": [...]}}, "sort": [...]}
    -> {"hits": {"hits": [
         {"_source": {
           "detector_id": "...", "task_id": "..." | absent,
           "anomaly_grade": <float [0,1]>, "confidence": <float [0,1]>,
           "feature_data": [{"feature_id": "...", "feature_name": "...", "data": <float>}],
           "expected_values": [{"likelihood": <float>,
                                 "value_list": [{"feature_id": "...", "data": <float>}]}],
           "entity": [{"name": "...", "value": "..."}],
           "data_start_time": <epoch_ms>, "data_end_time": <epoch_ms>
         }}, ...]}}
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class AnomalyDetectionResultsClient(ABC):
    """Read-only access to real AD/RCF anomaly results for one detector."""

    @abstractmethod
    async def search_results(
        self,
        *,
        detector_id: str,
        min_grade: float = 0.0,
        size: int = 1000,
    ) -> dict[str, Any]:
        """Return the RAW OpenSearch AD results-search response for
        *detector_id*, filtered to ``anomaly_grade > min_grade`` and sorted
        by ``anomaly_grade`` descending (most anomalous first -- the
        natural order for a triage-prioritization consumer).

        Uses the plugin's own dedicated results-search endpoint, never a
        raw query against the protected results index (see module
        docstring). *detector_id* scopes this to one org's own detector
        (``AnomalyDetectorProvisioner.detector_name``/``ensure_org_detector``
        establish that per-org scoping one layer up); this method performs
        no tenant scoping of its own.
        """


class OpenSearchAnomalyDetectionResultsClient(AnomalyDetectionResultsClient):
    """Real OpenSearch 2.11.1 Anomaly Detection results reader."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def search_results(
        self,
        *,
        detector_id: str,
        min_grade: float = 0.0,
        size: int = 1000,
    ) -> dict[str, Any]:
        body = {
            "size": size,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"detector_id": detector_id}},
                        {"range": {"anomaly_grade": {"gt": min_grade}}},
                    ]
                }
            },
            "sort": [{"anomaly_grade": "desc"}, {"data_end_time": "desc"}],
        }
        # verify=False: same self-signed internal step-ca cert as every
        # other admin-credentialed SA/OpenSearch adapter in this repo.
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            resp = await client.post(
                f"{self._base_url}/_plugins/_anomaly_detection/detectors/results/_search",
                auth=self._auth,
                json=body,
            )
            resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        logger.info(
            "anomaly_results_fetched",
            extra={
                "detector_id": detector_id,
                "min_grade": min_grade,
                "hit_count": result.get("hits", {}).get("total", {}).get("value"),
            },
        )
        return result
