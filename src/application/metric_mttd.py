"""MeanTimeToDetectCalculator: real detection latency from KronOS's own
Detection rows + their matched OpenSearch documents (roadmap M8/I2).

**A real, load-bearing caveat found while building this (read before
trusting this metric's numbers against this repo's existing historical
PoC data):** roadmap C5 (``poc/chain_detect_from_evidence/README.md``,
"Finding #1") already discovered that OpenSearch Security Analytics
monitors filter candidate documents by their own ``@timestamp`` field
against a *recent wall-clock* execution window, not by when the document
was physically indexed -- so a monitor structurally can never fire against
genuinely historical forensic evidence (real EVTX/PCAP timestamps are
always in the past, often years). Several of this repo's own existing
PoC passes (verified directly against the live cluster while building this
calculator: a real matched document under a ``*-201508`` index --
i.e. a real August-2015 event month -- was found at ``_version: 2`` with
its own ``@timestamp`` overwritten to the PoC's *run date*) worked around
this by re-indexing a handful of documents with a fresh ``@timestamp`` just
to get SA to fire at all for demonstration purposes.

This calculator computes exactly what the roadmap's own I2 text specifies
(``Detection.synced_at`` -- the moment KronOS's own audited Detection row
was created, the honest proxy for "created_at" since no separate field
exists -- minus the earliest matched document's own real ``@timestamp``),
against whatever ``@timestamp`` each document actually carries right now.
It does NOT attempt to detect or exclude timestamp-bumped documents --
doing so would require guessing at an undocumented threshold with no
principled cutoff. Instead it reports ``min``/``max``/``median`` alongside
the mean in ``detail`` specifically so a bimodal distribution (some deltas
near an SA schedule interval from a bumped doc, others genuinely multi-year
from an untouched one) is visible rather than smoothed away by one average
-- see this module's own README in ``poc/metrics_kpis/`` for the real,
captured numbers this produced against the live dev cluster.
"""

from __future__ import annotations

import logging
import statistics
from datetime import datetime
from typing import Any

from src.adapter.opensearch.client import AbstractTimelineIndex
from src.adapter.repository.detection import DetectionRepository
from src.application.metric_calculator import MetricCalculator
from src.domain.metrics import MetricResult
from src.domain.user import TenantContext

logger = logging.getLogger(__name__)


class MeanTimeToDetectCalculator(MetricCalculator):
    """MTTD, in seconds, from real Detection + real matched-document data."""

    def __init__(
        self, detection_repository: DetectionRepository, timeline_index: AbstractTimelineIndex
    ) -> None:
        self._detections = detection_repository
        self._timeline_index = timeline_index

    @property
    def metric_name(self) -> str:
        return "mttd_seconds"

    async def compute(self, tenant: TenantContext) -> MetricResult:
        # Group matched_document_ids by their own source_index so document
        # lookups can be batched per index (mirrors
        # DetectionSyncService._resolve_risk_inputs's own per-finding
        # lookup, generalized to a per-org batch here since MTTD needs
        # every synced Detection, not just one being scored at sync time).
        ids_by_index: dict[str, set[str]] = {}
        detection_refs: list[tuple[str, tuple[str, ...], datetime]] = []
        detection_count = 0
        async for detection in self._detections.stream_by_org(tenant.org_id):
            detection_count += 1
            if not detection.matched_document_ids:
                continue
            ids_by_index.setdefault(detection.source_index, set()).update(
                detection.matched_document_ids
            )
            detection_refs.append(
                (detection.source_index, detection.matched_document_ids, detection.synced_at)
            )

        if not detection_refs:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="seconds",
                sample_size=0,
                detail={"total_detections": detection_count},
                unavailable_reason=(
                    "No synced Detection rows with matched_document_ids exist for this "
                    "org yet -- MTTD needs at least one real finding linked to a real "
                    "indexed document."
                ),
            )

        docs_by_index: dict[str, dict[str, dict[str, Any]]] = {}
        for source_index, index_doc_ids in ids_by_index.items():
            try:
                docs_by_index[source_index] = await self._timeline_index.get_documents_by_id(
                    source_index, list(index_doc_ids)
                )
            except Exception as exc:  # noqa: BLE001 -- one bad index must not sink the whole metric
                logger.warning(
                    "mttd_document_lookup_failed",
                    extra={"source_index": source_index, "error": str(exc)},
                )
                docs_by_index[source_index] = {}

        deltas_seconds: list[float] = []
        skipped_missing_doc = 0
        skipped_missing_timestamp = 0
        skipped_negative = 0
        for source_index, matched_doc_ids, synced_at in detection_refs:
            docs = docs_by_index.get(source_index, {})
            event_times: list[datetime] = []
            for doc_id in matched_doc_ids:
                doc = docs.get(doc_id)
                if doc is None:
                    skipped_missing_doc += 1
                    continue
                raw_ts = doc.get("@timestamp")
                if not raw_ts:
                    skipped_missing_timestamp += 1
                    continue
                try:
                    event_times.append(_parse_timestamp(raw_ts))
                except ValueError:
                    skipped_missing_timestamp += 1
            if not event_times:
                continue
            delta = (synced_at - min(event_times)).total_seconds()
            if delta < 0:
                # A document whose @timestamp is AFTER this Detection was
                # synced is possible if that same document was re-indexed
                # with a fresher timestamp after the original SA finding
                # fired -- a real, observed data artifact (see module
                # docstring), not a bug in this calculator. Excluded rather
                # than reported as a fabricated negative latency.
                skipped_negative += 1
                continue
            deltas_seconds.append(delta)

        if not deltas_seconds:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="seconds",
                sample_size=0,
                detail={
                    "total_detections": detection_count,
                    "detections_with_matched_docs": len(detection_refs),
                    "skipped_missing_doc": skipped_missing_doc,
                    "skipped_missing_timestamp": skipped_missing_timestamp,
                    "skipped_negative_delta": skipped_negative,
                },
                unavailable_reason=(
                    "Every candidate Detection's matched document(s) were missing, "
                    "missing @timestamp, or had a negative delta -- no valid MTTD "
                    "sample could be computed for this org."
                ),
            )

        return MetricResult(
            metric_name=self.metric_name,
            org_id=tenant.org_id,
            value=statistics.mean(deltas_seconds),
            unit="seconds",
            sample_size=len(deltas_seconds),
            detail={
                "total_detections": detection_count,
                "detections_with_matched_docs": len(detection_refs),
                "min_seconds": min(deltas_seconds),
                "max_seconds": max(deltas_seconds),
                "median_seconds": statistics.median(deltas_seconds),
                "skipped_missing_doc": skipped_missing_doc,
                "skipped_missing_timestamp": skipped_missing_timestamp,
                "skipped_negative_delta": skipped_negative,
            },
        )


def _parse_timestamp(raw: str) -> datetime:
    """Parse a real ECS ``@timestamp`` string (ISO-8601, ``Z`` or explicit
    offset -- both observed for real against the live cluster while
    building this) into an aware ``datetime``."""
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))
