"""SplunkDetectionMapper: real Splunk HEC-shaped ``DetectionEventMapper``
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R2).

Maps a real KronOS ``Detection`` into the real HEC event envelope
(``{"time", "host", "source", "sourcetype", "index", "event"}``, verified
against the official Splunk docs -- see ``splunk_hec_sink.py``'s own module
docstring and ``poc/integration_sink_splunk_hec/README.md`` for the exact
sources cited). Field-placement decisions, made explicit here rather than
left implicit:

- ``time``: ``Detection.finding_timestamp`` as a Unix epoch (HEC's own
  documented ``<sec>.<ms>`` format) -- the moment the underlying SA finding
  fired, not ``synced_at``/``updated_at`` (which are KronOS's own
  bookkeeping timestamps, not the security-relevant event time a SIEM
  operator would want to pivot on).
- ``source``/``sourcetype``: fixed, namespaced, KronOS-chosen identifiers
  (``kronos:detection_sink``/``kronos:detection``) -- HEC's own docs
  describe ``source`` as "the app you're developing" and ``sourcetype`` as
  a free-choice classifier; both are constructor-overridable so a real
  deployment can align them with its own Splunk field-extraction/props.conf
  setup without a code change.
- ``host``: defaults to ``Detection.org_alias``. Real HEC's own docs
  describe ``host`` as "typically the hostname of the client... sending
  data" -- Detection has no per-finding source-host field of its own (that
  level of detail lives in the underlying OpenSearch document, out of
  scope for this mirror), so the closest real, always-present identity
  KronOS can honestly report is *which tenant* this detection is for, not
  a fabricated machine name. Constructor-overridable for a deployment that
  wants a fixed platform-identifying host value instead.
- ``index``: omitted unless explicitly configured (``None`` default) --
  mirrors HEC's own real "optional, falls back to the token's configured
  default index" behavior (per the docs) rather than guessing one.
- ``event``: a real, nested JSON object (HEC's own docs confirm ``event``
  may hold "a string, a number, another JSON object, and so on") carrying
  every field a real SOC operator would need to triage from Splunk alone
  without pivoting back into KronOS -- mirrors ``SyncDetectionTicketAction``'s
  own real field selection (``detection_id``, ``org_id``, ``org_alias``,
  ``case_id``, ``finding_id``, ``detector_name``, ``triage_state``,
  ``attack_tags``, ``risk_score``) plus the additional fields a SIEM
  consumer specifically benefits from that a ticket description doesn't
  need verbatim (``rule_matches`` structured, not prose; ``source_index``;
  ``matched_document_ids`` for correlation back to the original OpenSearch
  documents).

Zero framework imports (CLAUDE.md SS A.3) -- pure stdlib/dataclass, no
httpx/socket here (that's ``splunk_hec_sink.py``'s job).
"""

from __future__ import annotations

from typing import Any

from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent
from src.domain.detection import Detection

_DEFAULT_SOURCE = "kronos:detection_sink"
_DEFAULT_SOURCETYPE = "kronos:detection"


class SplunkDetectionMapper(DetectionEventMapper):
    """Maps one ``Detection`` into one real Splunk HEC event envelope."""

    def __init__(
        self,
        *,
        source: str = _DEFAULT_SOURCE,
        sourcetype: str = _DEFAULT_SOURCETYPE,
        index: str | None = None,
        host: str | None = None,
    ) -> None:
        self._source = source
        self._sourcetype = sourcetype
        self._index = index
        self._host = host

    def map(self, detection: Detection) -> MappedSinkEvent:
        event_body: dict[str, Any] = {
            "detection_id": str(detection.detection_id),
            "finding_id": detection.finding_id,
            "detector_name": detection.detector_name,
            "source_index": detection.source_index,
            "org_id": str(detection.org_id),
            "org_alias": detection.org_alias,
            "case_id": str(detection.case_id) if detection.case_id else None,
            "rule_matches": [
                {"rule_id": match.rule_id, "rule_name": match.rule_name, "tags": list(match.tags)}
                for match in detection.rule_matches
            ],
            "attack_tags": list(detection.attack_tags),
            "rule_severity": detection.rule_severity,
            "risk_score": detection.risk_score,
            "triage_state": detection.triage_state.value,
            "matched_document_ids": list(detection.matched_document_ids),
            "external_ticket_id": detection.external_ticket_id,
            "synced_at": detection.synced_at.isoformat(),
            "updated_at": detection.updated_at.isoformat(),
        }

        envelope: dict[str, Any] = {
            "time": detection.finding_timestamp.timestamp(),
            "host": self._host if self._host is not None else detection.org_alias,
            "source": self._source,
            "sourcetype": self._sourcetype,
            "event": event_body,
        }
        if self._index is not None:
            envelope["index"] = self._index

        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            payload=envelope,
            mapper_metadata={
                "source": self._source,
                "sourcetype": self._sourcetype,
                "index": self._index,
            },
        )
