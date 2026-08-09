"""SentinelDetectionMapper: real Microsoft Sentinel Logs Ingestion API-shaped
``DetectionEventMapper`` (KAFKA_AND_INTEGRATIONS_ROADMAP.md R4 -- "Microsoft
Sentinel sink connector").

**The "hard part" this module exists to solve (the R4 brief's own framing).**
Splunk HEC's ``event`` object (``splunk_detection_mapper.py``) and CEF's
extension zone (``cef_detection_mapper.py``) are both genuinely free-form --
either target accepts whatever key/value shape a mapper hands it. Microsoft
Sentinel's real Logs Ingestion API is the opposite: a POST body must match
the **rigid, pre-provisioned column set** declared in a Data Collection
Rule's (DCR) ``streamDeclaration`` -- verified directly from Microsoft's own
current docs (fetched and read this pass, not assumed from memory):

- ``learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview``
  -- "The stream contains a full list of **top-level properties that are
  contained in the JSON data you send**." I.e. every top-level key the
  request body carries must be a column the DCR's ``streamDeclaration``
  actually declares -- there is no free-form passthrough field a mapper can
  fall back on for "whatever didn't fit," unlike HEC's ``event`` object.
- ``learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-structure``
  -- stream-declaration columns are typed from a real, closed set:
  ``string``, ``int``, ``long``, ``real``, ``boolean``, ``dynamic``,
  ``datetime`` (``guid`` is explicitly NOT available at this layer -- GUIDs
  must be declared ``string``, which is why every id field below is
  ``string``, never a hypothetical ``guid`` column type).

**The "extra fields" case IS real and IS solved by Sentinel's own schema,
verified rather than assumed (the R4 brief's own explicit instruction).**
``dynamic`` is a real, first-class column type in that same closed type
list above -- Azure Monitor Logs' own docs describe it as holding
arbitrary JSON (object or array), queryable via KQL's own
``bag_keys()``/``mv-expand``. This mapper uses THAT real mechanism, not an
invented one: every ``Detection`` field that is itself a real, structured,
variable-shape collection (``rule_matches``, ``attack_tags``,
``matched_document_ids``) gets its own ``dynamic`` column, and every
secondary/traceability field that doesn't earn a first-class typed column
of its own (``external_ticket_id``, ``synced_at``, ``updated_at``) is
bucketed into one ``dynamic`` catch-all column, ``ExtendedProperties`` --
**never silently dropped**. This mapper is the ONLY place that decision is
made; a future field addition to ``Detection`` either earns its own typed
column (a real DCR schema change, i.e. redeploying the DCR) or is added to
the ``ExtendedProperties`` bag (zero DCR change), and this module's own
``_build_record`` is where that choice is visible and auditable.

**The rigid custom-table schema this PoC pre-provisions (this pass's own
design, documented here since no pre-existing customer DCR exists to
mirror -- see ``sentinel_sink.py``'s own module docstring and
``poc/integration_sink_sentinel/README.md`` for the exact DCR/DCE JSON this
schema corresponds to).** Table ``KronOSDetection_CL`` (custom tables MUST
carry the real, documented ``_CL`` suffix per the overview doc above),
stream ``Custom-KronOSDetection``, 14 columns:

| Column | Type | Source | Nullable |
|---|---|---|---|
| ``TimeGenerated`` | datetime | ``finding_timestamp`` | no |
| ``DetectionId`` | string | ``detection_id`` | no |
| ``FindingId`` | string | ``finding_id`` | no |
| ``DetectorName`` | string | ``detector_name`` | no |
| ``OrgId`` | string | ``org_id`` | no |
| ``OrgAlias`` | string | ``org_alias`` | no |
| ``CaseId`` | string | ``case_id`` | yes |
| ``SourceIndex`` | string | ``source_index`` | no |
| ``TriageState`` | string | ``triage_state.value`` | no |
| ``RuleSeverity`` | string | ``rule_severity`` | yes |
| ``RiskScore`` | real | ``risk_score`` | yes |
| ``AttackTags`` | dynamic | ``attack_tags`` array | no |
| ``RuleMatches`` | dynamic | ``rule_matches`` array of ``{rule_id, rule_name, tags}`` | no |
| ``MatchedDocumentIds`` | dynamic | ``matched_document_ids`` array | no |
| ``ExtendedProperties`` | dynamic | ticket/sync/update catch-all (below) | no |

The three ``Nullable`` columns are honest absences, never fabricated
defaults: ``CaseId`` is null for stream-scoped Detections that carry no
case (roadmap B2); ``RuleSeverity`` is null when no matched rule carried a
recognized Sigma severity tag (``highest_rule_severity``'s own contract);
``RiskScore`` is null in the degenerate case where no risk factor had a
usable value (roadmap F4's own "never substitute a fabricated neutral
value" rule, ``Detection.risk_score``'s own docstring).

Every real record this mapper produces carries EXACTLY these 14 keys, every
time -- no key is ever conditionally omitted (nullable columns still appear
with a JSON ``null``) -- because the real DCR contract requires the request
body's top-level property set to match the declared stream shape on every
single record, not just "eventually, across the whole batch."

Zero framework imports (CLAUDE.md SS A.3) -- pure stdlib/dataclass, no
httpx/socket here (that's ``sentinel_sink.py``'s job).
"""

from __future__ import annotations

from typing import Any

from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent
from src.domain.detection import Detection

# Real, chosen custom-table identifiers this mapper's record shape is
# provisioned against (see this module's own docstring table +
# poc/integration_sink_sentinel/README.md for the DCR JSON that declares
# them) -- constructor-overridable only in the sense that a caller could
# point a differently-provisioned DCR at the same record shape; the COLUMN
# SET itself (_build_record below) is what actually has to match the real
# DCR, not these display-only labels.
DEFAULT_TABLE_NAME = "KronOSDetection_CL"
DEFAULT_STREAM_NAME = "Custom-KronOSDetection"


class SentinelDetectionMapper(DetectionEventMapper):
    """Maps one ``Detection`` into one record matching the rigid
    ``KronOSDetection_CL`` custom-table column schema (this module's own
    docstring table)."""

    def map(self, detection: Detection) -> MappedSinkEvent:
        record = self._build_record(detection)
        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            payload=record,
            mapper_metadata={
                "table_name": DEFAULT_TABLE_NAME,
                "stream_name": DEFAULT_STREAM_NAME,
            },
        )

    @staticmethod
    def _build_record(detection: Detection) -> dict[str, Any]:
        rule_matches = [
            {"rule_id": match.rule_id, "rule_name": match.rule_name, "tags": list(match.tags)}
            for match in detection.rule_matches
        ]
        extended_properties: dict[str, Any] = {
            "external_ticket_id": detection.external_ticket_id,
            "synced_at": detection.synced_at.isoformat(),
            "updated_at": detection.updated_at.isoformat(),
        }
        return {
            # Azure Monitor's own real datetime wire format is an ISO 8601
            # string (the overview doc's own worked example: "2023-11-14
            # 15:10:02") -- isoformat() with a real timezone-aware
            # datetime (Detection.finding_timestamp is always UTC-aware,
            # src/domain/detection.py) produces an unambiguous, real ISO
            # 8601 string, never a naive/local one.
            "TimeGenerated": detection.finding_timestamp.isoformat(),
            "DetectionId": str(detection.detection_id),
            "FindingId": detection.finding_id,
            "DetectorName": detection.detector_name,
            "OrgId": str(detection.org_id),
            "OrgAlias": detection.org_alias,
            "CaseId": str(detection.case_id) if detection.case_id is not None else None,
            "SourceIndex": detection.source_index,
            "TriageState": detection.triage_state.value,
            "RuleSeverity": detection.rule_severity,
            "RiskScore": detection.risk_score,
            "AttackTags": list(detection.attack_tags),
            "RuleMatches": rule_matches,
            "MatchedDocumentIds": list(detection.matched_document_ids),
            "ExtendedProperties": extended_properties,
        }
