"""ECS normalizer: converts TimelineRecord to an OpenSearch document dict."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from src.domain.stream import StreamProvenance
from src.domain.timeline import EvidenceProvenance, Provenance, TimelineRecord


def build_index_name(org_alias: str, case_id: str, timestamp: datetime) -> str:
    """Return the per-tenant monthly index name for a timeline record.

    Pattern: ``kronos-{safe_org}-case-{case_id}-{yyyymm}``
    """
    safe_org = re.sub(r"[^a-z0-9-]", "-", org_alias.lower())
    yyyymm = timestamp.strftime("%Y%m")
    return f"kronos-{safe_org}-case-{case_id}-{yyyymm}"


def build_stream_index_name(org_alias: str, source_id: str, timestamp: datetime) -> str:
    """Return the per-tenant monthly index name for a continuous-telemetry
    record (``StreamProvenance``, ``src/domain/stream.py`` -- roadmap M1/B1).

    Pattern: ``kronos-{safe_org}-stream-{safe_source}-{yyyymm}`` -- a sibling
    to :func:`build_index_name`'s case-scoped naming, keyed on ``source_id``
    (e.g. a collector name) instead of ``case_id``, since a stream record has
    no owning case at ingest time. Both share the ``kronos-*`` prefix
    deliberately: ``kronos-generic-tenant``'s DLS clause
    (``scripts/provision_opensearch_security.py``) and the ISM policy
    (``ism_policy.json``) are both templated on that exact wildcard, so a new
    index family under it inherits both without any config change -- verified
    for real, not assumed, in ``poc/stream_index_dls/``.
    """
    safe_org = re.sub(r"[^a-z0-9-]", "-", org_alias.lower())
    safe_source = re.sub(r"[^a-z0-9-]", "-", source_id.lower())
    yyyymm = timestamp.strftime("%Y%m")
    return f"kronos-{safe_org}-stream-{safe_source}-{yyyymm}"


class ECSNormalizer:
    """Converts a :class:`TimelineRecord` to a nested OpenSearch document."""

    def to_document(self, record: TimelineRecord) -> dict[str, Any]:
        """Build a document dict suitable for OpenSearch bulk indexing.

        Flattened ECS fields on the record (e.g. ``event_kind``) are expanded
        back to nested form (``{"event": {"kind": ...}}``) as required by the
        ECS index mapping.  None values are omitted to avoid storing null fields.
        """
        raw: dict[str, Any] = {
            "@timestamp": record.timestamp.isoformat(),
            "event": {
                "kind": record.event_kind,
                "category": record.event_category or None,
                "type": record.event_type or None,
                "outcome": record.event_outcome,
                "original": record.event_original,
            },
            "host": {
                "name": record.host_name,
                "os": {"name": record.host_os_name},
            },
            "user": {
                "name": record.user_name,
                "id": record.user_id,
            },
            "process": {
                "pid": record.process_pid,
                "name": record.process_name,
            },
            "kronos": _provenance_document(record.kronos),
        }
        if record.message is not None:
            raw["message"] = record.message
        # source_path only exists on EvidenceProvenance (a stream event has
        # no container/source-path concept -- see StreamProvenance's own
        # docstring, src/domain/stream.py).
        if isinstance(record.kronos, EvidenceProvenance) and record.kronos.source_path is not None:
            raw["file"] = {"path": record.kronos.source_path}

        doc = _clean_none(raw)
        # Merge extra fields, expanding dotted keys into nested dicts (ECS convention).
        for key, value in record.extra.items():
            _set_dotted(doc, key, value)
        return doc


def _provenance_document(kronos: Provenance) -> dict[str, Any]:
    """Build the kronos.* sub-document for either provenance shape (roadmap D4).

    ``EvidenceProvenance`` and ``StreamProvenance`` share only
    ``ProvenanceBase``'s fields (org_id/org_alias/parser/parser_version/
    ingest_timestamp) -- the rest is genuinely different per kind (an
    evidence-file record has no source_id/batch_id/event_offset; a stream
    record has no evidence_id/sha256/record_index), so this branches once,
    explicitly, rather than trying to force one shared dict shape.
    """
    common: dict[str, Any] = {
        "org_id": str(kronos.org_id),
        "org_alias": kronos.org_alias,
        "parser": kronos.parser,
        "parser_version": kronos.parser_version,
        "ingest_timestamp": kronos.ingest_timestamp.isoformat(),
    }
    if isinstance(kronos, EvidenceProvenance):
        common.update(
            {
                "evidence_id": str(kronos.evidence_id),
                "case_id": str(kronos.case_id),
                "sha256": kronos.sha256,
                "record_index": kronos.record_index,
                "source_path": kronos.source_path,
                "container_sha256": kronos.container_sha256,
            }
        )
    else:
        assert isinstance(
            kronos, StreamProvenance
        )  # noqa: S101 -- exhaustiveness, not a runtime guard
        common.update(
            {
                "source_id": kronos.source_id,
                "batch_id": str(kronos.batch_id),
                "event_offset": kronos.event_offset,
                "case_id": str(kronos.case_id) if kronos.case_id is not None else None,
            }
        )
    return common


def _clean_none(obj: dict[str, Any]) -> dict[str, Any]:
    """Recursively remove keys whose value is None or an empty nested dict."""
    result: dict[str, Any] = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            cleaned = _clean_none(value)
            if cleaned:
                result[key] = cleaned
        elif value is not None:
            result[key] = value
    return result


def _set_dotted(doc: dict[str, Any], key: str, value: Any) -> None:
    """Set a value in *doc* using a dotted key path, merging into existing nested dicts.

    ``_set_dotted(doc, "event.code", "4624")`` is equivalent to
    ``doc.setdefault("event", {})["code"] = "4624"``.
    Non-dotted keys are set directly.
    """
    parts = key.split(".", 1)
    if len(parts) == 1:
        doc[key] = value
    else:
        head, tail = parts
        if head not in doc or not isinstance(doc[head], dict):
            doc[head] = {}
        _set_dotted(doc[head], tail, value)
