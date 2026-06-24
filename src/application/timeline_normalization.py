"""ECS normalizer: converts TimelineRecord to an OpenSearch document dict."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from src.domain.timeline import TimelineRecord


def build_index_name(org_alias: str, case_id: str, timestamp: datetime) -> str:
    """Return the per-tenant monthly index name for a timeline record.

    Pattern: ``kronos-{safe_org}-case-{case_id}-{yyyymm}``
    """
    safe_org = re.sub(r"[^a-z0-9-]", "-", org_alias.lower())
    yyyymm = timestamp.strftime("%Y%m")
    return f"kronos-{safe_org}-case-{case_id}-{yyyymm}"


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
            "kronos": {
                "evidence_id": str(record.kronos.evidence_id),
                "case_id": str(record.kronos.case_id),
                "org_id": str(record.kronos.org_id),
                "sha256": record.kronos.sha256,
                "parser": record.kronos.parser,
                "parser_version": record.kronos.parser_version,
                "record_index": record.kronos.record_index,
                "ingest_timestamp": record.kronos.ingest_timestamp.isoformat(),
            },
        }
        if record.message is not None:
            raw["message"] = record.message

        doc = _clean_none(raw)
        # Merge extra fields at the top level (format-specific preserved fields).
        doc.update(record.extra)
        return doc


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
