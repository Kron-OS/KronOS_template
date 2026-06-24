"""CloudTrailParser: parses AWS CloudTrail JSON logs into TimelineRecords."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import KronosProvenance, TimelineRecord
from src.domain.user import TenantContext

logger = logging.getLogger(__name__)


def _ext(filename: str) -> str:
    dot = filename.rfind(".")
    return filename[dot:].lower() if dot != -1 else ""


class CloudTrailParser(ForensicParser):
    """Parses AWS CloudTrail JSON — {"Records": [...]} or NDJSON (one object per line)."""

    @property
    def parser_name(self) -> str:
        return "cloudtrail"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Accept .json/.jsonl files that contain a 'Records' key in the first 8 KB."""
        if _ext(filename) not in {".json", ".jsonl"}:
            return False
        return b'"Records"' in header_bytes

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Yield one TimelineRecord per CloudTrail event record."""
        chunks: list[bytes] = []
        async for chunk in stream:
            chunks.append(chunk)
        raw = b"".join(chunks)

        records = self._extract_records(raw)
        for idx, ct_record in enumerate(records):
            yield self._to_timeline_record(ct_record, idx, evidence)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_records(self, raw: bytes) -> list[dict[str, Any]]:
        """Parse either {"Records": [...]} or NDJSON format."""
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return []

        # Try wrapped Records format first.
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "Records" in data:
                return list(data["Records"])
        except json.JSONDecodeError:
            pass

        # Fall back to NDJSON.
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError:
                logger.debug("cloudtrail_parser: skipping non-JSON line")
        return records

    def _to_timeline_record(
        self, ct: dict[str, Any], idx: int, evidence: Evidence
    ) -> TimelineRecord:
        identity = ct.get("userIdentity", {})
        user_name: str | None = identity.get("userName") or identity.get("principalId")
        user_id: str | None = identity.get("accountId")
        event_name: str = ct.get("eventName", "")
        event_source: str = ct.get("eventSource", "")

        ts_str: str = ct.get("eventTime", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.now(UTC)

        extra: dict[str, Any] = {
            "event.action": event_name,
            "cloud.service.name": event_source,
            "cloud.region": ct.get("awsRegion"),
            "source.ip": ct.get("sourceIPAddress"),
        }
        if ct.get("errorCode"):
            extra["error.code"] = ct["errorCode"]
        if ct.get("errorMessage"):
            extra["error.message"] = ct["errorMessage"]
        if ct.get("requestParameters"):
            extra["cloudtrail.request_parameters"] = ct["requestParameters"]

        provenance = KronosProvenance(
            evidence_id=evidence.evidence_id,
            case_id=evidence.metadata.case_id,
            org_id=evidence.metadata.org_id,
            sha256=evidence.sha256 or "",
            parser=self.parser_name,
            parser_version=self.parser_version,
            record_index=idx,
            ingest_timestamp=datetime.now(UTC),
        )

        return TimelineRecord(
            **{
                "@timestamp": ts,
                "message": f"{event_name} by {user_name or 'unknown'} on {event_source}",
                "event.kind": "event",
                "event.category": ["cloud"],
                "user.name": user_name,
                "user.id": user_id,
            },
            extra={k: v for k, v in extra.items() if v is not None},
            kronos=provenance,
        )
