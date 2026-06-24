"""FastEvtxParser: parses Windows Event Log (.evtx) files into TimelineRecords.

Requires the 'evtx' package (pyevtx-rs Python binding):
    pip install evtx

The evtx library requires random access to the file, so we buffer the entire
stream into a BytesIO before parsing.  EVTX files are typically <500 MB.
"""

from __future__ import annotations

import io
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

_EVTX_MAGIC = b"ElfFile\x00"


def _get_evtx_version() -> str:
    try:
        import evtx  # noqa: PLC0415

        return getattr(evtx, "__version__", "0.8")
    except ImportError:
        return "0.8"


class FastEvtxParser(ForensicParser):
    """Parses Windows EVTX event logs using the evtx-rs Python binding."""

    @property
    def parser_name(self) -> str:
        return "evtx-rs"

    @property
    def parser_version(self) -> str:
        return _get_evtx_version()

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Accept files whose first 8 bytes match the EVTX magic signature."""
        return header_bytes[:8] == _EVTX_MAGIC

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Buffer stream into memory, then parse synchronously via evtx library."""
        import evtx  # noqa: PLC0415

        chunks: list[bytes] = []
        async for chunk in stream:
            chunks.append(chunk)
        buf = io.BytesIO(b"".join(chunks))

        idx = 0
        # PyEvtxParser does not implement the context manager protocol; use directly.
        # records_json() may yield RuntimeError objects for malformed records per library docs.
        parser = evtx.PyEvtxParser(buf)
        for raw_record in parser.records_json():
            if isinstance(raw_record, RuntimeError):
                logger.debug(
                    "evtx_parser: skipping malformed record (library error)",
                    extra={"error": str(raw_record)},
                )
                continue
            try:
                record = self._to_timeline_record(raw_record, idx, evidence)
                yield record
                idx += 1
            except Exception:
                logger.debug(
                    "evtx_parser: skipping malformed record",
                    extra={"record_id": raw_record.get("event_record_id")},
                )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _to_timeline_record(
        self, raw: dict[str, Any], idx: int, evidence: Evidence
    ) -> TimelineRecord:
        event_data = json.loads(raw.get("data", "{}"))
        system: dict[str, Any] = event_data.get("Event", {}).get("System", {})

        # Timestamp
        time_created = system.get("TimeCreated", {})
        if isinstance(time_created, dict):
            ts_str: str = time_created.get("#attributes", {}).get("SystemTime", "")
        else:
            ts_str = str(time_created)
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            fallback = raw.get("timestamp", "").replace("Z", "+00:00")
            ts = datetime.fromisoformat(fallback) if raw.get("timestamp") else datetime.now(UTC)

        # EventID — may be int or {"#text": "4624", "#attributes": {...}}
        event_id_raw = system.get("EventID", {})
        event_id: str | None = None
        if isinstance(event_id_raw, dict):
            event_id = str(event_id_raw.get("#text", ""))
        elif event_id_raw is not None:
            event_id = str(event_id_raw)

        host_name: str | None = system.get("Computer")
        security = system.get("Security", {})
        user_id: str | None = None
        if isinstance(security, dict):
            user_id = security.get("#attributes", {}).get("UserID")

        extra: dict[str, Any] = {
            "event.module": "windows",
            "event.dataset": "windows.evtx",
        }
        if event_id:
            extra["event.code"] = event_id
        if system.get("Channel"):
            extra["log.file.path"] = system["Channel"]
        # Merge EventData fields.
        event_data_block = event_data.get("Event", {}).get("EventData", {})
        if isinstance(event_data_block, dict):
            for k, v in event_data_block.items():
                if k != "#text":
                    extra[f"winlog.event_data.{k}"] = v

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
                "event.kind": "event",
                "event.category": ["host"],
                "event.original": raw.get("data", "")[:32768],
                "host.name": host_name,
                "user.id": user_id,
            },
            extra=extra,
            kronos=provenance,
        )
