"""CloudTrailParser: parses AWS CloudTrail JSON logs into TimelineRecords."""

from __future__ import annotations

import ipaddress
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


def _is_ip_literal(value: str | None) -> bool:
    """True if *value* parses as a real IPv4/IPv6 address.

    Real, reproduced bug (Gap Audit Milestone AAAA): AWS CloudTrail's own
    ``sourceIPAddress`` field is documented to hold the calling AWS
    service's hostname (e.g. ``"ec2.amazonaws.com"``) instead of an actual
    IP address for AWS-service-initiated events (confirmed against a real
    CloudTrail log, tests/fixtures/samples/real/aws_cloudtrail.jsonl's own
    "SharedSnapshotVolumeCreated" row) -- blindly mapping it straight to
    ECS's strictly ``ip``-typed ``source.ip`` field made a real bulk-index
    call fail outright (``mapper_parsing_exception``: "'ec2.amazonaws.com'
    is not an IP string literal"), permanently sinking the evidence to
    ERROR after Celery's retries exhausted. This is not a synthetic edge
    case -- AWS-service-linked CloudTrail events are common in real
    production logs.
    """
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


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
        """Accept .json/.jsonl files with a 'Records' wrapper, or NDJSON rows
        shaped like AWS's own CloudTrail Lake/S3-export format (each line a
        flat envelope with a "CloudTrailEvent" field holding the real event
        as a JSON-encoded string, rather than a top-level "Records" array).
        """
        if _ext(filename) not in {".json", ".jsonl"}:
            return False
        return b'"Records"' in header_bytes or b'"CloudTrailEvent"' in header_bytes

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
                return [self._unwrap_cloudtrail_event(r) for r in data["Records"]]
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
                    records.append(self._unwrap_cloudtrail_event(obj))
            except json.JSONDecodeError:
                logger.debug("cloudtrail_parser: skipping non-JSON line")
        return records

    @staticmethod
    def _unwrap_cloudtrail_event(record: dict[str, Any]) -> dict[str, Any]:
        """Unwrap AWS's CloudTrail Lake/S3-export envelope, if present.

        That export shape wraps the real event — the one with the
        lowercase-camelCase fields (eventName, eventSource, eventTime, ...)
        this module reads — as a JSON-encoded string under a top-level
        "CloudTrailEvent" key, alongside PascalCase summary fields (EventId,
        EventName, ...) that _to_timeline_record doesn't look at. Without
        this, every field read in _to_timeline_record silently misses
        (case-sensitive dict lookups), producing timestamp-less, actor-less
        records instead of failing loudly.
        """
        nested = record.get("CloudTrailEvent")
        if isinstance(nested, str):
            try:
                unwrapped = json.loads(nested)
            except json.JSONDecodeError:
                return record
            if isinstance(unwrapped, dict):
                return unwrapped
        return record

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

        source_ip_raw = ct.get("sourceIPAddress")
        extra: dict[str, Any] = {
            "event.action": event_name,
            "event.module": "aws",
            "event.dataset": "aws.cloudtrail",
            "cloud.service.name": event_source,
            "cloud.region": ct.get("awsRegion"),
            # ECS's own convention for an ambiguous source address (real
            # IP or hostname, per ECS's "source.address" field docs):
            # always keep the raw value here (index_template.json maps it
            # `keyword`, no type constraint), and only additionally
            # populate the strictly `ip`-typed source.ip when it actually
            # parses as one -- see _is_ip_literal()'s own docstring for
            # the real bug this closes.
            "source.address": source_ip_raw,
            "source.ip": source_ip_raw if _is_ip_literal(source_ip_raw) else None,
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
                "event.original": json.dumps(ct)[:32768],
                "user.name": user_name,
                "user.id": user_id,
            },
            extra={k: v for k, v in extra.items() if v is not None},
            kronos=provenance,
        )
