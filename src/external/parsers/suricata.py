"""SuricataEveParser: parses Suricata EVE JSON logs into TimelineRecords.

EVE JSON (``eve.json``) is Suricata's real-time NDJSON event log -- one flat
JSON object per line, every line carrying ``timestamp``/``event_type`` plus
(for network events) the 5-tuple (``src_ip``/``src_port``/``dest_ip``/
``dest_port``/``proto``). Schema reference used: Suricata's own userguide,
``doc/userguide/output/eve/eve-json-format.rst`` at tag ``suricata-8.0.6``
(https://github.com/OISF/suricata/blob/suricata-8.0.6/doc/userguide/output/eve/eve-json-format.rst)
-- see tests/fixtures/samples/real/suricata/NOTICE.md for the real, captured
sample this parser is verified against (CLAUDE.md Section F).
"""

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

# ECS event.kind/event.category/event.type per real Suricata event_type --
# only the types actually verified against real captured output (see
# NOTICE.md); anything else falls back to _DEFAULT_ECS below rather than
# guessing at a mapping never exercised against real data.
_ECS_BY_EVENT_TYPE: dict[str, tuple[str, list[str], list[str]]] = {
    # event_type -> (event.kind, event.category, event.type)
    "alert": ("alert", ["intrusion_detection", "network"], ["info"]),
    "flow": ("event", ["network"], ["connection", "end"]),
    "http": ("event", ["network", "web"], ["protocol"]),
    "dns": ("event", ["network"], ["protocol"]),
    "tls": ("event", ["network"], ["protocol"]),
    "fileinfo": ("event", ["file", "network"], ["info"]),
    "anomaly": ("event", ["network"], ["error"]),
}
_DEFAULT_ECS: tuple[str, list[str], list[str]] = ("event", ["network"], [])


def _ext(filename: str) -> str:
    dot = filename.rfind(".")
    return filename[dot:].lower() if dot != -1 else ""


class SuricataEveParser(ForensicParser):
    """Parses Suricata EVE JSON (``eve.json``) NDJSON logs.

    Detection deliberately keys on ``flow_id`` (Suricata's own
    flow-correlation field, present on every network-event line -- see the
    userguide's "Field: flow_id" section) alongside ``event_type``, rather
    than any single Suricata-specific sub-object (``alert``/``dns``/``http``
    are all optional per line and would each miss real lines that lack that
    particular sub-object). ``CloudTrailParser`` keys on ``"Records"``/
    ``"CloudTrailEvent"``, which never appears in real EVE JSON, so the two
    parsers' detection signals cannot collide in either registration order --
    verified by reading both ``supports()`` methods together.
    """

    @property
    def parser_name(self) -> str:
        return "suricata-eve"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Accept .json/.jsonl files whose header carries EVE's own
        event_type + flow_id fields."""
        if _ext(filename) not in {".json", ".jsonl"}:
            return False
        return b'"event_type"' in header_bytes and b'"flow_id"' in header_bytes

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Yield one TimelineRecord per EVE JSON line (streamed, not buffered
        whole -- eve.json files can be very large on a busy sensor)."""
        partial = b""
        idx = 0

        async for chunk in stream:
            data = partial + chunk
            lines = data.split(b"\n")
            partial = lines.pop()  # last fragment may be incomplete

            for raw_line in lines:
                record = self._parse_line(raw_line, idx, evidence)
                if record is not None:
                    yield record
                    idx += 1

        if partial.strip():
            record = self._parse_line(partial, idx, evidence)
            if record is not None:
                yield record

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_line(self, raw_line: bytes, idx: int, evidence: Evidence) -> TimelineRecord | None:
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            return None
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("suricata_parser: skipping non-JSON line")
            return None
        if not isinstance(event, dict):
            return None
        return self._to_timeline_record(event, idx, evidence, line)

    def _to_timeline_record(
        self, event: dict[str, Any], idx: int, evidence: Evidence, raw_line: str
    ) -> TimelineRecord:
        event_type: str = event.get("event_type", "")
        kind, category, event_type_list = _ECS_BY_EVENT_TYPE.get(event_type, _DEFAULT_ECS)

        ts_str: str = event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str)
        except (ValueError, AttributeError):
            ts = datetime.now(UTC)

        extra = self._build_extra(event)

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
                "message": self._build_message(event_type, event),
                "event.kind": kind,
                "event.category": category,
                "event.type": event_type_list,
                "event.original": raw_line[:32768],
            },
            extra=extra,
            kronos=provenance,
        )

    @staticmethod
    def _build_message(event_type: str, event: dict[str, Any]) -> str:
        if event_type == "alert":
            alert = event.get("alert", {})
            return str(alert.get("signature") or f"suricata alert ({event_type})")
        if event_type == "http":
            http = event.get("http", {})
            method = http.get("http_method", "?")
            host = http.get("hostname", "")
            url = http.get("url", "")
            status = http.get("status", "")
            return f"{method} {host}{url} {status}"
        if event_type == "dns":
            dns = event.get("dns", {})
            queries = dns.get("queries") or []
            rrname = queries[0].get("rrname") if queries else dns.get("rrname")
            return f"dns {dns.get('type', '')} {rrname or ''}"
        if event_type == "flow":
            src = event.get("src_ip", "")
            dst = event.get("dest_ip", "")
            src_port = event.get("src_port", "")
            dst_port = event.get("dest_port", "")
            proto = event.get("proto", "")
            return f"{proto} flow {src}:{src_port} -> {dst}:{dst_port}"
        if event_type == "fileinfo":
            fileinfo = event.get("fileinfo", {})
            return f"file {fileinfo.get('filename', '')} ({fileinfo.get('size', '?')} bytes)"
        if event_type == "anomaly":
            anomaly = event.get("anomaly", {})
            return f"anomaly {anomaly.get('type', '')}: {anomaly.get('event', '')}"
        return f"suricata {event_type or 'event'}"

    @staticmethod
    def _build_extra(event: dict[str, Any]) -> dict[str, Any]:
        """Map the 5-tuple + type-specific sub-objects to ECS-ish keys plus
        namespaced Suricata fields, mirroring CloudTrailParser/NginxParser's
        own extra-field convention (real ECS field name where one exists,
        ``<subobject>.<field>`` passthrough otherwise)."""
        extra: dict[str, Any] = {
            "source.ip": event.get("src_ip"),
            "source.port": event.get("src_port"),
            "destination.ip": event.get("dest_ip"),
            "destination.port": event.get("dest_port"),
            "network.transport": (event.get("proto") or "").lower() or None,
            "network.protocol": event.get("app_proto"),
            "network.community_id": event.get("community_id"),
            "suricata.flow_id": event.get("flow_id"),
            "suricata.tx_id": event.get("tx_id"),
        }

        alert = event.get("alert")
        if isinstance(alert, dict):
            extra["alert.signature"] = alert.get("signature")
            extra["alert.category"] = alert.get("category")
            extra["alert.severity"] = alert.get("severity")
            extra["alert.action"] = alert.get("action")
            if alert.get("signature_id") is not None:
                extra["rule.id"] = str(alert["signature_id"])

        dns = event.get("dns")
        if isinstance(dns, dict):
            queries = dns.get("queries") or []
            if queries:
                extra["dns.rrname"] = queries[0].get("rrname")
                extra["dns.rrtype"] = queries[0].get("rrtype")
            extra["dns.type"] = dns.get("type")

        http = event.get("http")
        if isinstance(http, dict):
            extra["http.hostname"] = http.get("hostname")
            extra["url.path"] = http.get("url")
            extra["http.request.method"] = http.get("http_method")
            extra["http.response.status_code"] = http.get("status")

        tls = event.get("tls")
        if isinstance(tls, dict):
            extra["tls.subject"] = tls.get("subject")
            extra["tls.sni"] = tls.get("sni")

        flow = event.get("flow")
        if isinstance(flow, dict):
            extra["flow.bytes_toserver"] = flow.get("bytes_toserver")
            extra["flow.bytes_toclient"] = flow.get("bytes_toclient")
            extra["flow.pkts_toserver"] = flow.get("pkts_toserver")
            extra["flow.pkts_toclient"] = flow.get("pkts_toclient")
            extra["flow.state"] = flow.get("state")

        fileinfo = event.get("fileinfo")
        if isinstance(fileinfo, dict):
            extra["file.name"] = fileinfo.get("filename")
            extra["file.size"] = fileinfo.get("size")

        anomaly = event.get("anomaly")
        if isinstance(anomaly, dict):
            extra["anomaly.type"] = anomaly.get("type")
            extra["anomaly.event"] = anomaly.get("event")

        return {k: v for k, v in extra.items() if v is not None}
