"""NginxParser: parses combined log format access logs into TimelineRecords."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import KronosProvenance, TimelineRecord
from src.domain.user import TenantContext

logger = logging.getLogger(__name__)

# Combined Log Format regex.
_COMBINED_LOG_RE = re.compile(
    r"(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) "
    r"\[(?P<time_local>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status>\d{3}) (?P<bytes_sent>\d+|-) "
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# Quick check: does the header look like combined log format?
_HEADER_RE = re.compile(rb"^\S+ \S+ \S+ \[[\d/\w: +\-]+\] \"")


def _ext(filename: str) -> str:
    dot = filename.rfind(".")
    return filename[dot:].lower() if dot != -1 else ""


class NginxParser(ForensicParser):
    """Parses Nginx combined log format access logs."""

    @property
    def parser_name(self) -> str:
        return "nginx"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Accept .log/.txt files whose header matches combined log format."""
        if _ext(filename) not in {".log", ".txt"}:
            return False
        return bool(_HEADER_RE.search(header_bytes))

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Yield one TimelineRecord per valid combined-log-format line."""
        partial = b""
        idx = 0

        async for chunk in stream:
            data = partial + chunk
            lines = data.splitlines(keepends=True)
            # Keep the last fragment if it has no newline yet.
            if lines and not lines[-1].endswith((b"\n", b"\r")):
                partial = lines.pop()
            else:
                partial = b""

            for raw_line in lines:
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                record = self._parse_line(line, idx, evidence)
                if record is not None:
                    yield record
                    idx += 1

        # Process any remaining data.
        if partial:
            line = partial.decode("utf-8", errors="replace").rstrip("\r\n")
            record = self._parse_line(line, idx, evidence)
            if record is not None:
                yield record

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_line(self, line: str, idx: int, evidence: Evidence) -> TimelineRecord | None:
        if not line.strip():
            return None
        m = _COMBINED_LOG_RE.match(line)
        if not m:
            logger.debug("nginx_parser: skipping non-matching line")
            return None

        try:
            ts = datetime.strptime(m["time_local"], _TIME_FMT)
        except ValueError:
            ts = datetime.now(UTC)

        remote_user: str | None = m["remote_user"] if m["remote_user"] != "-" else None
        referrer: str | None = m["referrer"] if m["referrer"] != "-" else None
        bytes_sent: int | None = int(m["bytes_sent"]) if m["bytes_sent"] != "-" else None

        extra: dict[str, Any] = {
            "source.ip": m["remote_addr"],
            "http.request.method": m["method"],
            "url.path": m["path"],
            "http.response.status_code": int(m["status"]),
            "user_agent.original": m["user_agent"],
        }
        if bytes_sent is not None:
            extra["http.response.body.bytes"] = bytes_sent
        if referrer is not None:
            extra["http.request.referrer"] = referrer

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
                "message": f"{m['method']} {m['path']} {m['status']}",
                "event.kind": "event",
                "event.category": ["web"],
                "event.type": ["access"],
                "user.name": remote_user,
            },
            extra=extra,
            kronos=provenance,
        )
