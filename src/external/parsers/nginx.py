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

# Combined Log Format regex. Both the leading "$host:$server_port " prefix
# (nginx's log_format when multiple vhosts share one log file) and the
# trailing referrer/user-agent pair (absent in plain Common Log Format,
# which some nginx/apache configs still use) are optional — real-world
# access logs mix all of these; a real Plaso test corpus sample
# (test_data/apache_access.log, see tests/fixtures/samples/real/) has both
# variants sitting next to fully-combined lines in the same file, and the
# strict all-fields-required version of this regex silently dropped 9 of
# its 15 lines.
_COMBINED_LOG_RE = re.compile(
    r"(?:\S+:\d+ )?"
    r"(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) "
    r"\[(?P<time_local>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status>\d{3}) (?P<bytes_sent>\d+|-)"
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# Number of leading *content* lines detection inspects before giving up.
# Detection must not be anchored to byte 0: a real access log can legitimately
# begin with blank lines, an operator annotation, or W3C/IIS-style "#Fields:"
# comment headers, and the previous byte-0-anchored check ("^...") rejected
# the entire file in that case — surfacing as a "No parser found" ParsingError
# on upload even though every data line was a perfectly standard access-log
# entry. Scanning a bounded number of leading lines keeps detection O(1) on
# file size while tolerating that leading noise. Detection reuses the exact
# same _COMBINED_LOG_RE the parser uses, so "detected" always implies
# "parseable" — the two can no longer drift apart (they previously were two
# separate regexes that had to be kept in sync by hand).
_DETECT_MAX_LINES = 50


def _ext(filename: str) -> str:
    dot = filename.rfind(".")
    return filename[dot:].lower() if dot != -1 else ""


def _looks_like_access_log(header_bytes: bytes) -> bool:
    """True if any of the first _DETECT_MAX_LINES content lines is a log line.

    Skips a leading UTF-8 BOM, blank lines, and comment/header lines (``#``).
    Only the detection window (first N KB) is passed in; the last line may be
    truncated, which is harmless — earlier full lines decide the match.
    """
    text = header_bytes.decode("utf-8", errors="replace").lstrip("﻿")
    seen = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _COMBINED_LOG_RE.match(line) is not None:
            return True
        seen += 1
        if seen >= _DETECT_MAX_LINES:
            break
    return False


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
        """Accept .log/.txt files with at least one combined/common log line."""
        if _ext(filename) not in {".log", ".txt"}:
            return False
        return _looks_like_access_log(header_bytes)

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
        # referrer/user_agent are None outright (not "-") when the trailing
        # pair is absent entirely — plain Common Log Format, no quotes to
        # even contain a "-".
        referrer: str | None = m["referrer"] if m["referrer"] not in (None, "-") else None
        user_agent: str | None = m["user_agent"] if m["user_agent"] not in (None, "-") else None
        bytes_sent: int | None = int(m["bytes_sent"]) if m["bytes_sent"] != "-" else None

        extra: dict[str, Any] = {
            "event.module": "nginx",
            "event.dataset": "nginx.access",
            "source.ip": m["remote_addr"],
            "http.request.method": m["method"],
            "url.path": m["path"],
            "http.response.status_code": int(m["status"]),
        }
        if bytes_sent is not None:
            extra["http.response.body.bytes"] = bytes_sent
        if referrer is not None:
            extra["http.request.referrer"] = referrer
        if user_agent is not None:
            extra["user_agent.original"] = user_agent

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
                "event.original": line[:32768],
                "user.name": remote_user,
            },
            extra=extra,
            kronos=provenance,
        )
