"""CefDetectionMapper: real CEF (Common Event Format)-shaped
``DetectionEventMapper`` producing a full RFC 3164 syslog-framed CEF message
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R3 -- "Generic CEF-over-syslog sink
connector").

**Reuse ``SyslogIntegrationSink`` (R1) unchanged -- no sibling sink class,
and here's why (mirrors ``splunk_hec_sink.py``'s own sibling-vs-reuse
rigor, this time landing on the opposite answer, per the R3 brief's own
explicit "justify your choice" instruction).**

CEF's real, documented wire shape -- verified against the official Micro
Focus/OpenText "Implementing ArcSight Common Event Format (CEF)" guide and
corroborated, word-for-word on the escaping rules, by Micro Focus's own
"What is CEF?" doc page and the community.opentext.com CEF White Paper, plus
independently confirmed by Microsoft Sentinel's own CEF-via-AMA connector
docs (``learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama``)
-- is:

    <PRI>Mmm dd hh:mm:ss host CEF:Version|Device Vendor|Device Product|
    Device Version|Device Event Class ID|Name|Severity|Extension

i.e. an ordinary RFC 3164 (BSD syslog) framed line whose MESSAGE happens to
start with the literal token ``CEF:0|...``. ``SyslogIntegrationSink.push_events()``
already does exactly one thing: write whatever ``MappedSinkEvent.raw_text``
string it is given as one line (TCP, newline-terminated) or one datagram
(UDP) -- it never inspects, reshapes, or adds anything to that string (see
its own module docstring: "no auth, no ack, exactly the real transport
CEF/LEEF-over-syslog is"). Nothing about a CEF-over-syslog line needs
different *socket* behavior from any other line ``SyslogIntegrationSink``
already sends -- the entire CEF-specific requirement (the RFC 3164 header,
the CEF marker, and the header-vs-extension escaping rules) is about the
STRING CONTENTS, which ``MappedSinkEvent``'s own docstring already assigns
to the mapper's job ("only the mapper knows the target's own field
dictionary, so formatting happens here, never in the transport"). Building
a sibling sink class here would duplicate ``SyslogIntegrationSink``'s real
TCP/UDP-write-and-honest-``UNACKNOWLEDGED`` logic for zero behavioral
gain -- exactly the outcome ``splunk_hec_sink.py``'s own docstring flags as
"not enough shared behavior to justify" a new class, mirrored here to the
opposite conclusion: for CEF-over-syslog there IS enough shared behavior
(100% of the transport) to justify pure reuse. Verified for real, not just
argued: ``poc/integration_sink_cef_syslog/`` pushes a real ``Detection``
through this mapper and the real, *unmodified* ``SyslogIntegrationSink``
against a real local TCP+UDP receiver -- see that PoC's README/output.txt.

**Escaping rules implemented here (real, spec-verified, not memory).** CEF
divides every message into two structurally different zones with DIFFERENT
escaping rules -- confirmed, verbatim, from the real spec text: "If a pipe
(|) is used in the prefix, it has to be escaped with a backslash (\\).
However, pipes in the extension do not need escaping." / "If a backslash
(\\) is used in the prefix or the extension, it has to be escaped with
another backslash (\\)." / "If an equal sign (=) is used in the
extensions, it has to be escaped with a backslash (\\). However, equal
signs in the prefix need no escaping."

- **Header/"prefix" fields** (the 7 pipe-delimited fields from ``Version``
  through ``Severity``): a literal ``|`` MUST become ``\\|``; a literal
  ``\\`` MUST become ``\\\\``. Equals signs are left untouched here.
- **Extension fields** (space-separated ``key=value`` pairs): a literal
  ``=`` MUST become ``\\=``; a literal ``\\`` MUST become ``\\\\``. Pipes
  are left untouched here.
- In both zones, backslash-escaping is applied FIRST, before the
  zone-specific delimiter escaping -- otherwise the backslash just
  inserted to escape a ``|``/``=`` would itself get re-escaped a second
  time (verified by the round-trip parse in the PoC, not just asserted).

**RFC 3164 vs RFC 5424 (the R3 brief's own "check which is more
universally expected for CEF" question) -- RFC 3164 (BSD syslog), not RFC
5424.** Every real CEF worked example in the official Micro Focus/OpenText
docs, and every named-vendor CEF-over-syslog configuration guide found
during research (Palo Alto Networks, Centrify, Microsoft Sentinel's own
CEF-via-AMA connector), uses the plain ``Mmm dd hh:mm:ss host CEF:0|...``
BSD-style prefix -- never RFC 5424's structured-data/
``VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME`` form. ``facility=local4``
(RFC 3164 facility code 20) is used as the default PRI facility --
Microsoft's own CEF-via-AMA connector docs confirm this is the real,
common convention ("the syslog agent sets the facility to local4 for CEF
forwarding" by default) -- constructor-overridable since it is a generic
syslog-framing choice, not something the CEF spec itself mandates.

Zero framework imports (CLAUDE.md SS A.3) -- pure stdlib, no httpx/socket
here (that's ``SyslogIntegrationSink``'s job, reused unchanged per above).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.application.detection_sink_mapper import DetectionEventMapper, MappedSinkEvent
from src.domain.detection import Detection

_CEF_VERSION = 0
_DEFAULT_DEVICE_VENDOR = "KronOS"
_DEFAULT_DEVICE_PRODUCT = "DetectionSink"
_DEFAULT_DEVICE_VERSION = "1.0"

# Sigma severity vocabulary (SIGMA_SEVERITY_LEVELS, src/domain/detection.py)
# mapped onto CEF's own documented 0-10 integer Severity scale (the real
# spec's own worked guidance bands: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very
# High) -- deterministic, ascending, mirrors SIGMA_SEVERITY_LEVELS' own
# ordering so a higher Sigma tier never maps to a lower CEF severity.
_CEF_SEVERITY_BY_SIGMA_LEVEL: dict[str, int] = {
    "informational": 0,
    "low": 3,
    "medium": 5,
    "high": 8,
    "critical": 10,
}
# CEF's own documented "Unknown" floor -- an honest absence, never a
# fabricated risk judgment (mirrors highest_rule_severity()'s own "return
# None, never substitute a fabricated default" contract one level up) --
# used only when no matched rule carries a recognized Sigma severity tag.
_CEF_SEVERITY_UNKNOWN = 0

_RFC3164_MONTH_ABBR = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)  # fmt: skip
# local4 -- real, common CEF-over-syslog forwarder default (Microsoft
# Sentinel's own CEF-via-AMA connector docs: "the syslog agent sets the
# facility to local4 for CEF forwarding" by default). A generic RFC 3164
# framing choice, not part of the CEF spec itself, hence overridable below.
_DEFAULT_SYSLOG_FACILITY = 20
# RFC 3164 "Notice" -- a neutral default for the OUTER syslog envelope's
# own severity, distinct from CEF's own Severity header field above (which
# carries the real triage signal); overridable, never load-bearing.
_DEFAULT_SYSLOG_SEVERITY = 5


def _escape_backslashes(value: str) -> str:
    return value.replace("\\", "\\\\")


def _escape_header_field(value: str) -> str:
    """Real CEF header/"prefix" escaping: backslash first, then pipe.

    Equals signs are deliberately left untouched here -- the real spec's
    own text: "equal signs in the prefix need no escaping."
    """
    escaped = _escape_backslashes(value)
    escaped = escaped.replace("|", "\\|")
    return escaped.replace("\n", "\\n").replace("\r", "\\r")


def _escape_extension_value(value: str) -> str:
    """Real CEF extension escaping: backslash first, then equals.

    Pipes are deliberately left untouched here -- the real spec's own
    text: "pipes in the extension do not need escaping."
    """
    escaped = _escape_backslashes(value)
    escaped = escaped.replace("=", "\\=")
    return escaped.replace("\n", "\\n").replace("\r", "\\r")


def _rfc3164_prefix(timestamp: datetime, hostname: str, *, facility: int, severity: int) -> str:
    """A real RFC 3164 (BSD syslog) ``<PRI>Mmm dd hh:mm:ss host`` prefix."""
    pri = facility * 8 + severity
    ts = timestamp.astimezone(UTC)
    month = _RFC3164_MONTH_ABBR[ts.month - 1]
    # RFC 3164's own timestamp grammar space-pads the day to 2 characters,
    # never zero-pads it -- "Sep  9", not "Sep 09".
    formatted_ts = f"{month} {ts.day:2d} {ts.hour:02d}:{ts.minute:02d}:{ts.second:02d}"
    return f"<{pri}>{formatted_ts} {hostname}"


class CefDetectionMapper(DetectionEventMapper):
    """Maps one ``Detection`` into one real, RFC 3164-framed CEF syslog line.

    Produces ``MappedSinkEvent.raw_text`` (never ``payload``) -- the
    already-fully-formatted line ``SyslogIntegrationSink`` (unmodified,
    per this module's own docstring) writes as-is.
    """

    def __init__(
        self,
        *,
        device_vendor: str = _DEFAULT_DEVICE_VENDOR,
        device_product: str = _DEFAULT_DEVICE_PRODUCT,
        device_version: str = _DEFAULT_DEVICE_VERSION,
        syslog_facility: int = _DEFAULT_SYSLOG_FACILITY,
        syslog_severity: int = _DEFAULT_SYSLOG_SEVERITY,
        hostname: str | None = None,
    ) -> None:
        self._device_vendor = device_vendor
        self._device_product = device_product
        self._device_version = device_version
        self._syslog_facility = syslog_facility
        self._syslog_severity = syslog_severity
        self._hostname = hostname

    def map(self, detection: Detection) -> MappedSinkEvent:
        name = self._event_name(detection)
        severity = self._cef_severity(detection)
        header_fields = [
            f"CEF:{_CEF_VERSION}",
            _escape_header_field(self._device_vendor),
            _escape_header_field(self._device_product),
            _escape_header_field(self._device_version),
            _escape_header_field(detection.detector_name),
            _escape_header_field(name),
            str(severity),
        ]
        # Real CEF wire shape: 7 pipe-delimited header fields, a TRAILING
        # pipe, then the extension appended directly with no leading pipe
        # of its own (verified against the real worked spec example --
        # "CEF:0|Security|threatmanager|1.0|100|worm...|10|src=...").
        header = "|".join(header_fields) + "|"
        extension = self._extension(detection)
        cef_message = header + extension

        hostname = self._hostname if self._hostname is not None else detection.org_alias
        prefix = _rfc3164_prefix(
            detection.finding_timestamp,
            hostname,
            facility=self._syslog_facility,
            severity=self._syslog_severity,
        )
        raw_text = f"{prefix} {cef_message}"

        return MappedSinkEvent(
            source_detection_id=str(detection.detection_id),
            raw_text=raw_text,
            mapper_metadata={
                "device_vendor": self._device_vendor,
                "device_product": self._device_product,
                "device_event_class_id": detection.detector_name,
                "cef_severity": severity,
            },
        )

    @staticmethod
    def _event_name(detection: Detection) -> str:
        if detection.rule_matches and detection.rule_matches[0].rule_name:
            return detection.rule_matches[0].rule_name
        return detection.detector_name

    @staticmethod
    def _cef_severity(detection: Detection) -> int:
        level = detection.rule_severity
        if level is None:
            return _CEF_SEVERITY_UNKNOWN
        return _CEF_SEVERITY_BY_SIGMA_LEVEL[level]

    @staticmethod
    def _extension(detection: Detection) -> str:
        # Real, standard CEF Extension Dictionary keys used where they map
        # cleanly (externalId, cat, rt, msg -- all real, documented CEF
        # dictionary fields), plus the real CEF "custom string"/"custom
        # number" escape hatch (cs1-4/cs1Label-4Label, cn1/cn1Label) the
        # spec itself reserves for exactly this "vendor has its own fields"
        # case, mirroring SplunkDetectionMapper's own real-field-selection
        # precedent one layer down in a different envelope shape.
        fields: dict[str, Any] = {
            "externalId": str(detection.detection_id),
            "cat": detection.detector_name,
            "rt": int(detection.finding_timestamp.timestamp() * 1000),
            "msg": f"KronOS detection {detection.finding_id} ({detection.triage_state.value})",
            "cs1Label": "KronOS Org ID",
            "cs1": str(detection.org_id),
            "cs3Label": "KronOS Triage State",
            "cs3": detection.triage_state.value,
            "cs4Label": "KronOS ATT&CK Tags",
            "cs4": ",".join(detection.attack_tags),
        }
        # cs2/cs2Label (case correlation) only added as a pair -- omitted
        # entirely, never emitted as a dangling label with no value, when
        # this Detection has no case_id (stream-scoped indices, roadmap B2).
        if detection.case_id is not None:
            fields["cs2Label"] = "KronOS Case ID"
            fields["cs2"] = str(detection.case_id)
        if detection.risk_score is not None:
            fields["cn1Label"] = "KronOS Risk Score"
            fields["cn1"] = detection.risk_score

        parts: list[str] = []
        for key, value in fields.items():
            if value is None:
                continue
            parts.append(f"{key}={_escape_extension_value(str(value))}")
        return " ".join(parts)
