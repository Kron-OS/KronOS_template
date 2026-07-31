"""KronOS custom exception hierarchy."""


class KronOSException(Exception):  # noqa: N818
    """Base exception for all KronOS errors."""

    def __init__(self, message: str, context: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.context = context or {}


class ValidationError(KronOSException):
    """Raised when input validation fails at any boundary."""


class StorageError(KronOSException):
    """Raised on failures interacting with object storage (MinIO/S3)."""


class ParsingError(KronOSException):
    """Raised when a forensic parser cannot process evidence."""


class EvidenceStateConflictError(ParsingError):
    """Raised when evidence is not in the FSM state a parse-pipeline step requires.

    Distinct from a generic ParsingError so Celery tasks can recognize "this
    evidence will never become parseable again by retrying" and skip retry —
    see src/external/celery_app.py's except-clause ordering.
    """


class AuditLogError(KronOSException):
    """Raised when the audit log cannot be written or read."""


class AuthenticationError(KronOSException):
    """Raised when JWT validation or Keycloak interaction fails."""


class AuthorizationError(KronOSException):
    """Raised when a user lacks the required role or scope."""


class EvidenceStateError(KronOSException):
    """Raised when an invalid FSM transition is attempted on evidence."""


class DetectionStateError(KronOSException):
    """Raised when an invalid triage FSM transition is attempted on a Detection."""


class RulePackError(KronOSException):
    """Raised on rule-pack lifecycle failures: signature rejection, cost-gate
    rejection surfaced as a hard error, or publish/detector-wiring failure."""


class TimestampingError(KronOSException):
    """Raised when RFC 3161 timestamp acquisition or verification fails closed.

    Deliberately distinct from StorageError: a TSA failure must never be
    mistaken for a transient storage hiccup and silently retried into a
    fabricated success — see AUDIT-06 / COMP-3.
    """


class BatchSealFailedError(KronOSException):
    """Raised when any step of sealing a stream batch fails (roadmap M3/D3).

    The caller (``BatchSealingService``) never acks the source stream
    messages when this is raised — they remain real, pending entries in the
    consumer group so at-least-once delivery resurfaces them for the next
    seal attempt. Wraps the underlying failure (WORM write, TSA call, audit
    write, or repository persist); never fabricates partial success.
    """


class EvidenceLossDetectedError(KronOSException):
    """Raised when a stream's MAXLEN retention has trimmed events that were
    never sealed into a WORM batch (roadmap M3/D3) -- real, silent evidence
    loss, not a warning-level condition. This codebase has no real external
    paging/alerting integration today (checked: no PagerDuty/Opsgenie/
    webhook hook exists anywhere in ``src/``) -- this exception plus a
    ``logger.critical`` structured log line IS "paging" in this codebase
    until a real integration is added; documented honestly rather than
    claimed as more than it is.
    """
