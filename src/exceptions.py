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


class AuditLogError(KronOSException):
    """Raised when the audit log cannot be written or read."""


class AuthenticationError(KronOSException):
    """Raised when JWT validation or Keycloak interaction fails."""


class AuthorizationError(KronOSException):
    """Raised when a user lacks the required role or scope."""


class EvidenceStateError(KronOSException):
    """Raised when an invalid FSM transition is attempted on evidence."""
