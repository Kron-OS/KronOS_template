"""Dependency injection container for FastAPI.

Repositories and services are registered here; tests override bindings
via FastAPI's ``app.dependency_overrides`` without touching production code.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from src.adapter.repository.audit_log import AuditLogRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage
from src.application.audit_log import AuditLogService

# ---------------------------------------------------------------------------
# Repository providers — replaced in tests via app.dependency_overrides
# ---------------------------------------------------------------------------

_audit_log_repository: AuditLogRepository | None = None
_evidence_repository: EvidenceRepository | None = None
_evidence_storage: EvidenceStorage | None = None


def get_audit_log_repository() -> AuditLogRepository:
    """Provide the configured AuditLogRepository."""
    if _audit_log_repository is None:
        raise RuntimeError(
            "AuditLogRepository is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _audit_log_repository


def get_evidence_repository() -> EvidenceRepository:
    """Provide the configured EvidenceRepository."""
    if _evidence_repository is None:
        raise RuntimeError(
            "EvidenceRepository is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _evidence_repository


def get_evidence_storage() -> EvidenceStorage:
    """Provide the configured EvidenceStorage."""
    if _evidence_storage is None:
        raise RuntimeError(
            "EvidenceStorage is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _evidence_storage


def get_audit_log_service(
    repository: Annotated[AuditLogRepository, Depends(get_audit_log_repository)],
) -> AuditLogService:
    """Construct AuditLogService with the injected repository."""
    return AuditLogService(repository)


# ---------------------------------------------------------------------------
# Runtime configuration — called once at application startup
# ---------------------------------------------------------------------------


def configure_dependencies(
    audit_log_repository: AuditLogRepository,
    evidence_repository: EvidenceRepository,
    evidence_storage: EvidenceStorage,
) -> None:
    """Wire concrete implementations into the container.

    Should be called exactly once, in the FastAPI lifespan event handler.
    """
    global _audit_log_repository, _evidence_repository, _evidence_storage
    _audit_log_repository = audit_log_repository
    _evidence_repository = evidence_repository
    _evidence_storage = evidence_storage


def reset_dependencies() -> None:
    """Reset all dependency bindings (used only in tests)."""
    global _audit_log_repository, _evidence_repository, _evidence_storage
    _audit_log_repository = None
    _evidence_repository = None
    _evidence_storage = None
