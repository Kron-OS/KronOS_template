"""Dependency injection container for FastAPI.

Repositories, services, and scanners are registered here.  Tests override
bindings via FastAPI's ``app.dependency_overrides`` or by calling
``configure_dependencies()`` with test doubles.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from src.adapter.repository.audit_log import AuditLogRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.scanning import AntivirusScanner, NoOpScanner
from src.application.validation import EvidenceValidator, default_validator_chain
from src.domain.user import Role, TenantContext

# ---------------------------------------------------------------------------
# Singleton configuration store — only one instance, set at startup.
# ---------------------------------------------------------------------------

_audit_log_repository: AuditLogRepository | None = None
_evidence_repository: EvidenceRepository | None = None
_evidence_storage: EvidenceStorage | None = None
_scanner: AntivirusScanner = NoOpScanner()
_max_upload_bytes: int = 1_073_741_824
_presigned_expiry: int = 3600


# ---------------------------------------------------------------------------
# Repository / storage providers
# ---------------------------------------------------------------------------


def get_audit_log_repository() -> AuditLogRepository:
    if _audit_log_repository is None:
        raise RuntimeError(
            "AuditLogRepository is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _audit_log_repository


def get_evidence_repository() -> EvidenceRepository:
    if _evidence_repository is None:
        raise RuntimeError(
            "EvidenceRepository is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _evidence_repository


def get_evidence_storage() -> EvidenceStorage:
    if _evidence_storage is None:
        raise RuntimeError(
            "EvidenceStorage is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _evidence_storage


def get_scanner() -> AntivirusScanner:
    return _scanner


# ---------------------------------------------------------------------------
# Service providers (constructed fresh per-request — cheap, stateless)
# ---------------------------------------------------------------------------


def get_audit_log_service(
    repository: Annotated[AuditLogRepository, Depends(get_audit_log_repository)],
) -> AuditLogService:
    return AuditLogService(repository)


def get_validator() -> EvidenceValidator:
    return default_validator_chain(_max_upload_bytes)


def get_intake_service(
    evidence_repository: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    storage: Annotated[EvidenceStorage, Depends(get_evidence_storage)],
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
    validator: Annotated[EvidenceValidator, Depends(get_validator)],
    scanner: Annotated[AntivirusScanner, Depends(get_scanner)],
) -> EvidenceIntakeService:
    return EvidenceIntakeService(
        evidence_repository=evidence_repository,
        storage=storage,
        audit_log=audit_log,
        validator=validator,
        scanner=scanner,
        hash_service=HashService(),
        max_upload_bytes=_max_upload_bytes,
        presigned_url_expiry_seconds=_presigned_expiry,
    )


# ---------------------------------------------------------------------------
# Placeholder auth dependency — replaced by Keycloak JWT parsing in Phase 5.
#
# Reads org/user identity from HTTP headers so routes are testable without
# a running Keycloak instance.  The header names mirror what the Phase 5
# JWT middleware will populate after token verification.
# ---------------------------------------------------------------------------


def get_tenant_context(
    x_org_id: Annotated[str, Header(description="Organization UUID")] = "",
    x_org_alias: Annotated[str, Header(description="Organization alias")] = "",
    x_user_id: Annotated[str, Header(description="User UUID")] = "",
    x_username: Annotated[str, Header(description="Username")] = "",
    x_roles: Annotated[str, Header(description="Comma-separated roles")] = "analyst",
    x_correlation_id: Annotated[str, Header(description="Request correlation ID")] = "",
) -> TenantContext:
    """Extract TenantContext from request headers (Phase 2 placeholder).

    In Phase 5 this function is replaced by JWT-based extraction.  The header
    shape is identical to what the JWT middleware will populate, so routes
    require zero changes at that point.
    """
    try:
        org_id = uuid.UUID(x_org_id)
        user_id = uuid.UUID(x_user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid auth headers",
        ) from exc

    raw_roles = {r.strip() for r in x_roles.split(",") if r.strip()}
    roles: frozenset[Role] = frozenset()
    try:
        roles = frozenset(Role(r) for r in raw_roles)
    except ValueError:
        pass

    return TenantContext(
        org_id=org_id,
        org_alias=x_org_alias or "unknown",
        user_id=user_id,
        username=x_username or "unknown",
        roles=roles,
        correlation_id=x_correlation_id or str(uuid.uuid4()),
    )


# ---------------------------------------------------------------------------
# Runtime configuration — called once at application startup.
# ---------------------------------------------------------------------------


def configure_dependencies(
    audit_log_repository: AuditLogRepository,
    evidence_repository: EvidenceRepository,
    evidence_storage: EvidenceStorage,
    scanner: AntivirusScanner | None = None,
    max_upload_bytes: int = 1_073_741_824,
    presigned_expiry_seconds: int = 3600,
) -> None:
    """Wire concrete implementations into the container."""
    global _audit_log_repository, _evidence_repository, _evidence_storage
    global _scanner, _max_upload_bytes, _presigned_expiry
    _audit_log_repository = audit_log_repository
    _evidence_repository = evidence_repository
    _evidence_storage = evidence_storage
    if scanner is not None:
        _scanner = scanner
    _max_upload_bytes = max_upload_bytes
    _presigned_expiry = presigned_expiry_seconds


def reset_dependencies() -> None:
    """Reset all dependency bindings — used only in tests."""
    global _audit_log_repository, _evidence_repository, _evidence_storage, _scanner
    global _max_upload_bytes, _presigned_expiry
    _audit_log_repository = None
    _evidence_repository = None
    _evidence_storage = None
    _scanner = NoOpScanner()
    _max_upload_bytes = 1_073_741_824
    _presigned_expiry = 3600
