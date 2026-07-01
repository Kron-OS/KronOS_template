"""Additional integration tests to push overall coverage toward 85%.

Covers:
- keycloak_auth internals (_JwksCache, _extract_tenant, _map_roles)
- query_isolation (QueryIsolationGuard)
- step_up_auth (assert_acr, wrong operation/resource)
- fastapi_app exception handlers
- dependencies (configure, reset, get_parser_registry)
- timeline_normalization (ECSNormalizer, build_index_name)
- timeline_ingest (TimelineIngestionService)
- validation (ExtensionValidator, default_validator_chain, negative size)
- tenant_context (get_tenant_context with mocked state)
- FastAPI routes (upload-request, finalize, parse, delete)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.domain.user import Role, TenantContext
from src.exceptions import AuthorizationError, ValidationError
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_case, make_evidence_metadata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tenant(
    roles: frozenset[Role] | None = None,
    acr: str = "aal1",
    org_id: uuid.UUID | None = None,
) -> TenantContext:
    return TenantContext(
        org_id=org_id or uuid.uuid4(),
        org_alias="testorg",
        user_id=uuid.uuid4(),
        username="testuser",
        roles=roles or frozenset({Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
        acr=acr,
    )


def _seed_evidence(repo: InMemoryEvidenceRepository, org_id: uuid.UUID) -> Any:
    import asyncio

    from src.domain.evidence import Evidence

    ev = Evidence(metadata=make_evidence_metadata(org_id=org_id))
    asyncio.run(repo.save(ev))
    return ev


# ---------------------------------------------------------------------------
# Tests: _JwksCache
# ---------------------------------------------------------------------------


def test_jwks_cache_is_stale_initially() -> None:
    """A freshly created _JwksCache reports staleness for any issuer."""
    from src.external.middleware.keycloak_auth import _JwksCache

    cache = _JwksCache()
    assert cache.is_stale("http://keycloak/realms/master") is True


def test_jwks_cache_update_marks_fresh() -> None:
    """After update(), is_stale() returns False for that issuer."""
    from src.external.middleware.keycloak_auth import _JwksCache

    cache = _JwksCache()
    issuer = "http://keycloak/realms/test"
    jwks = {"keys": [{"kid": "key1", "kty": "RSA", "n": "abc", "e": "AQAB"}]}
    cache.update(issuer, jwks)
    assert cache.is_stale(issuer) is False


def test_jwks_cache_get_returns_key() -> None:
    """_JwksCache.get() returns the correct key after update."""
    from src.external.middleware.keycloak_auth import _JwksCache

    cache = _JwksCache()
    issuer = "http://keycloak/realms/test"
    key_data = {"kid": "key1", "kty": "RSA", "n": "modulus", "e": "AQAB"}
    cache.update(issuer, {"keys": [key_data]})

    retrieved = cache.get(issuer, "key1")
    assert retrieved is not None
    assert retrieved["kty"] == "RSA"


def test_jwks_cache_get_unknown_kid_returns_none() -> None:
    """_JwksCache.get() returns None for an unknown kid."""
    from src.external.middleware.keycloak_auth import _JwksCache

    cache = _JwksCache()
    issuer = "http://keycloak/realms/test"
    cache.update(issuer, {"keys": [{"kid": "known-kid", "kty": "RSA"}]})
    assert cache.get(issuer, "unknown-kid") is None


def test_jwks_cache_empty_keys_list() -> None:
    """_JwksCache handles an empty keys list gracefully."""
    from src.external.middleware.keycloak_auth import _JwksCache

    cache = _JwksCache()
    issuer = "http://keycloak/realms/test"
    cache.update(issuer, {"keys": []})
    assert cache.is_stale(issuer) is False
    assert cache.get(issuer, "any") is None


# ---------------------------------------------------------------------------
# Tests: _extract_tenant
# ---------------------------------------------------------------------------


def test_extract_tenant_valid_claims() -> None:
    """_extract_tenant maps a valid claims dict to TenantContext."""
    from src.external.middleware.keycloak_auth import _extract_tenant

    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    claims = {
        "sub": str(user_id),
        "organization": {"myorg": {"id": str(org_id)}},
        "roles": ["analyst"],
        "jti": "correlation-123",
        "acr": "aal2",
        "preferred_username": "alice",
    }
    tenant = _extract_tenant(claims)
    assert tenant.org_id == org_id
    assert tenant.user_id == user_id
    assert tenant.org_alias == "myorg"
    assert Role.ANALYST in tenant.roles
    assert tenant.acr == "aal2"
    assert tenant.username == "alice"
    assert tenant.correlation_id == "correlation-123"


def test_extract_tenant_missing_organization_raises() -> None:
    """_extract_tenant raises AuthenticationError when organization claim is absent."""
    from src.exceptions import AuthenticationError
    from src.external.middleware.keycloak_auth import _extract_tenant

    claims = {"sub": str(uuid.uuid4()), "organization": {}}
    with pytest.raises(AuthenticationError):
        _extract_tenant(claims)


def test_extract_tenant_invalid_org_id_raises() -> None:
    """_extract_tenant raises AuthenticationError when org_id is not a valid UUID."""
    from src.exceptions import AuthenticationError
    from src.external.middleware.keycloak_auth import _extract_tenant

    claims = {
        "sub": str(uuid.uuid4()),
        "organization": {"badorg": {"id": "not-a-uuid"}},
    }
    with pytest.raises(AuthenticationError):
        _extract_tenant(claims)


def test_extract_tenant_missing_sub_raises() -> None:
    """_extract_tenant raises AuthenticationError when 'sub' claim is absent."""
    from src.exceptions import AuthenticationError
    from src.external.middleware.keycloak_auth import _extract_tenant

    claims = {
        "organization": {"myorg": {"id": str(uuid.uuid4())}},
    }
    with pytest.raises(AuthenticationError):
        _extract_tenant(claims)


def test_extract_tenant_defaults_acr_to_aal1() -> None:
    """_extract_tenant defaults acr to 'aal1' when not present in claims."""
    from src.external.middleware.keycloak_auth import _extract_tenant

    claims = {
        "sub": str(uuid.uuid4()),
        "organization": {"myorg": {"id": str(uuid.uuid4())}},
        "roles": [],
    }
    tenant = _extract_tenant(claims)
    assert tenant.acr == "aal1"


# ---------------------------------------------------------------------------
# Tests: _map_roles
# ---------------------------------------------------------------------------


def test_map_roles_known_values() -> None:
    """_map_roles converts recognized role strings to Role enum members."""
    from src.external.middleware.keycloak_auth import _map_roles

    result = _map_roles(["org-admin", "analyst", "read-only"])
    assert Role.ORG_ADMIN in result
    assert Role.ANALYST in result
    assert Role.READ_ONLY in result


def test_map_roles_ignores_unknown() -> None:
    """_map_roles silently ignores unrecognized role strings."""
    from src.external.middleware.keycloak_auth import _map_roles

    result = _map_roles(["super-hacker", "analyst"])
    assert len(result) == 1
    assert Role.ANALYST in result


def test_map_roles_empty_list() -> None:
    """_map_roles returns an empty list for empty input."""
    from src.external.middleware.keycloak_auth import _map_roles

    assert _map_roles([]) == []


def test_map_roles_case_lead() -> None:
    """_map_roles maps case-lead to Role.CASE_LEAD."""
    from src.external.middleware.keycloak_auth import _map_roles

    result = _map_roles(["case-lead"])
    assert Role.CASE_LEAD in result


# ---------------------------------------------------------------------------
# Tests: QueryIsolationGuard
# ---------------------------------------------------------------------------


def test_query_isolation_same_org_passes() -> None:
    """assert_org_scope does not raise when tenant and resource orgs match."""
    from src.external.middleware.query_isolation import QueryIsolationGuard

    org_id = uuid.uuid4()
    tenant = _make_tenant(org_id=org_id)
    QueryIsolationGuard.assert_org_scope(tenant, org_id)  # should not raise


def test_query_isolation_different_org_raises() -> None:
    """assert_org_scope raises AuthorizationError on org mismatch."""
    from src.external.middleware.query_isolation import QueryIsolationGuard

    tenant = _make_tenant(org_id=uuid.uuid4())
    other_org = uuid.uuid4()
    with pytest.raises(AuthorizationError):
        QueryIsolationGuard.assert_org_scope(tenant, other_org)


# ---------------------------------------------------------------------------
# Tests: StepUpAuth additional paths
# ---------------------------------------------------------------------------


def test_step_up_assert_acr_passes_aal2() -> None:
    """assert_acr passes when tenant.acr is aal2."""
    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    tenant = _make_tenant(acr="aal2")
    step_up.assert_acr(tenant)  # should not raise


def test_step_up_assert_acr_raises_for_aal1() -> None:
    """assert_acr raises 401 when tenant.acr is aal1."""
    from fastapi import HTTPException

    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    tenant = _make_tenant(acr="aal1")
    with pytest.raises(HTTPException) as exc_info:
        step_up.assert_acr(tenant)
    assert exc_info.value.status_code == 401
    assert "acr_values" in exc_info.value.headers.get("WWW-Authenticate", "")


def test_step_up_wrong_operation_raises() -> None:
    """consume_ticket raises 401 when operation does not match."""
    from fastapi import HTTPException

    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    user_id = uuid.uuid4()
    ticket_id = step_up.issue_ticket(user_id, "evidence.delete", "res1")
    with pytest.raises(HTTPException):
        step_up.consume_ticket(ticket_id, user_id, "evidence.promote", "res1")


def test_step_up_wrong_resource_raises() -> None:
    """consume_ticket raises 401 when resource_id does not match."""
    from fastapi import HTTPException

    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    user_id = uuid.uuid4()
    ticket_id = step_up.issue_ticket(user_id, "evidence.delete", "resource-A")
    with pytest.raises(HTTPException):
        step_up.consume_ticket(ticket_id, user_id, "evidence.delete", "resource-B")


def test_step_up_unknown_ticket_raises() -> None:
    """consume_ticket raises 401 for a completely unknown ticket_id."""
    from fastapi import HTTPException

    from src.external.middleware.step_up_auth import StepUpAuth

    step_up = StepUpAuth()
    with pytest.raises(HTTPException):
        step_up.consume_ticket(uuid.uuid4(), uuid.uuid4(), "evidence.delete", "res")


# ---------------------------------------------------------------------------
# Tests: FastAPI exception handlers (fastapi_app.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def _app_no_keycloak() -> FastAPI:
    from src.external.dependencies import configure_dependencies, reset_dependencies
    from src.external.fastapi_app import create_app

    reset_dependencies()
    configure_dependencies(
        audit_log_repository=InMemoryAuditLogRepository(),
        evidence_repository=InMemoryEvidenceRepository(),
        evidence_storage=_NoopStorage(),
    )
    return create_app()


class _NoopStorage:
    async def request_presigned_upload(self, evidence, expires_in_seconds=3600):
        from src.adapter.storage.storage import PresignedUploadResponse

        return PresignedUploadResponse("http://fake/upload", "key/test", expires_in_seconds)

    async def stream_object(self, object_key, chunk_size=65536, *, bucket="quarantine"):
        yield b"\x00" * 16

    async def promote_to_evidence_bucket(self, quarantine_key, evidence):
        return f"evidence/{evidence.evidence_id}"

    async def delete_from_quarantine(self, quarantine_key):
        pass

    async def object_exists(self, object_key, *, bucket="quarantine"):
        return True


def test_create_app_with_keycloak_params() -> None:
    """create_app sets keycloak_validator in app.state when params are provided."""
    from src.external.dependencies import configure_dependencies, reset_dependencies
    from src.external.fastapi_app import create_app
    from src.external.middleware.keycloak_auth import KeycloakTokenValidator

    reset_dependencies()
    configure_dependencies(
        audit_log_repository=InMemoryAuditLogRepository(),
        evidence_repository=InMemoryEvidenceRepository(),
        evidence_storage=_NoopStorage(),
    )
    app = create_app(
        keycloak_issuer="http://kc/realms/master",
        keycloak_audience="kronos-backend",
        keycloak_jwks_url="http://kc/realms/master/.well-known/jwks.json",
    )
    assert hasattr(app.state, "keycloak_validator")
    assert isinstance(app.state.keycloak_validator, KeycloakTokenValidator)
    reset_dependencies()


def test_validation_error_returns_422(_app_no_keycloak: FastAPI) -> None:
    """ValidationError is mapped to HTTP 422."""
    from src.exceptions import ValidationError as KronOSValidationError
    from src.external.dependencies import get_tenant_context

    tenant = _make_tenant()
    _app_no_keycloak.dependency_overrides[get_tenant_context] = lambda: tenant

    @_app_no_keycloak.get("/test-validation-error")
    async def _raise_validation() -> None:
        raise KronOSValidationError("bad file", context={"detail": "test"})

    with TestClient(_app_no_keycloak, raise_server_exceptions=False) as client:
        resp = client.get("/test-validation-error")
    assert resp.status_code == 422
    assert "bad file" in resp.json()["detail"]


def test_authentication_error_returns_401(_app_no_keycloak: FastAPI) -> None:
    """AuthenticationError is mapped to HTTP 401."""
    from src.exceptions import AuthenticationError
    from src.external.dependencies import get_tenant_context

    tenant = _make_tenant()
    _app_no_keycloak.dependency_overrides[get_tenant_context] = lambda: tenant

    @_app_no_keycloak.get("/test-auth-error")
    async def _raise_auth() -> None:
        raise AuthenticationError("bad token")

    with TestClient(_app_no_keycloak, raise_server_exceptions=False) as client:
        resp = client.get("/test-auth-error")
    assert resp.status_code == 401


def test_authorization_error_returns_403(_app_no_keycloak: FastAPI) -> None:
    """AuthorizationError is mapped to HTTP 403."""
    from src.exceptions import AuthorizationError
    from src.external.dependencies import get_tenant_context

    tenant = _make_tenant()
    _app_no_keycloak.dependency_overrides[get_tenant_context] = lambda: tenant

    @_app_no_keycloak.get("/test-authz-error")
    async def _raise_authz() -> None:
        raise AuthorizationError("forbidden", context={})

    with TestClient(_app_no_keycloak, raise_server_exceptions=False) as client:
        resp = client.get("/test-authz-error")
    assert resp.status_code == 403


def test_storage_error_returns_503(_app_no_keycloak: FastAPI) -> None:
    """StorageError is mapped to HTTP 503."""
    from src.exceptions import StorageError
    from src.external.dependencies import get_tenant_context

    tenant = _make_tenant()
    _app_no_keycloak.dependency_overrides[get_tenant_context] = lambda: tenant

    @_app_no_keycloak.get("/test-storage-error")
    async def _raise_storage() -> None:
        raise StorageError("s3 unavailable", context={})

    with TestClient(_app_no_keycloak, raise_server_exceptions=False) as client:
        resp = client.get("/test-storage-error")
    assert resp.status_code == 503


def test_generic_kronos_error_returns_500(_app_no_keycloak: FastAPI) -> None:
    """Generic KronOSException is mapped to HTTP 500."""
    from src.exceptions import KronOSException
    from src.external.dependencies import get_tenant_context

    tenant = _make_tenant()
    _app_no_keycloak.dependency_overrides[get_tenant_context] = lambda: tenant

    @_app_no_keycloak.get("/test-kronos-error")
    async def _raise_kronos() -> None:
        raise KronOSException("something broke")

    with TestClient(_app_no_keycloak, raise_server_exceptions=False) as client:
        resp = client.get("/test-kronos-error")
    assert resp.status_code == 500


# ---------------------------------------------------------------------------
# Tests: dependencies module
# ---------------------------------------------------------------------------


def test_configure_and_reset_dependencies() -> None:
    """configure_dependencies sets repositories; reset_dependencies clears them."""
    from src.external.dependencies import (
        configure_dependencies,
        get_audit_log_repository,
        get_evidence_repository,
        reset_dependencies,
    )

    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()

    configure_dependencies(
        audit_log_repository=audit_repo,
        evidence_repository=evidence_repo,
        evidence_storage=_NoopStorage(),
    )

    assert get_audit_log_repository() is audit_repo
    assert get_evidence_repository() is evidence_repo

    reset_dependencies()

    with pytest.raises(RuntimeError):
        get_audit_log_repository()


def test_get_parser_registry_returns_registry() -> None:
    """get_parser_registry returns a ParserRegistry with registered parsers."""
    from src.application.parser_registry import ParserRegistry
    from src.external.dependencies import get_parser_registry, reset_dependencies

    reset_dependencies()
    registry = get_parser_registry()
    assert isinstance(registry, ParserRegistry)


def test_get_parser_registry_is_idempotent() -> None:
    """Calling get_parser_registry twice returns the same instance."""
    from src.external.dependencies import get_parser_registry, reset_dependencies

    reset_dependencies()
    r1 = get_parser_registry()
    r2 = get_parser_registry()
    assert r1 is r2


def test_unconfigured_storage_raises() -> None:
    """get_evidence_storage raises RuntimeError when not configured."""
    from src.external.dependencies import get_evidence_storage, reset_dependencies

    reset_dependencies()
    with pytest.raises(RuntimeError):
        get_evidence_storage()


# ---------------------------------------------------------------------------
# Tests: timeline_normalization
# ---------------------------------------------------------------------------


def _make_record(org_id: uuid.UUID | None = None) -> Any:
    from tests.fixtures.factories import make_timeline_record

    record = make_timeline_record()
    # Return as-is; the factory uses proper list types for event_category/event_type
    return record


def test_ecs_normalizer_produces_required_keys() -> None:
    """ECSNormalizer.to_document() always emits @timestamp and kronos block."""
    from src.application.timeline_normalization import ECSNormalizer

    normalizer = ECSNormalizer()
    record = _make_record()
    doc = normalizer.to_document(record)

    assert "@timestamp" in doc
    assert "kronos" in doc
    assert "evidence_id" in doc["kronos"]
    assert "org_id" in doc["kronos"]


def test_ecs_normalizer_strips_none_values() -> None:
    """ECSNormalizer omits None-valued fields from the document."""
    from src.application.timeline_normalization import ECSNormalizer

    normalizer = ECSNormalizer()
    record = _make_record()
    doc = normalizer.to_document(record)

    def _has_none(obj: Any) -> bool:
        if isinstance(obj, dict):
            return any(v is None or _has_none(v) for v in obj.values())
        return False

    assert not _has_none(doc)


def test_ecs_normalizer_extra_dotted_key_expanded() -> None:
    """Extra dotted keys in record.extra are expanded into nested dicts."""
    from src.application.timeline_normalization import ECSNormalizer
    from src.domain.timeline import KronosProvenance, TimelineRecord

    normalizer = ECSNormalizer()
    record = TimelineRecord(
        **{
            "@timestamp": datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC),
            "message": "GET /api 200",
            "event.kind": "event",
            "event.category": ["web"],
            "event.type": ["access"],
        },
        extra={"http.response.status_code": 200},
        kronos=KronosProvenance(
            evidence_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            org_alias="testorg",
            sha256="a" * 64,
            parser="nginx",
            parser_version="1.0",
            record_index=0,
            ingest_timestamp=datetime.now(UTC),
        ),
    )
    doc = normalizer.to_document(record)

    # "http.response.status_code" should be under doc["http"]["response"]["status_code"]
    assert "http" in doc
    assert doc["http"]["response"]["status_code"] == 200


def test_build_index_name_format() -> None:
    """build_index_name returns the expected monthly index pattern."""
    from src.application.timeline_normalization import build_index_name

    case_id = str(uuid.uuid4())
    ts = datetime(2026, 6, 15, tzinfo=UTC)
    name = build_index_name("MyOrg", case_id, ts)

    assert name.startswith("kronos-")
    assert "case-" in name
    assert name.endswith("-202606")


def test_build_index_name_sanitizes_org_alias() -> None:
    """build_index_name lowercases and replaces non-alphanumeric chars with hyphens."""
    from src.application.timeline_normalization import build_index_name

    ts = datetime(2026, 1, 1, tzinfo=UTC)
    name = build_index_name("Acme Corp!", "case-id", ts)

    assert "acme-corp-" in name


# ---------------------------------------------------------------------------
# Tests: timeline_ingest (TimelineIngestionService)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timeline_ingest_returns_record_count() -> None:
    """TimelineIngestionService.ingest_records returns correct count."""
    from src.adapter.opensearch.client import InMemoryOpenSearchClient
    from src.application.audit_log import AuditLogService
    from src.application.timeline_ingest import TimelineIngestionService

    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    opensearch = InMemoryOpenSearchClient()
    service = TimelineIngestionService(opensearch=opensearch, audit_log=audit_log)

    tenant = _make_tenant()

    async def _records():
        for i in range(5):
            record = _make_record(org_id=tenant.org_id)
            # Give each record the right org alias and a unique index
            yield record

    evidence_id = uuid.uuid4()
    count = await service.ingest_records(_records(), tenant, evidence_id)
    assert count == 5


@pytest.mark.asyncio
async def test_timeline_ingest_stores_in_opensearch() -> None:
    """Records are actually stored in InMemoryOpenSearchClient."""
    from src.adapter.opensearch.client import InMemoryOpenSearchClient
    from src.application.audit_log import AuditLogService
    from src.application.timeline_ingest import TimelineIngestionService

    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    opensearch = InMemoryOpenSearchClient()
    service = TimelineIngestionService(opensearch=opensearch, audit_log=audit_log)

    tenant = _make_tenant()

    async def _records():
        yield _make_record(org_id=tenant.org_id)

    await service.ingest_records(_records(), tenant, uuid.uuid4())
    assert opensearch.total_documents() == 1


@pytest.mark.asyncio
async def test_timeline_ingest_audit_events_emitted() -> None:
    """INGEST_STARTED and INGEST_COMPLETED are both logged."""
    from src.adapter.opensearch.client import InMemoryOpenSearchClient
    from src.application.audit_log import AuditLogService
    from src.application.timeline_ingest import TimelineIngestionService
    from src.domain.audit import AuditEventType

    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    opensearch = InMemoryOpenSearchClient()
    service = TimelineIngestionService(opensearch=opensearch, audit_log=audit_log)

    tenant = _make_tenant()

    async def _records():
        yield _make_record(org_id=tenant.org_id)

    await service.ingest_records(_records(), tenant, uuid.uuid4())

    event_types = [e.event_type for e in audit_repo.events]
    assert AuditEventType.INGEST_STARTED in event_types
    assert AuditEventType.INGEST_COMPLETED in event_types


@pytest.mark.asyncio
async def test_timeline_ingest_batch_flush() -> None:
    """Records are flushed in batches; all arrive in OpenSearch."""
    from src.adapter.opensearch.client import InMemoryOpenSearchClient
    from src.application.audit_log import AuditLogService
    from src.application.timeline_ingest import TimelineIngestionService

    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    opensearch = InMemoryOpenSearchClient()
    # Tiny batch size to force multiple flushes
    service = TimelineIngestionService(opensearch=opensearch, audit_log=audit_log, batch_size=3)

    tenant = _make_tenant()

    async def _records():
        for _ in range(7):
            yield _make_record(org_id=tenant.org_id)

    count = await service.ingest_records(_records(), tenant, uuid.uuid4())
    assert count == 7
    assert opensearch.total_documents() == 7


# ---------------------------------------------------------------------------
# Tests: validation (ExtensionValidator, negative size, default_validator_chain)
# ---------------------------------------------------------------------------


def test_extension_validator_blocks_exe() -> None:
    """ExtensionValidator rejects .exe files."""
    from src.application.validation import ExtensionValidator

    validator = ExtensionValidator()
    with pytest.raises(ValidationError):
        validator.validate("malware.exe", "application/octet-stream", 100, b"MZ")


def test_extension_validator_allows_evtx() -> None:
    """ExtensionValidator allows .evtx files."""
    from src.application.validation import ExtensionValidator

    validator = ExtensionValidator()
    validator.validate("log.evtx", "application/x-evtx", 100, b"ElfFile\x00")


def test_extension_validator_blocks_dll() -> None:
    """ExtensionValidator rejects .dll files."""
    from src.application.validation import ExtensionValidator

    validator = ExtensionValidator()
    with pytest.raises(ValidationError):
        validator.validate("evil.dll", "application/octet-stream", 100, b"MZ")


def test_file_size_validator_negative_raises() -> None:
    """FileSizeValidator rejects negative size."""
    from src.application.validation import FileSizeValidator

    validator = FileSizeValidator(max_bytes=1_000_000)
    with pytest.raises(ValidationError):
        validator.validate("test.log", "text/plain", -1, b"x")


def test_magic_byte_validator_accepts_text_extension() -> None:
    """MagicByteValidator accepts .json without binary magic."""
    from src.application.validation import MagicByteValidator

    validator = MagicByteValidator()
    validator.validate("cloudtrail.json", "application/json", 100, b"{}")


def test_magic_byte_validator_rejects_empty_file() -> None:
    """MagicByteValidator rejects empty header bytes for binary extensions."""
    from src.application.validation import MagicByteValidator

    validator = MagicByteValidator()
    with pytest.raises(ValidationError):
        validator.validate("data.evtx", "application/x-evtx", 0, b"")


def test_default_validator_chain_accepts_evtx() -> None:
    """default_validator_chain accepts a valid EVTX file."""
    from src.application.validation import default_validator_chain

    chain = default_validator_chain(max_upload_bytes=10_000_000)
    data = b"ElfFile\x00" + b"\x00" * 50
    chain.validate("test.evtx", "application/x-evtx", len(data), data)


def test_default_validator_chain_rejects_exe() -> None:
    """default_validator_chain rejects an .exe file at the extension stage."""
    from src.application.validation import default_validator_chain

    chain = default_validator_chain(max_upload_bytes=10_000_000)
    with pytest.raises(ValidationError):
        chain.validate("payload.exe", "application/octet-stream", 100, b"MZ")


def test_default_validator_chain_rejects_oversized() -> None:
    """default_validator_chain rejects a file that exceeds max_upload_bytes."""
    from src.application.validation import default_validator_chain

    chain = default_validator_chain(max_upload_bytes=100)
    with pytest.raises(ValidationError):
        chain.validate("big.evtx", "application/x-evtx", 200, b"ElfFile\x00" + b"\x00" * 50)


# ---------------------------------------------------------------------------
# Tests: tenant_context dependency (get_tenant_context)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_tenant_context_with_valid_validator() -> None:
    """get_tenant_context extracts TenantContext from a mocked validator."""
    from fastapi import Request
    from fastapi.security import HTTPAuthorizationCredentials

    from src.external.middleware.tenant_context import get_tenant_context

    expected_tenant = _make_tenant()
    mock_validator = AsyncMock()
    mock_validator.validate_and_extract.return_value = expected_tenant

    mock_request = MagicMock(spec=Request)
    mock_request.app.state.keycloak_validator = mock_validator

    mock_credentials = MagicMock(spec=HTTPAuthorizationCredentials)
    mock_credentials.credentials = "fake.jwt.token"

    tenant = await get_tenant_context(request=mock_request, credentials=mock_credentials)
    assert tenant.org_id == expected_tenant.org_id
    mock_validator.validate_and_extract.assert_called_once_with("fake.jwt.token")


@pytest.mark.asyncio
async def test_get_tenant_context_auth_error_becomes_401() -> None:
    """get_tenant_context converts AuthenticationError to HTTP 401."""
    from fastapi import HTTPException, Request
    from fastapi.security import HTTPAuthorizationCredentials

    from src.exceptions import AuthenticationError
    from src.external.middleware.tenant_context import get_tenant_context

    mock_validator = AsyncMock()
    mock_validator.validate_and_extract.side_effect = AuthenticationError("bad token")

    mock_request = MagicMock(spec=Request)
    mock_request.app.state.keycloak_validator = mock_validator

    mock_credentials = MagicMock(spec=HTTPAuthorizationCredentials)
    mock_credentials.credentials = "expired.jwt.token"

    with pytest.raises(HTTPException) as exc_info:
        await get_tenant_context(request=mock_request, credentials=mock_credentials)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Tests: FastAPI evidence routes (upload-request, finalize, parse-start)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_deps_fixture():
    from src.external.dependencies import reset_dependencies

    reset_dependencies()
    yield
    reset_dependencies()


@pytest.fixture
def _app_with_deps():
    from src.adapter.repository.case_repository import InMemoryCaseRepository
    from src.external.dependencies import configure_dependencies
    from src.external.fastapi_app import create_app
    from src.external.middleware.step_up_auth import StepUpAuth

    audit_repo = InMemoryAuditLogRepository()
    evidence_repo = InMemoryEvidenceRepository()
    case_repo = InMemoryCaseRepository()
    storage = _NoopStorage()
    configure_dependencies(
        audit_log_repository=audit_repo,
        evidence_repository=evidence_repo,
        evidence_storage=storage,
        case_repository=case_repo,
    )
    app = create_app()
    step_up = StepUpAuth()

    from src.external.dependencies import get_step_up_auth, get_tenant_context

    tenant = _make_tenant(roles=frozenset({Role.ORG_ADMIN}), acr="aal2")
    app.dependency_overrides[get_tenant_context] = lambda: tenant
    app.dependency_overrides[get_step_up_auth] = lambda: step_up
    return app, audit_repo, evidence_repo, case_repo, step_up, tenant


def test_upload_request_returns_presigned_url(_app_with_deps) -> None:
    """POST /api/evidence/upload/request returns 201 with upload URL."""
    import asyncio

    app, _, _, case_repo, _, tenant = _app_with_deps
    case = make_case(org_id=tenant.org_id)
    asyncio.run(case_repo.save(case))

    with TestClient(app) as client:
        resp = client.post(
            "/api/evidence/upload/request",
            json={
                "filename": "test.evtx",
                "contentType": "application/x-evtx",
                "sizeBytes": 1024,
                "caseId": str(case.case_id),
            },
        )
    assert resp.status_code == 201
    data = resp.json()
    assert "presignedUrl" in data
    assert "evidenceId" in data


def test_upload_request_missing_fields_returns_422(_app_with_deps) -> None:
    """POST /api/evidence/upload/request returns 422 when required fields are missing."""
    app, _, _, _, _, _ = _app_with_deps
    with TestClient(app) as client:
        resp = client.post(
            "/api/evidence/upload/request",
            json={"filename": "test.evtx"},  # missing contentType, sizeBytes, caseId
        )
    assert resp.status_code == 422


def test_parse_start_422_for_evidence_no_storage_key(_app_with_deps) -> None:
    """POST /api/evidence/parse/start/{id} returns 422 when evidence has no storage key."""
    import asyncio

    from src.domain.evidence import Evidence, EvidenceState

    app, _, evidence_repo, _, _, tenant = _app_with_deps

    ev = Evidence(
        metadata=make_evidence_metadata(org_id=tenant.org_id),
        state=EvidenceState.RECEIVED,
    )
    asyncio.run(evidence_repo.save(ev))

    with TestClient(app) as client:
        resp = client.post(f"/api/evidence/parse/start/{ev.evidence_id}")
    # ParsingError ("no storage key") → 422
    assert resp.status_code == 422


def test_parse_start_422_for_unknown_evidence(_app_with_deps) -> None:
    """POST /api/evidence/parse/start/{id} returns 422 for unknown evidence (ValidationError)."""
    app, _, _, _, _, _ = _app_with_deps
    with TestClient(app) as client:
        resp = client.post(f"/api/evidence/parse/start/{uuid.uuid4()}")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Tests: OpenSearch isolation (opensearch_isolation.py)
# ---------------------------------------------------------------------------


def test_opensearch_isolation_second_query_also_filtered() -> None:
    """OpenSearchQueryBuilder wraps multiple distinct queries consistently."""
    from src.external.middleware.opensearch_isolation import OpenSearchQueryBuilder

    tenant = _make_tenant()
    builder = OpenSearchQueryBuilder(tenant)

    q1 = builder.build({"query": {"match": {"event.action": "login"}}})
    q2 = builder.build({"query": {"match": {"event.outcome": "failure"}}})

    for q in (q1, q2):
        filters = q["query"]["bool"]["filter"]
        assert any("term" in f and "kronos.org_id" in f.get("term", {}) for f in filters)


def test_opensearch_isolation_org_id_value() -> None:
    """The injected org_id filter uses the exact tenant UUID string."""
    from src.external.middleware.opensearch_isolation import OpenSearchQueryBuilder

    org_id = uuid.uuid4()
    tenant = _make_tenant(org_id=org_id)
    builder = OpenSearchQueryBuilder(tenant)
    wrapped = builder.build({"query": {"match_all": {}}})

    filters = wrapped["query"]["bool"]["filter"]
    org_terms = [
        f["term"]["kronos.org_id"]
        for f in filters
        if "term" in f and "kronos.org_id" in f.get("term", {})
    ]
    assert len(org_terms) == 1
    assert org_terms[0] == str(org_id)
