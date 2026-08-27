"""FastAPI application factory and exception handlers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.exceptions import (
    AuditLogError,
    AuthenticationError,
    AuthorizationError,
    ConcurrentModificationError,
    KronOSException,
    StorageError,
    StorageQuotaExceededError,
    ValidationError,
)
from src.external.logging_config import configure_logging
from src.external.routes import admin as admin_routes
from src.external.routes import admin_connector_status as admin_connector_status_routes
from src.external.routes import admin_integration_sources as admin_integration_sources_routes
from src.external.routes import audit as audit_routes
from src.external.routes import auth as auth_routes
from src.external.routes import cases as cases_routes
from src.external.routes import detections as detections_routes
from src.external.routes import evidence as evidence_routes
from src.external.routes import integration_source_push as integration_source_push_routes
from src.external.routes import sse as sse_routes
from src.external.routes import step_up as step_up_routes

# Configure structured JSON logging as early as possible (module import time)
# so every log emitted during app startup — not just requests — is rendered
# as JSON (COMP-8). Safe to call at import time: configure_logging() only
# reads env vars and mutates the stdlib logging root logger/structlog global
# config, it does not depend on FastAPI or any request-scoped state.
configure_logging()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Wire real database/storage dependencies on startup when env vars are set."""
    import os  # noqa: PLC0415

    if os.getenv("DATABASE_URL"):
        try:
            from src.external.startup import wire_dependencies_async  # noqa: PLC0415

            await wire_dependencies_async()
        except Exception as exc:  # noqa: BLE001
            import logging  # noqa: PLC0415

            logging.getLogger(__name__).warning("startup wiring failed: %s", exc)
    yield


_DEFAULT_CORS_ORIGINS = ["http://localhost", "http://localhost:5173", "http://localhost:4173"]


def create_app(
    keycloak_issuer: str | None = None,
    keycloak_audience: str = "kronos-backend",
    keycloak_jwks_url: str | None = None,
    step_up_ticket_store: Any | None = None,
    cors_allowed_origins: list[str] | None = None,
) -> FastAPI:
    """Construct and configure the KronOS FastAPI application.

    When *keycloak_issuer* and *keycloak_jwks_url* are provided the JWT
    validator is registered in ``app.state.keycloak_validator`` so the
    ``get_tenant_context`` dependency can use it.  Tests may omit these
    and override ``get_tenant_context`` via ``app.dependency_overrides``.

    *step_up_ticket_store* (a ``TicketStore``) wires step-up tickets into a
    shared backend (e.g. ``RedisTicketStore``); when omitted, the process-local
    in-memory store is used. Production with multiple replicas must pass a Redis
    store (build it with ``dependencies.build_step_up_ticket_store(settings)``).
    """
    if step_up_ticket_store is not None:
        from src.external.dependencies import configure_step_up_auth  # noqa: PLC0415

        configure_step_up_auth(step_up_ticket_store)

    app = FastAPI(
        title="KronOS",
        description="Forensically sound, multi-tenant evidence management platform",
        version="0.1.0",
        lifespan=_lifespan,
    )

    if keycloak_issuer and keycloak_jwks_url:
        from src.external.middleware.keycloak_auth import KeycloakTokenValidator  # noqa: PLC0415

        app.state.keycloak_validator = KeycloakTokenValidator(
            issuer=keycloak_issuer,
            audience=keycloak_audience,
            jwks_url=keycloak_jwks_url,
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_allowed_origins or _DEFAULT_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_routes.router)
    app.include_router(cases_routes.router)
    app.include_router(evidence_routes.router)
    app.include_router(detections_routes.router)
    app.include_router(admin_routes.router)
    app.include_router(admin_integration_sources_routes.router)
    app.include_router(admin_connector_status_routes.router)
    app.include_router(audit_routes.router)
    app.include_router(sse_routes.router)
    app.include_router(step_up_routes.router)
    app.include_router(integration_source_push_routes.router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        """Liveness/readiness probe target.

        Deliberately dependency-free (no DB/OpenSearch/etc. check): this
        endpoint backs BOTH the Kubernetes liveness and readiness probes
        (charts/kronos/templates/backend/deployment.yaml) and nginx's
        /healthz proxy (docker/nginx/nginx.conf.template) -- a liveness
        probe that depends on an external service causes Kubernetes to
        kill and restart an otherwise-healthy process during a transient
        downstream outage. Real, verified gap this closes: no such route
        existed at all before, so every one of those probes always 404'd
        (docs/verification-pass-findings.md finding G).
        """
        return {"status": "ok"}

    _register_exception_handlers(app)

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": str(exc), "context": exc.context},
        )

    @app.exception_handler(AuthenticationError)
    async def auth_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(AuthorizationError)
    async def authz_error_handler(request: Request, exc: AuthorizationError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(StorageError)
    async def storage_error_handler(request: Request, exc: StorageError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    # Gap Audit 2026-08-28 (real bug, found via a real E2E test, not just
    # inspection): a concurrent-modification race (e.g. two analysts
    # triaging the same Detection near-simultaneously) previously fell
    # through to the generic StorageError handler above -> 503, wrongly
    # indistinguishable from an actual infra outage. Registered before/
    # independent of detections.py's own route-level catch, mirroring
    # StorageQuotaExceededError's own precedent immediately below for the
    # same "defense in depth for any future call site without its own
    # try/except" reasoning. Must be registered so Starlette's exact-type
    # lookup prefers this over the parent StorageError handler above.
    @app.exception_handler(ConcurrentModificationError)
    async def concurrent_modification_handler(
        request: Request, exc: ConcurrentModificationError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    # Registered before/independent of evidence.py's own route-level catch
    # (defense in depth for any future call site that raises this without
    # its own try/except) -- see that route's comment for the 413-not-409
    # reasoning.
    @app.exception_handler(StorageQuotaExceededError)
    async def quota_exceeded_handler(
        request: Request, exc: StorageQuotaExceededError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=413,
            content={"detail": {"message": str(exc), **exc.context}},
        )

    @app.exception_handler(AuditLogError)
    async def audit_error_handler(request: Request, exc: AuditLogError) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.exception_handler(KronOSException)
    async def kronos_error_handler(request: Request, exc: KronOSException) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})


# Module-level instance for uvicorn/gunicorn entrypoints.
# Wire Keycloak from environment variables when present.
import os as _os  # noqa: E402

# KEYCLOAK_PUBLIC_URL is the browser-visible URL (token issuer claim).
# KEYCLOAK_URL is the Docker-internal URL used to fetch JWKS.
_keycloak_internal_url = _os.getenv("KEYCLOAK_URL", "")
_keycloak_public_url = _os.getenv("KEYCLOAK_PUBLIC_URL", _keycloak_internal_url)
_keycloak_realm = _os.getenv("KEYCLOAK_REALM", "kronos")
_keycloak_issuer = (
    f"{_keycloak_public_url}/realms/{_keycloak_realm}" if _keycloak_public_url else None
)
_keycloak_jwks = (
    f"{_keycloak_internal_url}/realms/{_keycloak_realm}/protocol/openid-connect/certs"
    if _keycloak_internal_url
    else None
)

# Read directly via os.getenv (not Settings()) so this module stays
# importable without a full env — tests construct create_app() directly
# and override as needed. Must match MINIO_API_CORS_ALLOW_ORIGIN on the
# MinIO server (docker-compose*.yml) — same origins, enforced
# independently by each server.
_cors_allowed_origins = [
    origin.strip()
    for origin in _os.getenv("CORS_ALLOWED_ORIGINS", ",".join(_DEFAULT_CORS_ORIGINS)).split(",")
    if origin.strip()
]

app = create_app(
    keycloak_issuer=_keycloak_issuer,
    keycloak_jwks_url=_keycloak_jwks,
    cors_allowed_origins=_cors_allowed_origins,
)
