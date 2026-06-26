"""FastAPI application factory and exception handlers."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.exceptions import (
    AuditLogError,
    AuthenticationError,
    AuthorizationError,
    KronOSException,
    StorageError,
    ValidationError,
)
from src.external.routes import admin as admin_routes
from src.external.routes import audit as audit_routes
from src.external.routes import auth as auth_routes
from src.external.routes import cases as cases_routes
from src.external.routes import evidence as evidence_routes
from src.external.routes import sse as sse_routes


def create_app(
    keycloak_issuer: str | None = None,
    keycloak_audience: str = "kronos-backend",
    keycloak_jwks_url: str | None = None,
    step_up_ticket_store: Any | None = None,
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
        allow_origins=["http://localhost", "http://localhost:5173", "http://localhost:4173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_routes.router)
    app.include_router(cases_routes.router)
    app.include_router(evidence_routes.router)
    app.include_router(admin_routes.router)
    app.include_router(audit_routes.router)
    app.include_router(sse_routes.router)
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

    @app.exception_handler(AuditLogError)
    async def audit_error_handler(request: Request, exc: AuditLogError) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.exception_handler(KronOSException)
    async def kronos_error_handler(request: Request, exc: KronOSException) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})


# Module-level instance for uvicorn/gunicorn entrypoints.
app = create_app()
