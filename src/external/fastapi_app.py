"""FastAPI application factory and exception handlers."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.exceptions import (
    AuditLogError,
    AuthenticationError,
    AuthorizationError,
    KronOSException,
    StorageError,
    ValidationError,
)
from src.external.routes import evidence as evidence_routes


def create_app() -> FastAPI:
    """Construct and configure the KronOS FastAPI application."""
    app = FastAPI(
        title="KronOS",
        description="Forensically sound, multi-tenant evidence management platform",
        version="0.1.0",
    )

    app.include_router(evidence_routes.router)
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
