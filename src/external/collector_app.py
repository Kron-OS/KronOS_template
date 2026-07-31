"""Minimal ASGI app for the mTLS collector listener (roadmap M3/D2).

Deliberately separate from ``src/external/fastapi_app.py``'s browser/API app
-- the collector listener has a different trust model entirely (mTLS client
certs, no Keycloak JWTs, no session cookies) and does not need any of the
main app's routes, middleware, or dependencies (Postgres/MinIO/OpenSearch
wiring). Only ``CollectorIngestService`` (Redis-backed, via D1's adapter)
is required.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.exceptions import AuthenticationError
from src.external.routes.collector_ingest import router as collector_router


def create_collector_app() -> FastAPI:
    app = FastAPI(title="KronOS Collector Ingest", docs_url=None, redoc_url=None)
    app.include_router(collector_router)

    @app.exception_handler(AuthenticationError)
    async def auth_error_handler(request: Request, exc: AuthenticationError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    return app


collector_app = create_collector_app()
