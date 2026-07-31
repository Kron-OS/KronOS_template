"""MTLSIdentityH11Protocol: uvicorn HTTP protocol subclass that captures the
verified TLS peer certificate and exposes it to the ASGI app (roadmap M3/D2).

Real, verified finding (``poc/collector_ingest_mtls/``): uvicorn 0.51.0 (the
real installed version -- ``pyproject.toml``'s ``uvicorn>=0.30`` pin has
drifted, flagged here the same way D1 flagged an equivalent drift for
``redis``) implements NO ASGI TLS extension -- its entire source tree was
grepped for "client_cert"/"ssl_object"/"tls" and none of the HTTP protocol
implementations reference any of them. ``ssl_cert_reqs=CERT_REQUIRED`` +
``ssl_ca_certs=...`` on ``uvicorn.Config`` DOES real, correct enforcement at
the TLS-handshake layer (confirmed: a connection presenting no cert, or a
cert not signed by the configured CA, is reset before a single HTTP byte is
processed -- it never reaches ASGI), but the verified peer certificate
itself is silently discarded afterward -- nothing in uvicorn's request scope
carries it forward to the application. This class recovers it via the one
real hook available: the asyncio SSL transport's own
``get_extra_info("ssl_object")``, standard-library functionality unrelated
to uvicorn's own (nonexistent) support for this.

Deliberately swappable: any future replacement (a different ASGI server
that DOES implement the ASGI TLS extension, or a hypercorn/daphne
migration) only needs a different extraction point at the
``get_collector_identity`` dependency boundary
(``src/external/middleware/collector_mtls.py``) -- this class is the one
place tied specifically to uvicorn's own gap.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol

logger = logging.getLogger(__name__)

SCOPE_KEY = "kronos_client_cert_der"

_ASGIApp = Callable[[dict[str, Any], Any, Any], Awaitable[None]]


class MTLSIdentityH11Protocol(H11Protocol):
    """H11Protocol that injects the verified client cert's DER bytes into
    ``scope["extensions"]["kronos_client_cert_der"]`` for every HTTP request
    on this connection, before the ASGI app runs.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client_cert_der: bytes | None = None
        self.app = _inject_cert_extension(self.app, self)

    def connection_made(self, transport: Any) -> None:  # type: ignore[override]
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is None:
            return
        try:
            self._client_cert_der = ssl_object.getpeercert(binary_form=True)
        except Exception:  # noqa: BLE001
            logger.warning("mtls_peer_cert_extraction_failed", exc_info=True)
            self._client_cert_der = None


def _inject_cert_extension(app: _ASGIApp, protocol: MTLSIdentityH11Protocol) -> _ASGIApp:
    async def wrapped(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            scope.setdefault("extensions", {})[SCOPE_KEY] = protocol._client_cert_der
        await app(scope, receive, send)

    return wrapped
