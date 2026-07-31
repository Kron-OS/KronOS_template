"""Starts the mTLS collector listener alongside the main app's existing
plain-HTTP listener (roadmap M3/D2) -- "dual" meaning the deployment now has
two real listeners with two different trust models, not that this one
process replaces the existing ``uvicorn src.external.fastapi_app:app``
command (docker-compose.dev.yml) -- that listener is unchanged; nginx keeps
terminating TLS for it exactly as ``poc/tls_lan_https/`` already verified.

This listener is different: mTLS termination happens HERE, in this uvicorn
process itself, using the custom ``MTLSIdentityH11Protocol``
(``src/external/mtls_protocol.py``) -- because uvicorn's own ASGI server
has no TLS-passthrough extension to hand a client cert to an app behind a
separate TLS-terminating proxy, and even if nginx *did* forward a verified
client-cert header, this deployment deliberately does not add that
indirection for what is (roadmap-wide) the single most security-sensitive
new trust boundary in Milestone M3.

Real, empirically-confirmed requirement (poc/collector_ingest_mtls/):
``ssl_cert_reqs=ssl.CERT_REQUIRED`` + ``ssl_ca_certs=<step-ca root>`` on
``uvicorn.Config`` enforces the TLS-handshake-level rejection of any
connection without a CA-signed client cert -- confirmed directly, not
assumed. This listener's OWN server certificate is a normal step-ca-issued
leaf (server auth), unrelated to the client-auth certs it verifies.
"""

from __future__ import annotations

import argparse
import ssl

import uvicorn

from src.external.collector_app import collector_app
from src.external.mtls_protocol import MTLSIdentityH11Protocol


def _wire_collector_dependencies() -> None:
    """Mirrors src/external/startup.py's real Redis DB-number convention
    (settings.stream_redis_db) -- this standalone listener wires only what
    CollectorIngestService actually needs, not the full app's dependency
    graph (see collector_app.py's docstring)."""
    from urllib.parse import urlsplit, urlunsplit  # noqa: PLC0415

    from redis.asyncio import Redis as AsyncRedis  # noqa: PLC0415

    from src.adapter.queue.event_dedup import RedisEventDedupChecker  # noqa: PLC0415
    from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415
    from src.external.dependencies import configure_collector_ingest_service  # noqa: PLC0415

    settings = Settings()  # type: ignore[call-arg]
    redis_url = settings.redis_url.get_secret_value()
    parsed = urlsplit(redis_url)
    stream_redis_url = urlunsplit(parsed._replace(path=f"/{settings.stream_redis_db}"))
    redis_client = AsyncRedis.from_url(stream_redis_url)

    configure_collector_ingest_service(
        RedisStreamIngestAdapter(redis_client),
        RedisEventDedupChecker(redis_client),
        max_stream_length=settings.collector_max_stream_length,
        dedup_ttl_seconds=settings.collector_dedup_ttl_seconds,
    )


def run(
    *,
    host: str = "0.0.0.0",
    port: int = 8443,
    server_certfile: str,
    server_keyfile: str,
    client_ca_certs: str,
) -> None:
    _wire_collector_dependencies()
    config = uvicorn.Config(
        collector_app,
        host=host,
        port=port,
        ssl_certfile=server_certfile,
        ssl_keyfile=server_keyfile,
        ssl_ca_certs=client_ca_certs,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        http=MTLSIdentityH11Protocol,
        log_level="info",
    )
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--server-cert", required=True, help="This listener's own TLS server certificate")
    parser.add_argument("--server-key", required=True, help="This listener's own TLS server private key")
    parser.add_argument("--client-ca", required=True, help="step-ca root CA used to verify collector client certs")
    args = parser.parse_args()
    run(
        host=args.host,
        port=args.port,
        server_certfile=args.server_cert,
        server_keyfile=args.server_key,
        client_ca_certs=args.client_ca,
    )
