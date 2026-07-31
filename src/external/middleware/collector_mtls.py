"""CollectorIdentityExtractor: turns a verified mTLS peer certificate into a
CollectorIdentity (roadmap M3/D2).

Mirrors ``keycloak_auth.py``'s shape (validator class + FastAPI dependency),
but the verification mechanism is TLS-layer X.509, not a JWT: the real
trust decision -- "is this certificate signed by our step-ca root, and
un-expired" -- is already made by the TLS transport itself
(``ssl_cert_reqs=CERT_REQUIRED`` + ``ssl_ca_certs=<step-ca root>``, wired in
``src/external/run_dual_listener.py``) before a single byte of HTTP reaches
this code; a connection presenting no cert, or a cert not signed by the
pinned CA, or an expired cert, never completes its TLS handshake and never
reaches this dependency at all -- verified empirically against the real
running step-ca in ``poc/collector_ingest_mtls/`` (a `curl` with no client
cert, and one with a self-signed cert, both get a bare connection reset,
never an HTTP response). This class's only job is parsing the
ALREADY-VERIFIED peer certificate's identity out of its Subject Alternative
Name -- it does not re-verify signature/chain/expiry itself (that would be
redundant with, not a substitute for, the TLS layer's own real enforcement).

Identity encoding: a URI Subject Alternative Name of the form
``urn:kronos:collector:org:<org_id>:source:<source_id>``, set by step-ca at
issuance time (per real collector/org pairing -- automated per-org
provisioning tooling is a follow-up, out of this item's scope). Chosen over
stuffing identity into the CommonName because SAN is the field X.509
tooling actually expects identity/subject-alt-identity data in, and a URI
SAN (as opposed to a DNS/IP SAN) cleanly marks this as "not a hostname" to
any code that might otherwise treat SANs as server-identity hostnames.
"""

from __future__ import annotations

import logging
import re
import uuid
from abc import ABC, abstractmethod
from typing import Any

from cryptography import x509
from fastapi import Request

from src.domain.collector import CollectorIdentity
from src.exceptions import AuthenticationError

logger = logging.getLogger(__name__)

_URN_PATTERN = re.compile(
    r"^urn:kronos:collector:org:(?P<org_id>[0-9a-fA-F-]{36}):source:(?P<source_id>.+)$"
)

_SCOPE_KEY = "kronos_client_cert_der"


class CollectorIdentityExtractor(ABC):
    """Turns raw, already-TLS-verified peer certificate bytes into a CollectorIdentity."""

    @abstractmethod
    def extract(self, der_cert: bytes) -> CollectorIdentity:
        """Raises AuthenticationError if the certificate carries no valid collector identity."""


class X509SanCollectorIdentityExtractor(CollectorIdentityExtractor):
    """Real implementation: parses the DER cert's URI SAN via `cryptography`."""

    def extract(self, der_cert: bytes) -> CollectorIdentity:
        try:
            cert = x509.load_der_x509_certificate(der_cert)
        except ValueError as exc:
            raise AuthenticationError(f"Malformed client certificate: {exc}") from exc

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound:
            uris = []

        for uri in uris:
            match = _URN_PATTERN.match(uri)
            if match is None:
                continue
            try:
                org_id = uuid.UUID(match.group("org_id"))
            except ValueError as exc:
                raise AuthenticationError(
                    f"Client certificate SAN has a malformed org_id: {uri!r}"
                ) from exc
            return CollectorIdentity(
                org_id=org_id,
                source_id=match.group("source_id"),
                cert_subject=cert.subject.rfc4514_string(),
                not_after=cert.not_valid_after_utc.isoformat(),
            )

        raise AuthenticationError(
            "Client certificate carries no 'urn:kronos:collector:org:...:source:...' SAN"
        )


# Stateless -- one shared instance, same idiom as keycloak_auth.py's module-level
# `_bearer = HTTPBearer(...)`. Swappable in principle: tests/future callers can
# construct a different CollectorIdentityExtractor and override the
# `get_collector_identity` dependency via app.dependency_overrides, exactly
# like get_tenant_context.
_extractor: CollectorIdentityExtractor = X509SanCollectorIdentityExtractor()


def get_collector_identity(request: Request) -> CollectorIdentity:
    """FastAPI dependency: the authenticated CollectorIdentity for this mTLS request.

    Reads the DER-encoded peer certificate that uvicorn's custom
    ``MTLSIdentityH11Protocol`` (``src/external/mtls_protocol.py``) already
    placed on ``request.scope["extensions"]["kronos_client_cert_der"]``
    during ``connection_made`` -- see that module's docstring for why
    uvicorn's stock protocol classes do not expose this by default (verified
    empirically against the real installed uvicorn 0.51.0 source: no TLS/
    client-cert ASGI extension exists there).
    """
    extensions: dict[str, Any] = request.scope.get("extensions") or {}
    der_cert = extensions.get(_SCOPE_KEY)
    if der_cert is None:
        # Reaching this dependency at all already required a completed TLS
        # handshake with ssl_cert_reqs=CERT_REQUIRED on whichever listener
        # served this connection -- an absent cert here means the request
        # landed on the wrong (non-mTLS) listener/protocol, a real
        # misconfiguration, not a normal "no credentials supplied" case a
        # collector could hit legitimately.
        raise AuthenticationError(
            "No verified client certificate on this connection "
            "(request did not arrive via the mTLS collector listener)"
        )
    return _extractor.extract(der_cert)
