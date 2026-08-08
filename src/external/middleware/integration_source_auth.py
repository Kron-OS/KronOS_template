"""Pluggable authentication collaborators for ``IntegrationSource`` (roadmap Q1).

Two genuinely different authentication directions exist here, so this
module deliberately does NOT force them into one ABC (a "does this pass a
vibe check" abstraction would hide a real signature mismatch, the same
class of mistake CLAUDE.md SS G.1 warns against for parallel hierarchies):

1. **Inbound** (PUSH): an external tool's own webhook call arrives at
   KronOS and must be turned into an :class:`IntegrationSourceIdentity`
   before ``IntegrationSourceIngestService.ingest_push`` runs. Two real
   transports exist in this codebase already:
   - mTLS: **fully reused, not reimplemented.** A push source authenticated
     this way arrives on the existing dual-listener mTLS transport
     (``src/external/middleware/collector_mtls.py``,
     ``src/external/run_dual_listener.py``) exactly like the D2 collector
     path -- ``identity_from_collector_identity`` below is the one-field
     adapter from the already-verified ``CollectorIdentity`` to
     ``IntegrationSourceIdentity``. There is no
     ``MtlsInboundSourceAuthenticator`` class because there is nothing left
     to authenticate: the TLS layer already did it, same as D2.
   - Static API key: genuinely new (D2's collector path has no API-key
     mode) -- ``StaticApiKeyInboundAuthenticator`` below, for sources whose
     webhook transport is plain TLS + a shared-secret header (Wazuh's
     ``wazuh-integratord`` is exactly this shape: ``hook_url`` + `api_key`
     in ``ossec.conf``, per the roadmap's own SS0 research).
2. **Outbound** (POLL): KronOS is the one making the HTTP call to the
   external tool's own API, so "authenticate" means "attach the right
   credential to an outbound request" -- a completely different shape
   (no inbound identity to derive, no request to verify). ``OutboundAuthStrategy``
   below is intentionally `httpx`-shaped (headers + optional client kwargs)
   since every real POLL source built on this foundation uses `httpx`
   (already pinned >=0.27 in pyproject.toml, and already the transport
   ``TicketingSystem``'s own webhook implementation uses).
"""

from __future__ import annotations

import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from src.domain.collector import CollectorIdentity
from src.domain.integration_source import IntegrationSourceIdentity
from src.exceptions import AuthenticationError

logger = logging.getLogger(__name__)


class IntegrationSourceAuthError(AuthenticationError):
    """Raised when an inbound push request or outbound poll call cannot be
    authenticated -- a real, observed rejection (unknown key, missing
    header, non-2xx token response), never silently treated as anonymous."""


def identity_from_collector_identity(
    identity: CollectorIdentity, *, source_type: str
) -> IntegrationSourceIdentity:
    """Adapt an already mTLS-verified ``CollectorIdentity`` into an
    ``IntegrationSourceIdentity`` for a PUSH source reusing the D2 transport.

    The only genuinely new field is ``source_type`` (which ``CollectorIdentity``
    has no notion of -- it is scoped to one physical collector, not a
    registered ``IntegrationSource`` implementation) -- the caller (the route
    handling that specific source_type) supplies it, never derived from the
    certificate itself.
    """
    return IntegrationSourceIdentity(
        org_id=identity.org_id,
        source_id=identity.source_id,
        source_type=source_type,
        auth_method="mtls",
    )


# --- Inbound (PUSH): request -> IntegrationSourceIdentity -------------------


class InboundSourceAuthenticator(ABC):
    """Authenticates one inbound webhook-push HTTP request into an identity.

    Only covers non-mTLS transports -- see this module's own docstring for
    why mTLS push sources reuse the D2 collector path directly instead of
    implementing this ABC.
    """

    @abstractmethod
    async def authenticate(self, headers: Mapping[str, str]) -> IntegrationSourceIdentity:
        """Raises :class:`IntegrationSourceAuthError` if *headers* carry no
        valid, provisioned credential."""


@dataclass(frozen=True)
class StaticApiKeyProvisioning:
    """One provisioned (org, source) pair's static API key -- config data,
    never derived from anything a request supplies about itself."""

    api_key: str
    org_id: uuid.UUID
    source_id: str
    source_type: str


class StaticApiKeyInboundAuthenticator(InboundSourceAuthenticator):
    """Looks up a shared-secret header against provisioned API keys.

    Provisioning is explicit, out-of-band config (constructor argument) --
    never inferred from the request itself (the exact invariant
    ``CollectorIdentity``'s own docstring establishes for mTLS, applied here
    to the API-key transport). A real deployment sources
    ``provisioned_keys`` from Vault/env via ``Settings``, never hardcoded.
    """

    _HEADER_NAME = "X-KronOS-Source-Key"

    def __init__(self, provisioned_keys: Mapping[str, StaticApiKeyProvisioning]) -> None:
        self._provisioned_keys = dict(provisioned_keys)

    async def authenticate(self, headers: Mapping[str, str]) -> IntegrationSourceIdentity:
        # Header lookups must be case-insensitive per RFC 7230 SS3.2, but a
        # plain dict (as tests/PoC use) is not -- normalize defensively so
        # this authenticator behaves the same whether it is handed a real
        # ASGI/httpx case-insensitive multidict or a plain test dict.
        normalized = {k.lower(): v for k, v in headers.items()}
        api_key = normalized.get(self._HEADER_NAME.lower())
        if api_key is None:
            raise IntegrationSourceAuthError(
                f"Missing required '{self._HEADER_NAME}' header on inbound push request"
            )
        provisioning = self._provisioned_keys.get(api_key)
        if provisioning is None:
            raise IntegrationSourceAuthError("Inbound push API key is not provisioned")
        return IntegrationSourceIdentity(
            org_id=provisioning.org_id,
            source_id=provisioning.source_id,
            source_type=provisioning.source_type,
            auth_method="api-key",
        )


# --- Outbound (POLL): attach credentials to KronOS's own HTTP call ---------


class OutboundAuthStrategy(ABC):
    """Attaches credentials to an outbound HTTP call KronOS makes to poll an
    external tool's own API."""

    @abstractmethod
    async def headers(self) -> dict[str, str]:
        """Extra HTTP headers this call needs (e.g. ``Authorization``).

        May raise :class:`IntegrationSourceAuthError` if a credential could
        not be obtained (e.g. token endpoint rejected the request) -- a real
        failure, never silently returns empty headers to paper over it.
        """

    def client_kwargs(self) -> dict[str, Any]:
        """Extra ``httpx.AsyncClient``/request kwargs (e.g. ``cert=`` for
        mTLS). Default: none -- most strategies only need headers."""
        return {}


class ApiKeyOutboundAuthStrategy(OutboundAuthStrategy):
    """Static bearer/API-key header, e.g. ``Authorization: Bearer <token>``."""

    def __init__(self, header_name: str, header_value: str) -> None:
        self._header_name = header_name
        self._header_value = header_value

    async def headers(self) -> dict[str, str]:
        return {self._header_name: self._header_value}


class MtlsOutboundAuthStrategy(OutboundAuthStrategy):
    """Client-certificate auth for an external API that itself requires mTLS
    (`httpx` already supports ``cert=(certfile, keyfile)`` natively)."""

    def __init__(self, cert_file: str, key_file: str) -> None:
        self._cert_file = cert_file
        self._key_file = key_file

    async def headers(self) -> dict[str, str]:
        return {}

    def client_kwargs(self) -> dict[str, Any]:
        return {"cert": (self._cert_file, self._key_file)}


@dataclass
class _CachedToken:
    access_token: str
    expires_at_monotonic: float


class OAuth2ClientCredentialsOutboundAuthStrategy(OutboundAuthStrategy):
    """OAuth2 client-credentials grant (RFC 6749 SS4.4), parameterized by
    token endpoint + scope -- deliberately not hardcoded to one IdP, since
    the roadmap's own SS0 research found CrowdStrike's and Microsoft Entra
    ID's token servers are both real, distinct instances of this same grant
    type with different endpoints/scopes, not different grant types.

    Caches the token in-process until ``expires_in`` (minus a safety margin)
    elapses, per RFC 6749's own recommendation that a client SHOULD NOT
    request a new token for every call -- verified against the spec's own
    text, not assumed. A 30s safety margin avoids a token expiring
    mid-flight on a request that was issued a moment before real expiry.
    """

    _EXPIRY_SAFETY_MARGIN_SECONDS = 30.0

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
    ) -> None:
        self._http_client = http_client
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._cached: _CachedToken | None = None

    async def headers(self) -> dict[str, str]:
        token = await self._get_valid_token()
        return {"Authorization": f"Bearer {token}"}

    async def _get_valid_token(self) -> str:
        if self._cached is not None and self._cached.expires_at_monotonic > time.monotonic():
            return self._cached.access_token

        data: dict[str, str] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            data["scope"] = self._scope

        try:
            response = await self._http_client.post(self._token_endpoint, data=data)
        except httpx.HTTPError as exc:
            raise IntegrationSourceAuthError(
                f"OAuth2 client-credentials token request failed: {exc}"
            ) from exc

        if response.status_code != 200:
            raise IntegrationSourceAuthError(
                "OAuth2 token endpoint rejected client-credentials request "
                f"(status={response.status_code}, body={response.text[:500]!r})"
            )

        try:
            body = response.json()
            access_token = str(body["access_token"])
            expires_in = float(body.get("expires_in", 300))
        except (KeyError, ValueError, TypeError) as exc:
            raise IntegrationSourceAuthError(f"OAuth2 token response malformed: {exc}") from exc

        self._cached = _CachedToken(
            access_token=access_token,
            expires_at_monotonic=time.monotonic()
            + max(expires_in - self._EXPIRY_SAFETY_MARGIN_SECONDS, 0.0),
        )
        return access_token
