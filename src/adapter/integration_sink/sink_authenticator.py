"""SinkAuthenticator: pluggable auth strategies for outbound sink pushes
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R1, SS4 design constraint #2).

**Why its own collaborator, not baked into each concrete sink.** The real
auth landscape across sink targets is genuinely heterogeneous -- static
bearer/token header (Splunk HEC's ``Authorization: Splunk <token>``),
OAuth2 client-credentials with a real cacheable/refreshable token (Sentinel's
Entra ID flow -- re-authenticating on every single push would be both slow
and a real, avoidable load on the customer's IdP), an API-key *tuple*
(Elastic's ``(id, key)`` shape, distinct from a single bearer token), and
mTLS (QRadar HTTP Receiver). If each concrete ``IntegrationSink``
implemented its own auth inline, R2 (Splunk, static token) and R4
(Sentinel, OAuth2) could not share any sink-side transport code even though
their actual HTTP-POST-and-read-response logic is identical -- the auth
strategy is the only thing that differs. Splitting it out means
``HttpJsonIntegrationSink`` (this module's sibling) is written ONCE and
reused by every HTTP-family target regardless of which auth strategy that
target needs.

mTLS is deliberately NOT a header -- ``httpx.AsyncClient`` already accepts
``cert=``/``verify=`` at the client level (roadmap SS4's own explicit
"reuse, don't reinvent" instruction), so ``SinkAuthParams`` carries those
two fields directly in the shape ``httpx`` already expects, rather than
inventing a parallel mTLS-specific type.
"""

from __future__ import annotations

import base64
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field

import httpx

from src.exceptions import IntegrationSinkError

# Real-world token expiries are rarely exact-to-the-second by the time our
# own request round-trips back -- refresh a little early rather than risk
# handing out a token that expires mid-flight to the very push it's for.
_OAUTH2_REFRESH_MARGIN_SECONDS = 30.0


@dataclass(frozen=True)
class SinkAuthParams:
    """Real auth material to apply to the next real outbound call.

    ``cert``/``verify`` are in ``httpx.AsyncClient``'s own accepted shapes
    (``cert``: path to a combined cert+key PEM, or a ``(certfile, keyfile)``
    tuple; ``verify``: ``True``/``False`` or a CA bundle path) -- passed
    straight through by ``HttpJsonIntegrationSink``, never reinterpreted.
    """

    headers: Mapping[str, str] = field(default_factory=dict)
    cert: str | tuple[str, str] | None = None
    verify: bool | str = True


class SinkAuthenticator(ABC):
    """Produces the real auth material for the next real outbound call.

    ``prepare()`` is called before EVERY push by the owning
    ``IntegrationSink`` -- implementations that need a refreshable token
    (OAuth2) are responsible for their own internal caching/expiry so this
    stays cheap to call every time; implementations with no per-call state
    (static token, mTLS) just return the same value every time.
    """

    @abstractmethod
    async def prepare(self) -> SinkAuthParams:
        """Return the auth material for the next real call.

        Raises ``IntegrationSinkError`` if real auth material cannot be
        produced (e.g. a real OAuth2 token-endpoint failure) -- never
        returns a fabricated/expired token silently.
        """


class NullAuthenticator(SinkAuthenticator):
    """No application-layer auth at all -- the real, documented case for
    CEF/LEEF-over-syslog (roadmap SS0: "no application-layer auth,
    fire-and-forget"). Also a legitimate stand-in for an HTTP target
    genuinely configured with no auth (e.g. an internal-network-only
    receiver)."""

    async def prepare(self) -> SinkAuthParams:
        return SinkAuthParams()


class StaticTokenAuthenticator(SinkAuthenticator):
    """A fixed bearer/token header, applied unchanged to every call.

    ``scheme`` is configurable (not hardcoded to ``Bearer``) because real
    targets differ: Splunk HEC's own documented header is literally
    ``Authorization: Splunk <token>`` (roadmap SS0), not the more common
    ``Bearer`` scheme.
    """

    def __init__(
        self,
        token: str,
        *,
        header_name: str = "Authorization",
        scheme: str = "Bearer",
        verify: bool | str = True,
    ) -> None:
        if not token:
            raise ValueError("StaticTokenAuthenticator requires a non-empty token")
        self._header_name = header_name
        self._value = f"{scheme} {token}" if scheme else token
        self._verify = verify

    async def prepare(self) -> SinkAuthParams:
        return SinkAuthParams(headers={self._header_name: self._value}, verify=self._verify)


class ApiKeyTupleAuthenticator(SinkAuthenticator):
    """An ``(id, key)`` pair encoded as an ``ApiKey`` auth header -- Elastic's
    own real API-key shape (``Authorization: ApiKey base64(id:key)``),
    structurally distinct from a single bearer token (roadmap SS4 design
    constraint #2 names this as its own case, not reducible to
    ``StaticTokenAuthenticator``).
    """

    def __init__(self, key_id: str, api_key: str) -> None:
        if not key_id or not api_key:
            raise ValueError("ApiKeyTupleAuthenticator requires non-empty key_id and api_key")
        encoded = base64.b64encode(f"{key_id}:{api_key}".encode()).decode()
        self._value = f"ApiKey {encoded}"

    async def prepare(self) -> SinkAuthParams:
        return SinkAuthParams(headers={"Authorization": self._value})


class MtlsAuthenticator(SinkAuthenticator):
    """Client-certificate auth -- no headers, just ``httpx``'s own
    ``cert=``/``verify=`` client params (QRadar HTTP Receiver, roadmap SS0).
    """

    def __init__(self, cert: str | tuple[str, str], *, verify: bool | str = True) -> None:
        self._cert = cert
        self._verify = verify

    async def prepare(self) -> SinkAuthParams:
        return SinkAuthParams(cert=self._cert, verify=self._verify)


class OAuth2ClientCredentialsAuthenticator(SinkAuthenticator):
    """Real OAuth2 client-credentials flow with real token caching/expiry.

    Parameterized by *token_url* (never hardcoded to one IdP -- Sentinel's
    Entra ID token endpoint and any other target's own OAuth2 server both
    fit this same shape, roadmap SS4). ``prepare()`` only performs a real
    token-endpoint POST when no cached token exists or the cached one is
    within ``_OAUTH2_REFRESH_MARGIN_SECONDS`` of its real, server-reported
    ``expires_in`` -- proven for real in
    ``poc/integration_sink_foundation/`` (two pushes, one real token fetch).
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: str | None = None,
        timeout: float = 15.0,
        verify: bool | str = True,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._timeout = timeout
        self._verify = verify
        self._cached_token: str | None = None
        self._expires_at_monotonic: float = 0.0
        self._fetch_count = 0

    @property
    def real_token_fetch_count(self) -> int:
        """Exposed purely for PoC/test verification that caching actually
        avoids re-authenticating on every push -- not used by production
        callers."""
        return self._fetch_count

    async def prepare(self) -> SinkAuthParams:
        now = time.monotonic()
        if self._cached_token is None or now >= self._expires_at_monotonic:
            await self._fetch_token()
        return SinkAuthParams(headers={"Authorization": f"Bearer {self._cached_token}"})

    async def _fetch_token(self) -> None:
        body = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            body["scope"] = self._scope
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify) as client:
                response = await client.post(self._token_url, data=body)
        except httpx.HTTPError as exc:
            raise IntegrationSinkError(
                "Real OAuth2 client-credentials token request failed to complete",
                context={"token_url": self._token_url, "error": str(exc)},
            ) from exc

        if response.status_code != 200:
            raise IntegrationSinkError(
                "OAuth2 token endpoint rejected the real client-credentials request",
                context={
                    "token_url": self._token_url,
                    "status_code": response.status_code,
                    "body": response.text[:500],
                },
            )

        try:
            payload = response.json()
            access_token = payload["access_token"]
            expires_in = float(payload.get("expires_in", 3600))
        except (ValueError, KeyError, TypeError) as exc:
            raise IntegrationSinkError(
                "OAuth2 token endpoint returned a 2xx response with no usable "
                "access_token -- never fabricating one",
                context={
                    "token_url": self._token_url,
                    "body": response.text[:500],
                    "error": str(exc),
                },
            ) from exc

        self._cached_token = access_token
        self._expires_at_monotonic = time.monotonic() + max(
            0.0, expires_in - _OAUTH2_REFRESH_MARGIN_SECONDS
        )
        self._fetch_count += 1
