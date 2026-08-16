"""Unit tests for the IntegrationSource auth collaborators (roadmap Q1).

External dependency mocked per CLAUDE.md SS B.5: the OAuth2 token endpoint
is an AsyncMock-backed httpx.AsyncClient, never a real network call in a
unit test (the real call is proven in poc/integration_source_foundation/).
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest

from src.adapter.repository.integration_source_key import (
    InMemoryIntegrationSourceKeyRepository,
)
from src.domain.collector import CollectorIdentity
from src.exceptions import AuthenticationError
from src.external.middleware.integration_source_auth import (
    ApiKeyOutboundAuthStrategy,
    IntegrationSourceAuthError,
    MtlsOutboundAuthStrategy,
    OAuth2ClientCredentialsOutboundAuthStrategy,
    StaticApiKeyInboundAuthenticator,
    identity_from_collector_identity,
)


class TestIdentityFromCollectorIdentity:
    def test_adapts_org_and_source_id_verbatim(self) -> None:
        org_id = uuid.uuid4()
        collector_identity = CollectorIdentity(
            org_id=org_id,
            source_id="edr-host-1",
            cert_subject="CN=test",
            not_after="2026-01-01T00:00:00+00:00",
        )

        identity = identity_from_collector_identity(collector_identity, source_type="wazuh")

        assert identity.org_id == org_id
        assert identity.source_id == "edr-host-1"
        assert identity.source_type == "wazuh"
        assert identity.auth_method == "mtls"


class TestStaticApiKeyInboundAuthenticator:
    """Milestone W8 (Gap Audit P1-7): the authenticator now takes a real
    ``IntegrationSourceKeyRepository`` and queries it per request, instead
    of the boot-time-only static dict + linear ``hmac.compare_digest`` scan
    Milestone W6/P2-W9 added (see this module's own updated docstring for
    why that scan's own timing-side-channel concern is superseded, not
    regressed, by a real hash-indexed DB lookup). The old dict-specific
    tests (multiple-keys-in-one-dict resolution, hmac.compare_digest
    wiring, no-early-exit scan behavior) are gone because the mechanism
    they proved no longer exists; ``InMemoryIntegrationSourceKeyRepository``
    itself is covered directly in
    ``tests/unit/adapter/test_integration_source_key_repository.py``.
    """

    async def _repo_with_key(
        self, org_id: uuid.UUID, source_id: str = "s1", source_type: str = "generic-webhook"
    ) -> tuple[InMemoryIntegrationSourceKeyRepository, str]:
        repo = InMemoryIntegrationSourceKeyRepository()
        record = await repo.provision(org_id, source_id, source_type)
        return repo, record.api_key

    @pytest.mark.asyncio
    async def test_valid_key_resolves_to_provisioned_identity(self) -> None:
        org_id = uuid.uuid4()
        repo, api_key = await self._repo_with_key(org_id)
        authenticator = StaticApiKeyInboundAuthenticator(repo)

        identity = await authenticator.authenticate({"X-KronOS-Source-Key": api_key})

        assert identity.org_id == org_id
        assert identity.source_id == "s1"
        assert identity.source_type == "generic-webhook"
        assert identity.auth_method == "api-key"

    @pytest.mark.asyncio
    async def test_header_lookup_is_case_insensitive(self) -> None:
        org_id = uuid.uuid4()
        repo, api_key = await self._repo_with_key(org_id)
        authenticator = StaticApiKeyInboundAuthenticator(repo)

        identity = await authenticator.authenticate({"x-kronos-source-key": api_key})

        assert identity.org_id == org_id

    @pytest.mark.asyncio
    async def test_missing_header_raises(self) -> None:
        authenticator = StaticApiKeyInboundAuthenticator(InMemoryIntegrationSourceKeyRepository())
        with pytest.raises(IntegrationSourceAuthError):
            await authenticator.authenticate({})

    @pytest.mark.asyncio
    async def test_unknown_key_raises(self) -> None:
        authenticator = StaticApiKeyInboundAuthenticator(InMemoryIntegrationSourceKeyRepository())
        with pytest.raises(IntegrationSourceAuthError):
            await authenticator.authenticate({"X-KronOS-Source-Key": "not-provisioned"})

    def test_auth_error_is_an_authentication_error(self) -> None:
        assert issubclass(IntegrationSourceAuthError, AuthenticationError)

    @pytest.mark.asyncio
    async def test_multiple_provisioned_keys_each_resolve_correctly(self) -> None:
        """With several provisioned keys (possibly different orgs), a
        lookup by one org's key must resolve to THAT org's identity, never
        another's."""
        org_1, org_2 = uuid.uuid4(), uuid.uuid4()
        repo = InMemoryIntegrationSourceKeyRepository()
        rec_1 = await repo.provision(org_1, "s1", "wazuh")
        rec_2 = await repo.provision(org_2, "s2", "crowdstrike")
        authenticator = StaticApiKeyInboundAuthenticator(repo)

        identity_1 = await authenticator.authenticate({"X-KronOS-Source-Key": rec_1.api_key})
        identity_2 = await authenticator.authenticate({"X-KronOS-Source-Key": rec_2.api_key})

        assert identity_1.org_id == org_1
        assert identity_1.source_id == "s1"
        assert identity_2.org_id == org_2
        assert identity_2.source_id == "s2"

    @pytest.mark.asyncio
    async def test_revoked_key_is_rejected(self) -> None:
        """A key that was provisioned then revoked must behave exactly
        like a never-provisioned key -- the whole point of ``revoke``."""
        org_id = uuid.uuid4()
        repo, api_key = await self._repo_with_key(org_id)
        authenticator = StaticApiKeyInboundAuthenticator(repo)

        # Sanity: works before revocation.
        await authenticator.authenticate({"X-KronOS-Source-Key": api_key})

        await repo.revoke(org_id, "s1")

        with pytest.raises(IntegrationSourceAuthError):
            await authenticator.authenticate({"X-KronOS-Source-Key": api_key})

    @pytest.mark.asyncio
    async def test_org_isolation_one_orgs_key_never_resolves_to_another(self) -> None:
        """Confirms the identity's org_id always comes from the matched
        provisioning record itself, never guessable/overridable by the
        caller -- two different orgs' distinct keys must never cross-match."""
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        repo = InMemoryIntegrationSourceKeyRepository()
        rec_a = await repo.provision(org_a, "s-a", "generic-webhook")
        await repo.provision(org_b, "s-b", "generic-webhook")
        authenticator = StaticApiKeyInboundAuthenticator(repo)

        identity = await authenticator.authenticate({"X-KronOS-Source-Key": rec_a.api_key})

        assert identity.org_id == org_a
        assert identity.org_id != org_b


class TestApiKeyOutboundAuthStrategy:
    @pytest.mark.asyncio
    async def test_returns_configured_header(self) -> None:
        strategy = ApiKeyOutboundAuthStrategy("Authorization", "Bearer abc123")
        assert await strategy.headers() == {"Authorization": "Bearer abc123"}

    def test_no_extra_client_kwargs(self) -> None:
        strategy = ApiKeyOutboundAuthStrategy("X-Key", "abc")
        assert strategy.client_kwargs() == {}


class TestMtlsOutboundAuthStrategy:
    @pytest.mark.asyncio
    async def test_no_headers_needed(self) -> None:
        strategy = MtlsOutboundAuthStrategy("/tmp/cert.pem", "/tmp/key.pem")
        assert await strategy.headers() == {}

    def test_client_kwargs_carries_cert_tuple(self) -> None:
        strategy = MtlsOutboundAuthStrategy("/tmp/cert.pem", "/tmp/key.pem")
        assert strategy.client_kwargs() == {"cert": ("/tmp/cert.pem", "/tmp/key.pem")}


class TestOAuth2ClientCredentialsOutboundAuthStrategy:
    def _mock_client(self, status_code: int = 200, json_body: dict | None = None) -> AsyncMock:
        client = AsyncMock(spec=httpx.AsyncClient)
        response = httpx.Response(
            status_code=status_code,
            json=(
                json_body if json_body is not None else {"access_token": "tok-1", "expires_in": 300}
            ),
            request=httpx.Request("POST", "https://idp.example/token"),
        )
        client.post.return_value = response
        return client

    @pytest.mark.asyncio
    async def test_fetches_and_returns_bearer_token(self) -> None:
        client = self._mock_client()
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
            scope="alerts.read",
        )

        headers = await strategy.headers()

        assert headers == {"Authorization": "Bearer tok-1"}
        client.post.assert_awaited_once()
        _url, kwargs = client.post.await_args[0][0], client.post.await_args[1]
        assert kwargs["data"]["grant_type"] == "client_credentials"
        assert kwargs["data"]["scope"] == "alerts.read"

    @pytest.mark.asyncio
    async def test_token_is_cached_across_calls(self) -> None:
        client = self._mock_client()
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )

        await strategy.headers()
        await strategy.headers()

        client.post.assert_awaited_once()  # second call served from cache

    @pytest.mark.asyncio
    async def test_expired_token_is_refetched(self) -> None:
        client = self._mock_client(json_body={"access_token": "tok-1", "expires_in": 1})
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )
        # Force the cached token to already be past its safety-margin expiry.
        await strategy.headers()
        assert strategy._cached is not None
        strategy._cached.expires_at_monotonic = time.monotonic() - 1

        await strategy.headers()

        assert client.post.await_count == 2

    @pytest.mark.asyncio
    async def test_non_200_response_raises(self) -> None:
        client = self._mock_client(status_code=401, json_body={"error": "invalid_client"})
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client, token_endpoint="https://idp.example/token", client_id="id", client_secret="bad"
        )

        with pytest.raises(IntegrationSourceAuthError):
            await strategy.headers()

    @pytest.mark.asyncio
    async def test_malformed_response_raises(self) -> None:
        client = self._mock_client(json_body={"not_a_token_field": "x"})
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )

        with pytest.raises(IntegrationSourceAuthError):
            await strategy.headers()

    @pytest.mark.asyncio
    async def test_http_error_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = httpx.ConnectError("connection refused")
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )

        with pytest.raises(IntegrationSourceAuthError):
            await strategy.headers()
