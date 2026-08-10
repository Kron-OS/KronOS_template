"""Real, CI-wired verification that the security-enabled
docker/docker-compose.test.yml profile (Gap Audit P1-14 / V3) actually
works end-to-end: OpenSearch's security plugin genuinely enabled + real DLS
tenant isolation, driven by real Keycloak-issued JWTs that the real,
unmodified ``KeycloakTokenValidator`` (src/external/middleware/
keycloak_auth.py) validates.

This is NOT a standalone-bootable test: it assumes an already-running,
already-provisioned stack (docker compose up + the real opensearch-init/
keycloak-init one-shot services + poc/ci_security_enabled_stack/
provision_ci_org_b.py's second org/client/user) -- exactly what
.github/workflows/security-integration-tests.yml sets up before invoking
pytest, and what poc/ci_security_enabled_stack/run_poc.sh does for a local
run. Skipped entirely (module-level) when the required env vars aren't
set, so `pytest tests/integration/` on its own (no security stack running)
still passes/skips cleanly, matching this directory's existing
Docker-availability skip convention (conftest.py).

Mirrors poc/ci_security_enabled_stack/verify_security_stack.py's own real
checks (kept in sync manually; that script is the throwaway/scratch
original per CLAUDE.md §F.3, this is the "confirm an automated test
exercises it the same way" per §F.2 step 5).
"""

from __future__ import annotations

import os

import httpx
import pytest
from jose import jwt as jose_jwt

from src.adapter.opensearch.client import OpenSearchClient
from src.external.middleware.keycloak_auth import KeycloakTokenValidator

_KC_BASE = os.environ.get("KRONOS_SECURITY_STACK_KC_BASE", "")
_OS_BASE = os.environ.get("KRONOS_SECURITY_STACK_OS_BASE", "")

pytestmark = pytest.mark.security_stack

if not _KC_BASE or not _OS_BASE:
    pytest.skip(
        "KRONOS_SECURITY_STACK_KC_BASE / KRONOS_SECURITY_STACK_OS_BASE not set -- "
        "security-enabled stack integration tests only run when a real "
        "docker-compose.test.yml security-enabled stack is up (see "
        "poc/ci_security_enabled_stack/README.md and "
        ".github/workflows/security-integration-tests.yml)",
        allow_module_level=True,
    )

_REALM = "kronos"
_TOKEN_URL = f"{_KC_BASE}/realms/{_REALM}/protocol/openid-connect/token"
_JWKS_URL = f"{_KC_BASE}/realms/{_REALM}/protocol/openid-connect/certs"
_CI_CLIENT_ID = "kronos-ci-verifier"
_OS_ADMIN_PASSWORD = os.environ.get("KRONOS_SECURITY_STACK_OS_ADMIN_PASSWORD", "KronOSCiTest#2026")


def _password_grant(username: str, password: str) -> str:
    resp = httpx.post(
        _TOKEN_URL,
        data={
            "client_id": _CI_CLIENT_ID,
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        timeout=15.0,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _search_as(token: str, index: str) -> dict:
    with httpx.Client(
        verify=False
    ) as h:  # noqa: S501 - self-signed demo cert, matches prod's verify_certs=False
        resp = h.get(f"{_OS_BASE}/{index}/_search", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json()


@pytest.fixture(scope="module")
def org_a_token() -> str:
    return _password_grant("analyst", "DevAnalyst#2026")


@pytest.fixture(scope="module")
def org_b_token() -> str:
    return _password_grant("ci-analyst-b", "CiAnalystB#2026")


class TestRealKeycloakJwtValidation:
    """MINIMUM BAR (b): a real Keycloak-issued JWT the real backend validates."""

    async def test_validator_extracts_tenant_context_for_two_real_orgs(
        self, org_a_token: str, org_b_token: str
    ) -> None:
        validator = KeycloakTokenValidator(
            issuer=f"{_KC_BASE}/realms/{_REALM}", audience="kronos-backend", jwks_url=_JWKS_URL
        )
        tenant_a = await validator.validate_and_extract(org_a_token)
        tenant_b = await validator.validate_and_extract(org_b_token)

        claims_a = jose_jwt.get_unverified_claims(org_a_token)
        assert str(tenant_a.org_id) == claims_a["org_id"]
        assert tenant_a.org_id != tenant_b.org_id

    async def test_validator_rejects_a_tampered_token(self, org_a_token: str) -> None:
        from src.exceptions import AuthenticationError

        with pytest.raises(AuthenticationError):
            await KeycloakTokenValidator(
                issuer=f"{_KC_BASE}/realms/{_REALM}", audience="kronos-backend", jwks_url=_JWKS_URL
            ).validate_and_extract(org_a_token[:-4] + "abcd")


class TestRealOpenSearchDlsIsolation:
    """MINIMUM BAR (a)+(c): security plugin genuinely on, real DLS isolates
    two real Keycloak orgs -- equivalent to I1's own tenant-isolation proof."""

    async def test_two_real_orgs_are_dls_isolated(self, org_a_token: str, org_b_token: str) -> None:
        import uuid

        claims_a = jose_jwt.get_unverified_claims(org_a_token)
        claims_b = jose_jwt.get_unverified_claims(org_b_token)
        org_id_a, org_id_b = claims_a["org_id"], claims_b["org_id"]
        assert org_id_a != org_id_b

        os_host, os_port = _OS_BASE.replace("https://", "").split(":")
        client = OpenSearchClient(
            hosts=[{"host": os_host, "port": int(os_port)}],
            http_auth=("admin", _OS_ADMIN_PASSWORD),
            use_ssl=True,
            verify_certs=False,
        )
        await client.ensure_index_template()
        index_name = f"kronos-cisec-it-{uuid.uuid4().hex[:8]}"
        docs = [
            (
                index_name,
                "doc-org-a",
                {
                    "@timestamp": "2026-08-10T00:00:00Z",
                    "message": "org A",
                    "kronos": {
                        "org_id": org_id_a,
                        "case_id": "cisec-it",
                        "evidence_id": "e1",
                        "parser": "test",
                        "parser_version": "1",
                        "record_index": 0,
                        "ingest_timestamp": "2026-08-10T00:00:00Z",
                    },
                },
            ),
            (
                index_name,
                "doc-org-b",
                {
                    "@timestamp": "2026-08-10T00:00:00Z",
                    "message": "org B",
                    "kronos": {
                        "org_id": org_id_b,
                        "case_id": "cisec-it",
                        "evidence_id": "e2",
                        "parser": "test",
                        "parser_version": "1",
                        "record_index": 0,
                        "ingest_timestamp": "2026-08-10T00:00:00Z",
                    },
                },
            ),
        ]
        assert await client.bulk_index(docs) == 2
        await client._client.indices.refresh(
            index=index_name
        )  # noqa: SLF001 - test-only, real client internals
        await client.ensure_generic_tenant_role()
        await client.close()

        result_a = _search_as(org_a_token, index_name)
        result_b = _search_as(org_b_token, index_name)

        assert {h["_id"] for h in result_a["hits"]["hits"]} == {"doc-org-a"}
        assert {h["_id"] for h in result_b["hits"]["hits"]} == {"doc-org-b"}
