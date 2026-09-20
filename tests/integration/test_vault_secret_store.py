"""Integration tests for VaultSecretStore against a real testcontainers
Vault 1.17 (connector marketplace, `/admin/connectors`).

Complements poc/vault_secret_store/ (CLAUDE.md SS F's own throwaway,
hand-run verification) -- this file is the pytest-automated, repeatable
proof that the real adapter class (not a standalone script) round-trips
correctly and enforces the "no cross-org collision" hard requirement.
Uses a real testcontainers Vault (not the shared dev-compose one) for CI
hermeticity, mirroring postgres_engine's own session-scoped pattern.
"""

from __future__ import annotations

import json
import time
import uuid

import pytest

pytestmark = pytest.mark.integration

_MOUNT_INIT_SCRIPT = """
set -e
vault secrets enable -path=kronos-connectors -version=2 kv
vault policy write kronos-connectors-app - <<'POLICY'
path "kronos-connectors/data/*"     { capabilities = ["create","read","update","delete"] }
path "kronos-connectors/metadata/*" { capabilities = ["read","list","delete"] }
POLICY
vault auth enable approle
vault write auth/approle/role/kronos-connectors-app \
  policies=kronos-connectors-app token_ttl=1h token_max_ttl=4h
"""


@pytest.fixture(scope="session")
def vault_approle_creds(tmp_path_factory):  # type: ignore[no-untyped-def]
    """Start a real Vault 1.17 dev-mode container, provision the same
    kronos-connectors mount/policy/AppRole as docker-compose.dev.yml's
    vault-connectors-init service, and return (vault_url, creds_file)."""
    from testcontainers.core.container import DockerContainer

    container = (
        DockerContainer("hashicorp/vault:1.17")
        .with_env("VAULT_DEV_ROOT_TOKEN_ID", "root")
        .with_env("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .with_env("VAULT_ADDR", "http://127.0.0.1:8200")
        .with_env("VAULT_TOKEN", "root")
        .with_exposed_ports(8200)
    )
    with container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(8200)
        vault_url = f"http://{host}:{port}"

        # Real readiness wait: dev-mode Vault auto-unseals almost
        # immediately, but the HTTP listener takes a moment after the
        # container reports "running" -- poll `vault status` inside the
        # container (same real, reproduced HTTP-vs-HTTPS-default finding
        # as docker-compose.prod.yml's own vault healthcheck).
        for _ in range(30):
            result = container.exec(["vault", "status"])
            if result.exit_code in (0, 2):  # 2 == sealed check passed, HA mode quirk; both mean "up"
                break
            time.sleep(1)
        else:
            pytest.fail("Vault container did not become ready in time")

        init_result = container.exec(["sh", "-c", _MOUNT_INIT_SCRIPT])
        assert init_result.exit_code == 0, init_result.output.decode()

        # Separate exec calls (not appended to the script above) so each
        # `-format=json` output is parsed as its own single JSON document --
        # Vault's pretty-printed JSON spans multiple lines, so concatenating
        # two calls' output in one script and splitting by "starts with {"
        # is not a valid way to separate them (real, reproduced parse
        # failure this file's own earlier draft hit before this fix).
        role_id_result = container.exec(
            ["vault", "read", "-format=json", "auth/approle/role/kronos-connectors-app/role-id"]
        )
        assert role_id_result.exit_code == 0, role_id_result.output.decode()
        role_id = json.loads(role_id_result.output.decode())["data"]["role_id"]

        secret_id_result = container.exec(
            ["vault", "write", "-f", "-format=json", "auth/approle/role/kronos-connectors-app/secret-id"]
        )
        assert secret_id_result.exit_code == 0, secret_id_result.output.decode()
        secret_id = json.loads(secret_id_result.output.decode())["data"]["secret_id"]

        creds_file = tmp_path_factory.mktemp("vault-creds") / "kronos-connectors-approle.json"
        creds_file.write_text(json.dumps({"role_id": role_id, "secret_id": secret_id}))

        yield vault_url, str(creds_file)


def _store(vault_approle_creds):  # type: ignore[no-untyped-def]
    from src.adapter.secret.vault_secret_store import VaultSecretStore

    vault_url, creds_file = vault_approle_creds
    return VaultSecretStore.from_approle_creds_file(vault_url, creds_file)


@pytest.mark.asyncio
async def test_put_then_get_round_trips(vault_approle_creds) -> None:  # type: ignore[no-untyped-def]
    store = _store(vault_approle_creds)
    org_id = uuid.uuid4()

    await store.put(org_id, "sentinel", {"client_secret": "s3cr3t", "tenant_id": "t1"})
    resolved = await store.get(org_id, "sentinel")

    assert resolved == {"client_secret": "s3cr3t", "tenant_id": "t1"}


@pytest.mark.asyncio
async def test_get_returns_none_for_never_written_path(vault_approle_creds) -> None:  # type: ignore[no-untyped-def]
    store = _store(vault_approle_creds)
    assert await store.get(uuid.uuid4(), "sentinel") is None


@pytest.mark.asyncio
async def test_delete_then_get_returns_none(vault_approle_creds) -> None:  # type: ignore[no-untyped-def]
    store = _store(vault_approle_creds)
    org_id = uuid.uuid4()
    await store.put(org_id, "splunk-hec", {"splunk_hec_token": "tok"})

    await store.delete(org_id, "splunk-hec")

    assert await store.get(org_id, "splunk-hec") is None


@pytest.mark.asyncio
async def test_delete_is_idempotent_on_never_written_path(vault_approle_creds) -> None:  # type: ignore[no-untyped-def]
    store = _store(vault_approle_creds)
    await store.delete(uuid.uuid4(), "splunk-hec")  # must not raise


@pytest.mark.asyncio
async def test_cross_org_isolation_hard_requirement(vault_approle_creds) -> None:  # type: ignore[no-untyped-def]
    """Hard requirement (CLAUDE.md 'no collision, independent per client'):
    two orgs' secrets at the same source_type never collide, and deleting
    one never affects the other."""
    store = _store(vault_approle_creds)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()

    await store.put(org_a, "sentinel", {"client_secret": "secret-a"})
    await store.put(org_b, "sentinel", {"client_secret": "secret-b"})

    resolved_a = await store.get(org_a, "sentinel")
    resolved_b = await store.get(org_b, "sentinel")
    assert resolved_a is not None and resolved_a["client_secret"] == "secret-a"
    assert resolved_b is not None and resolved_b["client_secret"] == "secret-b"

    await store.delete(org_a, "sentinel")
    assert await store.get(org_a, "sentinel") is None
    resolved_b_after = await store.get(org_b, "sentinel")
    assert resolved_b_after is not None
    assert resolved_b_after["client_secret"] == "secret-b"
