"""VaultSecretStore: real per-org connector secret storage on HashiCorp
Vault 1.17 via hvac 2.4.0.

Verified for real against a real running Vault before this was written --
see poc/vault_secret_store/README.md (CLAUDE.md Section F) for the actual
captured write/read/delete/isolation output this adapter's design is taken
from. Authenticates via a dedicated, least-privilege AppRole
(`kronos-connectors-app`, scoped only to the `kronos-connectors` KV-v2
mount) rather than the shared root `vault_token` -- see
`docker-compose.dev.yml`'s `vault-connectors-init` service for how that
AppRole/mount/policy is provisioned, and `Settings.vault_connectors_approle_creds_file`
for how this adapter finds its role_id/secret_id.

Real, explicit limitation (stated here, not just in the PoC README): this
AppRole's policy is static and mount-wide, not per-org -- the isolation
this store provides is that every caller (`ConnectorConfigService`) always
supplies `org_id` from an authenticated `TenantContext`, never from
request input. This module does not, and cannot by itself, prevent a
compromised backend process's own Vault token from reading another org's
path; that would require dynamic per-org Vault policies, explicitly out of
scope for this pass.

``hvac.Client`` is a synchronous, ``requests``-based client -- hvac has no
official async support. Every real network call below is wrapped in
``asyncio.to_thread`` so it runs on a worker thread instead of blocking the
event loop (CLAUDE.md SS A.5: "No blocking operations on the FastAPI
thread") -- confirmed this matters here specifically because
``ConnectorConfigService`` is reachable from real FastAPI request handlers
(``admin_connector_config.py``), not just from a Celery task's own
short-lived loop where a blocking call is merely wasteful, not
request-stalling.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

import hvac
import hvac.exceptions

from src.application.secret_store import SecretStore
from src.exceptions import StorageError

_MOUNT_POINT = "kronos-connectors"


class VaultSecretStore(SecretStore):
    """Vault KV-v2-backed SecretStore, authenticated via a dedicated AppRole."""

    def __init__(self, vault_url: str, role_id: str, secret_id: str) -> None:
        self._vault_url = vault_url
        self._role_id = role_id
        self._secret_id = secret_id
        self._client: hvac.Client | None = None

    @classmethod
    def from_approle_creds_file(cls, vault_url: str, creds_file: str) -> VaultSecretStore:
        """Build from the JSON `{role_id, secret_id}` file
        `vault-connectors-init` writes to the shared `vault_connectors_creds`
        volume (see `docker-compose.dev.yml`)."""
        data = json.loads(Path(creds_file).read_text())
        return cls(vault_url, data["role_id"], data["secret_id"])

    def _login(self) -> hvac.Client:
        client = hvac.Client(url=self._vault_url)
        try:
            resp = client.auth.approle.login(role_id=self._role_id, secret_id=self._secret_id)
        except Exception as exc:
            raise StorageError(
                "VaultSecretStore: AppRole login failed",
                context={"vault_url": self._vault_url, "error": str(exc), "error_type": type(exc).__name__},
            ) from exc
        client.token = resp["auth"]["client_token"]
        return client

    def _get_client(self) -> hvac.Client:
        if self._client is None or not self._client.is_authenticated():
            self._client = self._login()
        return self._client

    @staticmethod
    def _path(org_id: uuid.UUID, source_type: str) -> str:
        return f"{org_id}/{source_type}"

    async def put(self, org_id: uuid.UUID, source_type: str, secrets: dict[str, str]) -> None:
        await asyncio.to_thread(self._put_sync, org_id, source_type, secrets)

    def _put_sync(self, org_id: uuid.UUID, source_type: str, secrets: dict[str, str]) -> None:
        client = self._get_client()
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=self._path(org_id, source_type), secret=secrets, mount_point=_MOUNT_POINT
            )
        except Exception as exc:
            raise StorageError(
                "VaultSecretStore: failed to write connector secret",
                context={
                    "org_id": str(org_id),
                    "source_type": source_type,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            ) from exc

    async def get(self, org_id: uuid.UUID, source_type: str) -> dict[str, str] | None:
        return await asyncio.to_thread(self._get_sync, org_id, source_type)

    def _get_sync(self, org_id: uuid.UUID, source_type: str) -> dict[str, str] | None:
        client = self._get_client()
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=self._path(org_id, source_type),
                mount_point=_MOUNT_POINT,
                raise_on_deleted_version=True,
            )
        except hvac.exceptions.InvalidPath:
            return None  # never written -- an honest, valid "not configured", not an error
        except Exception as exc:
            raise StorageError(
                "VaultSecretStore: failed to read connector secret",
                context={
                    "org_id": str(org_id),
                    "source_type": source_type,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            ) from exc
        return resp["data"]["data"]

    async def delete(self, org_id: uuid.UUID, source_type: str) -> None:
        await asyncio.to_thread(self._delete_sync, org_id, source_type)

    def _delete_sync(self, org_id: uuid.UUID, source_type: str) -> None:
        client = self._get_client()
        try:
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=self._path(org_id, source_type), mount_point=_MOUNT_POINT
            )
        except hvac.exceptions.InvalidPath:
            return  # idempotent: already gone
        except Exception as exc:
            raise StorageError(
                "VaultSecretStore: failed to delete connector secret",
                context={
                    "org_id": str(org_id),
                    "source_type": source_type,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            ) from exc
