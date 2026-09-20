# PoC: per-org connector secret storage on real Vault

Per CLAUDE.md Section F: `Settings.vault_url`/`vault_token` exist in
`src/config.py` and 4 dev-compose services set a `VAULT_URL` env var
pointing at a `vault` host, but `docker-compose.dev.yml` had **no `vault:`
service at all**, no `hvac` in `pyproject.toml`, and zero call sites for
`settings.vault_url`/`settings.vault_token` anywhere outside `config.py`
itself (confirmed by grep before writing this PoC). Vault has never
actually been called by this app. This PoC runs a real Vault 1.17 +
real hvac 2.4.0 client against a real dedicated KV-v2 mount before any
`src/` code assumes it works.

## Pinned versions

- `hashicorp/vault:1.17` — matches `docker-compose.prod.yml`'s existing
  KES-Vault pin, and the real dev-compose `vault` service added this pass.
- `hvac==2.4.0` — verified current latest via `pip index versions hvac`
  at implementation time (2.3.0/2.2.0/... below it). Pinned in
  `pyproject.toml`.

## Real docs used

- `developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2` — KV-v2 HTTP
  semantics. The important gotcha: the real HTTP paths are
  `<mount>/data/<path>` (read/write) and `<mount>/metadata/<path>`
  (list/delete-all-versions) — hvac's `secrets.kv.v2.*` helpers hide this
  prefixing, but the Vault *policy* below has to grant both prefixes
  explicitly, or writes succeed while `list_secrets`/full delete 403.
- `python-hvac.org` `Client.secrets.kv.v2` reference for
  `create_or_update_secret` / `read_secret_version` /
  `delete_metadata_and_all_versions` / `list_secrets` signatures, and
  `Client.auth.approle.login` for the AppRole login flow.

## What this proves (real output in `output.txt`)

1. A dedicated `kronos-connectors` KV-v2 mount + a least-privilege
   `kronos-connectors-app` policy + AppRole (not the root token) can
   authenticate and read/write/list/delete real secrets.
2. Two different org_ids' secrets at the same path suffix
   (`{org_id}/sentinel`) round-trip correctly and never collide — writing,
   reading, and deleting one org's secret has zero effect on the other's.
3. Reading a path that was never written raises a clean `hvac.exceptions.InvalidPath`
   (not a crash, not an empty-but-present value) — this is the exception
   `VaultSecretStore.get()` (Phase 3 of the connector-marketplace plan)
   must catch and translate to `None`, matching the codebase's existing
   `OrgQuota` "`None` means not configured" convention.

## Real, explicit limitation — read before assuming Vault enforces tenant isolation

The `kronos-connectors-app` AppRole's policy is **static and mount-wide**:
`path "kronos-connectors/data/*"` grants read/write to every org's path
under the mount, not just one org's. The single backend/Celery process
authenticates once with this one AppRole and can technically read *any*
org's secret through the Vault API.

**The actual collision boundary in this design is application-layer path
discipline** — `ConnectorConfigService`/`VaultSecretStore` (Phase 3) always
derive the `org_id` segment of the path from an authenticated
`TenantContext`, never from client-supplied input, so no code path exists
that lets one tenant *ask* to read another's secret. This PoC proves the
storage layer round-trips correctly per-path; it does **not** prove (and
does not claim) Vault-native ACL isolation between tenants at the token
level. A stronger hardening — dynamic Vault policies templated on a
per-org claim, so even a compromised backend process's Vault token could
only reach its own org's paths — is real, valuable future work, explicitly
out of scope for this pass.

## How to run

```sh
cd poc/vault_secret_store
docker compose -p kronos-poc-vaultconnectors -f docker-compose.yml up -d vault
docker compose -p kronos-poc-vaultconnectors -f docker-compose.yml run --rm vault-init
# copy the printed role_id/secret_id into the next command:
python3 run_poc.py <role_id> <secret_id>
# teardown:
docker compose -p kronos-poc-vaultconnectors -f docker-compose.yml down -v
```

Isolated project name (`kronos-poc-vaultconnectors`) and port (`18220`,
not `8200`) so this can run alongside the real dev-stack Vault or another
PoC on the same host without collision.

## Minor note, not a gap

`read_secret_version(..., raise_on_deleted_version=True)` emits a
`DeprecationWarning` under hvac 2.4.0 (the default flips in hvac 3.0.0) —
harmless today, cosmetic. Phase 3's real `VaultSecretStore` should pass
this kwarg explicitly either way so behavior doesn't silently change on a
future hvac upgrade.
