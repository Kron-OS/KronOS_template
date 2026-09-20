# Connector marketplace (`/admin/connectors`) — verification record

Plan: `/home/reca/.claude/plans/abstract-bubbling-locket.md` (Phases 0–7, all
complete). This document is the real, captured verification trail per
CLAUDE.md Section F — every claim below was actually run against the live
dev stack (`docker compose -p docker -f docker/docker-compose.dev.yml`),
not inferred from code review.

## What was built

- **Phase 0**: Real HashiCorp Vault wired into the app for the first time
  (`vault` + `vault-connectors-init` services, dedicated `kronos-connectors`
  KV-v2 mount + least-privilege AppRole). PoC: `poc/vault_secret_store/`.
- **Phases 1–3**: `ConnectorDefinition`/`ConnectorParameterSpec` (domain),
  `ConnectorCatalog`/`ConnectorConfigService`/`SecretStore` (application),
  `PostgresConnectorConfigRepository`/`VaultSecretStore` (adapter), migration
  `33dfde5b0b1f_add_connector_configs_table`. Circuit breaker (auto-disable
  after 5 consecutive failures) and reversible enable/disable kill switch.
- **Phase 4**: `celery_defender.py` rewritten from one hardcoded global org
  to iterating every org with an enabled `ms-defender-alerts` config, with a
  Vault-outage circuit breaker distinct from per-org failures. New
  `admin_connector_config.py` routes (catalog/config CRUD/disable/enable),
  step-up gated, rate-limited. New `ConnectorMarketplacePage.tsx` frontend.
- **Phase 5**: `SyncDetectionToSiemAction` rewritten to resolve each org's
  own Splunk HEC/CEF syslog/Sentinel config at push time
  (`build_sink_and_mapper_from_config`) instead of one global sink.
- **Phase 6**: `PushConnectorKeyPanel.tsx` — self-service API-key UI for
  Wazuh/Suricata/Zeek, wired to the pre-existing (previously frontend-less)
  `admin_integration_sources.py` routes.
- **Phase 7**: Removed all now-dead global `Settings` fields
  (`splunk_hec_*`, `cef_syslog_*`/`cef_device_*`, `sentinel_*`,
  `defender_*`) and their `configure_*_from_settings()` wiring functions,
  docker-compose env vars, and the now-obsolete global-Defender special
  case in `admin_connector_status.py`.

## Real end-to-end runs (this session, live dev stack)

1. **Vault**: real write/read/delete/list via AppRole login against the
   real dev-compose Vault; two fake org_ids proven never to collide
   (`poc/vault_secret_store/output.txt`).
2. **Defender POLL circuit breaker**: configured a real per-org Defender
   config with fake-but-structurally-valid credentials; ran
   `run_defender_poll_cycle()` against the real Microsoft OAuth2 token
   endpoint (real auth failure, real per-org `record_failure`); repeated to
   5 consecutive failures and confirmed `enabled` flipped to `false` +
   `auto_disabled_at` set in real Postgres; confirmed the disabled org was
   then skipped by the next cycle with zero log noise.
3. **CEF syslog SINK, real UDP delivery**: configured a real per-org
   CEF-syslog connector pointed at a throwaway listener container on the
   same Docker network; pushed a real `Detection` through
   `SyncDetectionToSiemAction`; the listener received a genuine
   RFC 3164-framed CEF line containing that org's own org ID, case ID, and
   ATT&CK tags — confirmed per-org destination routing works for real, not
   just in unit tests.
4. **Wazuh PUSH, real HTTP ingest**: provisioned a real API key for a fresh
   test org via `IntegrationSourceKeyRepository`; sent a real captured
   Wazuh `sshd` alert (shape verified in `poc/integration_source_wazuh/`)
   to `POST https://kronos.local/api/integrations/push/wazuh` with the key
   in `X-KronOS-Source-Key`, through real nginx/TLS; got a real `202`
   with `accepted: true`; confirmed a real
   `integration_source.push_ingested` audit row landed in Postgres for
   that exact org.
5. **Full per-org config lifecycle** (configure → redacted read → disable
   → confirm `resolve_runtime_config` returns `None` → re-enable → confirm
   secret resolves again → delete → confirm both the Postgres row and the
   Vault secret are gone): ran end-to-end against the real backend
   container, real Postgres, real Vault. All steps behaved exactly as
   designed.
6. **Real HTTP catalog browse**: logged in as the real `admin` Keycloak
   user (OIDC PKCE flow through real Keycloak), called
   `GET https://kronos.local/api/admin/connectors/catalog` — real `200`
   with all 7 connector definitions and correct parameter lists.
7. **Frontend**: `tsc -b --noEmit` clean, 135 Vitest tests passing, real
   `vite build` served through nginx and reachable over HTTPS.
8. **Full test suite**: 2042 unit tests + 11 integration tests (real
   testcontainers Postgres + Vault) passing after every phase, including
   after the Phase 7 cleanup removed ~700 lines of now-dead global-config
   wiring.

## Known, honest residual gaps (not fixed this pass, flagged not hidden)

- **Live browser step-up (aal2/TOTP) click-through was not performed.** The
  `admin` test user's real Keycloak token is `acr=aal1`; exercising the
  actual MFA redirect requires a registered TOTP secret this session didn't
  have saved. The step-up gating logic itself (ticket issuance/consumption,
  401 challenge, one-time-use enforcement) is thoroughly covered by 12
  passing `TestClient` tests against the exact same production route code
  (`tests/unit/test_admin_connector_config_routes.py`) — the only thing not
  separately re-proven is the browser-side OIDC redirect dance, which is
  pre-existing, unmodified infrastructure (`apiClient`'s axios interceptor)
  already relied on by every other step-up-gated feature in this app.
- **Vault ACL isolation is application-layer, not Vault-native.** The
  `kronos-connectors-app` AppRole's policy is static and mount-wide, not
  per-org. Documented explicitly in `poc/vault_secret_store/README.md` and
  `vault_secret_store.py`'s own module docstring. Real per-org Vault ACL
  templating is a valid future hardening, out of scope for this pass.
- **Per-org ingestion volume quota** (`OrgIngestionQuota`, cross-cutting
  hardening section item 1 of the plan) was not built this pass — the
  circuit breaker (auto-disable after repeated failures) is real and
  verified, but a hard per-org event-rate ceiling is not. Flagged as
  follow-up, not silently dropped.
- **ISM aggressive-tier verification** (cross-cutting hardening item 2:
  confirming new connector stream indices actually get the
  `ism_policy_stream_aggressive.json` tier, not the default) was not
  re-checked this pass.

## Cleanup performed

Test artifacts created during this verification (throwaway orgs, a
short-lived `kronos-poc-udp-listener` container) were removed at the end of
each step; none were left running or persisted beyond what's captured
above.
