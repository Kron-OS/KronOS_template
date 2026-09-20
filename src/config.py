"""Application configuration via pydantic-settings (all values from env or Vault)."""

from __future__ import annotations

import os
from typing import Literal

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration; values come from environment variables only.

    No defaults for secrets — missing required vars raise ValidationError at
    startup, preventing silent misconfigurations in production.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # Gap Audit Milestone MM: `docker-compose.prod.yml` used to bake
        # resolved Postgres/Redis DSNs (with plaintext passwords) directly
        # into kronos-backend/celery-worker/db-migrate's `environment:`
        # block — `docker inspect --format '{{json .Config.Env}}'` returned
        # them verbatim (see poc/backend_prod_secret_config_env_exposure/
        # for the real, captured repro+fix). pydantic-settings 2.14.2's
        # real, current `secrets_dir` SettingsConfigDict option (verified
        # against this repo's own installed version — see that PoC's
        # README for the exact source read) resolves a field from a file
        # named after the field (case-insensitively) under this directory,
        # e.g. DATABASE_URL from <secrets_dir>/database_url. `None`
        # (the default whenever KRONOS_SECRETS_DIR is unset, e.g.
        # docker-compose.dev.yml) disables this source entirely and
        # preserves the existing plain-env-var-only behaviour completely
        # unchanged — dev never sets this var. Set
        # KRONOS_SECRETS_DIR=/run/secrets in production so the four DSN
        # fields below resolve from mounted Docker secret files instead.
        # This var is a path *convention*, not a secret itself — safe to
        # pass as a plain `environment:` value, same spirit as
        # POSTGRES_PASSWORD_FILE naming a path rather than embedding a
        # credential.
        secrets_dir=os.environ.get("KRONOS_SECRETS_DIR") or None,
    )

    # Application
    app_name: str = "kronos"
    debug: bool = False
    log_level: str = "INFO"
    # Gates fail-open vs. fail-closed behaviour (e.g. ClamAV misconfiguration,
    # EVID-6) — "production" must never silently downgrade a security control.
    environment: Literal["development", "test", "production"] = "development"

    # Database
    database_url: SecretStr = Field(description="Postgres DSN, e.g. postgresql+asyncpg://...")

    # Redis
    redis_url: SecretStr = Field(description="Redis DSN, e.g. redis://...")

    # Continuous ingestion (roadmap M3/D1, poc/stream_ingest_redis/) -- a
    # separate DB number on the SAME shared Redis instance, so a stream's
    # own real burst/backpressure characteristics never contend with the
    # Celery broker/backend (DB 1/2) or step-up tickets (DB 0).
    stream_redis_db: int = 3

    # Collector ingest (roadmap M3/D2) -- real, enforced (not advisory)
    # per-(org,source) backpressure ceiling, and how long a content-hash
    # dedup key is remembered (must comfortably exceed any realistic
    # collector retry/backoff window; see EventDedupChecker's docstring for
    # why this trades unbounded storage growth for a bounded false-negative
    # window on very late retries).
    collector_max_stream_length: int = 1_000_000
    collector_dedup_ttl_seconds: int = 3600

    # MinIO / S3
    minio_endpoint: str = Field(description="MinIO endpoint, e.g. minio:9000")
    minio_access_key: SecretStr
    minio_secret_key: SecretStr
    minio_use_tls: bool = True
    # Browser-facing endpoint used ONLY to sign presigned upload/download URLs.
    # SigV4 signs the Host header, so a URL signed against the internal
    # Docker hostname (minio_endpoint) is cryptographically invalid once a
    # browser — which cannot resolve that hostname — sends the request to a
    # different Host. Falls back to minio_endpoint when unset (single-
    # hostname deployments where the app and clients share a network).
    #
    # May be a bare "host:port" (scheme taken from minio_use_tls, the
    # original behavior) or a full "scheme://host:port" URL to override the
    # scheme independently of minio_use_tls — needed when the internal
    # backend->MinIO hop stays plain HTTP but the browser reaches MinIO's
    # presigned URLs via a TLS-terminating reverse proxy in front of it
    # (see startup.py's _resolve_minio_public_endpoint_url()).
    minio_public_endpoint: str | None = Field(
        default=None,
        description="Browser-facing MinIO endpoint for presigned URLs, e.g. localhost:9000 or https://minio.example.com",
    )
    # Canonical bucket names (Project_Specifications.md §2): quarantine is
    # "<prefix>-<org_alias>-quarantine" and evidence is "<prefix>-<org_alias>".
    # The prefix is "kronos-evidence"; scripts/provision_buckets.sh must match.
    minio_quarantine_bucket_prefix: str = "kronos-evidence"
    minio_evidence_bucket_prefix: str = "kronos-evidence"
    # Project_Specifications.md §2 "Retention Period": 365 days is the
    # spec-authoritative default, configurable per case/org (COMP-5 — this
    # previously disagreed with scripts/provision_buckets.sh's 365d default).
    minio_default_retention_days: int = 365
    # Derived-artifact bucket (Milestone EEEEE, poc/minio_derived_artifact/):
    # a SEPARATE, non-WORM bucket for regenerable content extracted on
    # demand from evidence (e.g. windows.dumpfiles byte extraction) --
    # real-verified that omitting ObjectLockEnabledForBucket entirely (not
    # just passing False) produces a genuinely non-WORM bucket where
    # delete/regenerate works, unlike the evidence bucket.
    minio_derived_bucket_prefix: str = "kronos-derived"

    # OpenSearch
    opensearch_url: str = Field(description="OpenSearch endpoint, e.g. https://opensearch:9200")
    opensearch_username: SecretStr
    opensearch_password: SecretStr
    # Dev OpenSearch runs with DISABLE_SECURITY_PLUGIN=true (docker-compose.dev.yml)
    # — the Security plugin's REST API (roles, DLS) doesn't exist there, so
    # TimelineIngestionService must skip ensure_generic_tenant_role() in that
    # mode. ISM (index rollover) is a separate, always-present plugin —
    # unaffected, never gated.
    # Production Keycloak+OpenSearch-Security deployments must set this true.
    opensearch_security_enabled: bool = Field(
        default=False,
        description="True only when the OpenSearch Security plugin is enabled (prod)",
    )

    # Rule-pack lifecycle (roadmap M2/C3) -- Cosign binary used to verify
    # signed third-party rule packs (src/adapter/signing/cosign_verifier.py).
    # Defaults to relying on PATH, matching how the rest of the toolchain
    # (Trivy, Cosign in CI) is invoked -- override when the binary isn't on
    # PATH (e.g. a pinned path in a Chainguard/Wolfi image).
    cosign_binary_path: str = "cosign"

    # Keycloak
    keycloak_url: str = Field(description="Keycloak base URL, e.g. https://auth.example.com")
    keycloak_realm: str = "kronos"
    keycloak_client_id: str = "kronos-backend"
    keycloak_client_secret: SecretStr
    # The SPA's public Keycloak client (keycloak-js in frontend/src/keycloak.ts,
    # VITE_KEYCLOAK_CLIENT_ID=kronos-frontend by default). A refresh token is
    # bound to the client it was issued to — /auth/refresh must redeem it as
    # THIS client, never as keycloak_client_id (kronos-backend, confidential,
    # a different client) or Keycloak rejects it: "Token client and authorized
    # client don't match".
    keycloak_spa_client_id: str = "kronos-frontend"

    # Vault
    vault_url: str = Field(description="HashiCorp Vault URL, e.g. https://vault:8200")
    vault_token: SecretStr

    # Per-org connector secret storage (connector marketplace,
    # `/admin/connectors`) -- deliberately a DEDICATED least-privilege
    # AppRole against a dedicated `kronos-connectors` KV-v2 mount, never
    # the root `vault_token` above (that stays reserved for KES/manual
    # operator use). See poc/vault_secret_store/README.md for the real
    # verification and docker-compose.dev.yml's `vault-connectors-init`
    # service for how the creds file this points at is minted.
    vault_connectors_approle_creds_file: str | None = Field(
        default=None,
        description=(
            "Path to a JSON file {role_id, secret_id} for the "
            "kronos-connectors-app AppRole. None means VaultSecretStore is "
            "not configured (an honest, valid dev/test state)."
        ),
    )

    # Celery
    celery_broker_url: SecretStr = Field(description="Celery broker, defaults to Redis URL")
    celery_result_backend: SecretStr

    # Upload limits. Must stay <= clamd's real StreamMaxLength/MaxFileSize
    # (docker-compose.dev.yml's CLAMD_CONF_StreamMaxLength/MaxFileSize/
    # MaxScanSize) -- otherwise a file this service accepts can still exceed
    # what the AV scanner will actually stream-scan, and clamd closes the
    # connection mid-transfer (confirmed against a real clamd: a real 239 MB
    # E01 upload hit clamd's compiled-in 100 MB StreamMaxLength default and
    # crashed with a raw BrokenPipeError, deterministically on every retry --
    # see poc/clamav/run_poc_large_file.py). 5 GB accommodates real forensic
    # disk images (E01/EWF), which routinely exceed 1 GB.
    max_upload_bytes: int = 5_368_709_120  # 5 GiB
    # 15 min per Project_Specifications.md §2 "Security Measures for Intake" (EVID-8).
    presigned_url_expiry_seconds: int = 900

    # Step-up ticket store: "memory" (single replica only) or "redis" (shared
    # across workers/replicas). Production with >1 backend replica MUST use
    # "redis"; otherwise a ticket issued by one replica is unknown to another.
    step_up_ticket_store: str = "memory"

    # OpenSearch Dashboards (iframe embed). Browser-facing, like
    # KEYCLOAK_PUBLIC_URL — the frontend loads this directly as the iframe
    # src, so it must be a host the browser can resolve (e.g.
    # http://localhost:5601 in dev, https://os.example.com in prod), not a
    # Docker-internal hostname such as opensearch-dashboards:5601.
    opensearch_dashboards_url: str | None = Field(
        default=None,
        description="Browser-facing OS Dashboards base URL for timeline iframe embed, e.g. http://localhost:5601",
    )
    # Docker-internal counterpart of opensearch_dashboards_url above, for the
    # backend's own server-to-server saved-objects calls (index-pattern
    # auto-provisioning, DashboardsIndexPatternProvisioner) — never
    # browser-facing, so no TLS/nginx hop needed, e.g.
    # http://opensearch-dashboards:5601 in dev.
    opensearch_dashboards_internal_url: str | None = Field(
        default=None,
        description="Docker-internal OS Dashboards base URL for backend saved-objects provisioning",
    )

    # RFC 3161 TSA
    tsa_url: str | None = Field(
        default=None,
        description="RFC 3161 TSA endpoint, e.g. http://tsa:318/api/v1/timestamp",
    )

    # ClamAV antivirus
    clamd_host: str = Field(default="localhost", description="clamd TCP host")
    clamd_port: int = Field(default=3310, description="clamd TCP port")

    # Plaso heavy parser
    # Path to kronos-plaso-worker.py inside the container that runs
    # FirecrackerLauncher (the q.parse.plaso Celery consumer). Defaults to
    # today's computed source-tree-relative path for backward compat; the new
    # celery-worker-plaso service in docker-compose.dev.yml sets this
    # explicitly so it doesn't depend on __file__ directory-depth matching
    # between the container and the source tree.
    plaso_worker_path: str | None = Field(
        default=None,
        description="Absolute path to kronos-plaso-worker.py; None uses computed default",
    )

    # Volatility3 heavy parser (roadmap E5) -- same reasoning as
    # plaso_worker_path immediately above: path to kronos-volatility-worker.py
    # inside the container that runs VolatilityLauncher (shares the same
    # q.parse.plaso Celery consumer/container as Plaso -- see
    # docker/Dockerfile.plaso-worker's own comment on why volatility3's real
    # dependency footprint is light enough to share that image rather than
    # needing its own).
    volatility_worker_path: str | None = Field(
        default=None,
        description="Absolute path to kronos-volatility-worker.py; None uses computed default",
    )

    # Real, verified finding (2026-09-20): this worker calls volatility3's
    # framework API directly rather than its CLI (vol.py), so
    # volatility3.framework.constants.REMOTE_ISF_URL is never set by
    # anything -- meaning every memory image whose exact kernel/PDB build
    # has no locally pre-installed ISF fails every symbol-dependent plugin
    # with UnsatisfiedException, regardless of RAM/CPU/network, even though
    # the OS family itself is correctly identified (banners.Banners needs
    # no symbol table). Default value is volatility3's own project's real,
    # CI-verified remote ISF index (see
    # github.com/volatilityfoundation/volatility3 PR #1316, "Enable Remote
    # ISF server for Linux testcases") -- a community-maintained,
    # dwarf2json-generated symbol index covering thousands of real Linux
    # kernel builds. Real-verified end-to-end against a genuine 4GB user
    # upload (Ubuntu 6.5.0-41-generic) that previously failed every plugin
    # with UnsatisfiedException: after wiring this in, automagic resolved
    # the kernel and linux.psscan recovered 1493 real process rows from the
    # same file -- see poc/volatility_remote_isf/README.md. Empty string
    # disables remote lookup entirely (fully offline/air-gapped
    # deployments) -- the worker only sets constants.REMOTE_ISF_URL when
    # this is truthy, so an empty value reproduces the exact pre-fix
    # behavior, not a new failure mode.
    volatility_remote_isf_url: str = Field(
        default="https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json",
        description="Remote ISF index URL for volatility3 symbol auto-download; empty disables",
    )

    # Case/ticket integration (roadmap M7/H4) -- a single, deployment-wide
    # outbound webhook URL for WebhookTicketingSystem, the same "one global
    # endpoint, not per-org config" shape this codebase already uses for
    # every other external adapter (keycloak_url, opensearch_url, vault_url
    # above are all deployment-wide too, never looked up per-org) -- see
    # ticket_sync_action.py's own module docstring for why no per-org
    # override was built this pass. None until an operator configures a
    # real external ticketing system's inbound-webhook URL.
    ticketing_webhook_url: str | None = Field(
        default=None,
        description="Outbound webhook URL for the external ITSM/ticketing system, e.g. https://itsm.example.com/webhooks/kronos",
    )

    # mTLS (internal service-to-service)
    tls_cert_path: str | None = Field(default=None, description="Path to service TLS certificate")
    tls_key_path: str | None = Field(default=None, description="Path to service TLS private key")
    tls_ca_path: str | None = Field(
        default=None, description="Path to CA bundle for mTLS verification"
    )

    @field_validator(
        "database_url",
        "redis_url",
        "celery_broker_url",
        "celery_result_backend",
        mode="before",
    )
    @classmethod
    def _reject_blank_dsn(cls, value: object, info: ValidationInfo) -> object:
        """Fail loudly on a blank DSN instead of silently connecting nowhere.

        Closes the one gap `secrets_dir`'s own file-lookup contract leaves
        open: a secret file that exists but is empty (or whitespace-only —
        e.g. a botched provisioning step that `touch`ed the file before
        writing it) resolves to `""`, which is a syntactically valid `str`
        and would otherwise sail past the "field required" check pydantic
        already enforces for a genuinely *missing* value, only to fail much
        later and far less clearly inside asyncpg/redis-py. A missing
        secrets_dir file, or a missing plain env var, still correctly hits
        that pre-existing "field required" ValidationError unchanged.
        """
        if isinstance(value, str) and not value.strip():
            raise ValueError(
                f"{info.field_name} resolved to an empty/whitespace-only value — "
                "check that the backing env var, or the secrets_dir file "
                "(see KRONOS_SECRETS_DIR), actually has real content"
            )
        return value
