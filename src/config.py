"""Application configuration via pydantic-settings (all values from env or Vault)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration; values come from environment variables only.

    No defaults for secrets — missing required vars raise ValidationError at
    startup, preventing silent misconfigurations in production.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

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

    # mTLS (internal service-to-service)
    tls_cert_path: str | None = Field(default=None, description="Path to service TLS certificate")
    tls_key_path: str | None = Field(default=None, description="Path to service TLS private key")
    tls_ca_path: str | None = Field(
        default=None, description="Path to CA bundle for mTLS verification"
    )
