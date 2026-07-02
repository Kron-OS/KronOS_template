"""Application configuration via pydantic-settings (all values from env or Vault)."""

from __future__ import annotations

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
    # Comma-separated origins allowed to call the API (CORSMiddleware) *and*
    # to PUT directly to MinIO presigned URLs (bucket CORS) — the browser
    # enforces CORS on both independently. Read from the same CORS_ALLOWED_
    # ORIGINS env var that src/external/fastapi_app.py reads directly via
    # os.getenv (it avoids constructing Settings() at import time so the
    # module stays importable without a full env in tests); keep both in
    # sync if you change the default here.
    cors_allowed_origins: str = "http://localhost,http://localhost:5173,http://localhost:4173"

    # Database
    database_url: SecretStr = Field(description="Postgres DSN, e.g. postgresql+asyncpg://...")

    # Redis
    redis_url: SecretStr = Field(description="Redis DSN, e.g. redis://...")

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
    minio_public_endpoint: str | None = Field(
        default=None,
        description="Browser-facing MinIO endpoint for presigned URLs, e.g. localhost:9000",
    )
    # Canonical bucket names (Project_Specifications.md §2): quarantine is
    # "<prefix>-<org_alias>-quarantine" and evidence is "<prefix>-<org_alias>".
    # The prefix is "kronos-evidence"; scripts/provision_buckets.sh must match.
    minio_quarantine_bucket_prefix: str = "kronos-evidence"
    minio_evidence_bucket_prefix: str = "kronos-evidence"
    minio_default_retention_days: int = 2555  # 7 years

    # OpenSearch
    opensearch_url: str = Field(description="OpenSearch endpoint, e.g. https://opensearch:9200")
    opensearch_username: SecretStr
    opensearch_password: SecretStr

    # Keycloak
    keycloak_url: str = Field(description="Keycloak base URL, e.g. https://auth.example.com")
    keycloak_realm: str = "kronos"
    keycloak_client_id: str = "kronos-backend"
    keycloak_client_secret: SecretStr

    # Vault
    vault_url: str = Field(description="HashiCorp Vault URL, e.g. https://vault:8200")
    vault_token: SecretStr

    # Celery
    celery_broker_url: SecretStr = Field(description="Celery broker, defaults to Redis URL")
    celery_result_backend: SecretStr

    # Upload limits
    max_upload_bytes: int = 1_073_741_824  # 1 GB
    presigned_url_expiry_seconds: int = 3600

    # Step-up ticket store: "memory" (single replica only) or "redis" (shared
    # across workers/replicas). Production with >1 backend replica MUST use
    # "redis"; otherwise a ticket issued by one replica is unknown to another.
    step_up_ticket_store: str = "memory"

    # OpenSearch Dashboards (iframe embed)
    opensearch_dashboards_url: str | None = Field(
        default=None,
        description="OS Dashboards base URL for timeline iframe embed, e.g. http://opensearch-dashboards:5601",
    )

    # RFC 3161 TSA
    tsa_url: str | None = Field(
        default=None,
        description="RFC 3161 TSA endpoint, e.g. http://tsa:318/api/v1/timestamp",
    )

    # ClamAV antivirus
    clamd_host: str = Field(default="localhost", description="clamd TCP host")
    clamd_port: int = Field(default=3310, description="clamd TCP port")

    # mTLS (internal service-to-service)
    tls_cert_path: str | None = Field(default=None, description="Path to service TLS certificate")
    tls_key_path: str | None = Field(default=None, description="Path to service TLS private key")
    tls_ca_path: str | None = Field(
        default=None, description="Path to CA bundle for mTLS verification"
    )

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]
