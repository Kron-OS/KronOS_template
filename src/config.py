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

    # Database
    database_url: SecretStr = Field(description="Postgres DSN, e.g. postgresql+asyncpg://...")

    # Redis
    redis_url: SecretStr = Field(description="Redis DSN, e.g. redis://...")

    # MinIO / S3
    minio_endpoint: str = Field(description="MinIO endpoint, e.g. minio:9000")
    minio_access_key: SecretStr
    minio_secret_key: SecretStr
    minio_use_tls: bool = True
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
