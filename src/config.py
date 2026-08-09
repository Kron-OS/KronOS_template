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

    # Splunk HTTP Event Collector sink (roadmap M-integrations/R2) -- same
    # "one global endpoint, not per-org config" shape as ticketing_webhook_url
    # above. Both splunk_hec_url and splunk_hec_token must be set for
    # get_splunk_hec_sink() to construct a real SplunkHecSink; either being
    # None means "not configured," an honest, legitimate dev/test state, not
    # an error (mirrors get_timestamp_service()'s own None-is-valid contract).
    splunk_hec_url: str | None = Field(
        default=None,
        description=(
            "Full Splunk HEC event-collector endpoint URL, e.g. "
            "https://splunk.example.com:8088/services/collector/event"
        ),
    )
    splunk_hec_token: SecretStr | None = Field(
        default=None,
        description="Splunk HEC token -- sent as 'Authorization: Splunk <token>', never logged.",
    )
    splunk_hec_source: str = Field(
        default="kronos:detection_sink",
        description="Splunk HEC 'source' field applied to every pushed Detection event.",
    )
    splunk_hec_sourcetype: str = Field(
        default="kronos:detection",
        description="Splunk HEC 'sourcetype' field applied to every pushed Detection event.",
    )
    splunk_hec_index: str | None = Field(
        default=None,
        description="Splunk HEC 'index' field -- omitted (token's default index applies) if unset.",
    )
    splunk_hec_verify_tls: bool = Field(
        default=True,
        description="Whether to verify the Splunk HEC endpoint's TLS cert (httpx 'verify=').",
    )

    # Generic CEF-over-syslog sink (roadmap M-integrations/R3) -- the
    # vendor-neutral universal fallback (no auth, fire-and-forget). Same
    # "one global endpoint, not per-org config" shape as splunk_hec_url
    # above. cef_syslog_host must be set for get_cef_syslog_sink() to
    # construct a real SyslogIntegrationSink; None means "not configured,"
    # an honest, legitimate dev/test state (mirrors splunk_hec_url's own
    # None-is-valid contract), never an error.
    cef_syslog_host: str | None = Field(
        default=None,
        description=(
            "Hostname/IP of the real CEF-over-syslog receiver "
            "(e.g. a QRadar/generic SIEM syslog listener)."
        ),
    )
    cef_syslog_port: int = Field(
        default=514,
        description=(
            "Port of the real CEF-over-syslog receiver "
            "(514 is syslog's own conventional default)."
        ),
    )
    cef_syslog_protocol: str = Field(
        default="tcp",
        description=(
            "'tcp' or 'udp' -- transport protocol for the CEF-over-syslog push "
            "(SyslogTransportProtocol)."
        ),
    )
    cef_device_vendor: str = Field(
        default="KronOS",
        description="CEF header 'Device Vendor' field applied to every pushed Detection event.",
    )
    cef_device_product: str = Field(
        default="DetectionSink",
        description="CEF header 'Device Product' field applied to every pushed Detection event.",
    )
    cef_device_version: str = Field(
        default="1.0",
        description="CEF header 'Device Version' field applied to every pushed Detection event.",
    )

    # Microsoft Sentinel Logs Ingestion API sink (roadmap M-integrations/R4)
    # -- the OAuth2 + rigid-pre-provisioned-schema case. Same "one
    # global endpoint, not per-org config" shape as splunk_hec_url/
    # cef_syslog_host above. ALL FOUR of sentinel_dce_endpoint/
    # sentinel_dcr_immutable_id/sentinel_client_id/sentinel_client_secret
    # must be set for get_sentinel_sink() to construct a real
    # SentinelHttpSink; any being None means "not configured," an honest,
    # legitimate dev/test state (mirrors splunk_hec_url's own
    # None-is-valid contract), never an error.
    sentinel_dce_endpoint: str | None = Field(
        default=None,
        description=(
            "Real Data Collection Endpoint (or DCR-embedded logs-ingestion "
            "endpoint) base URL, e.g. "
            "https://my-dce-5kyl.eastus-1.ingest.monitor.azure.com"
        ),
    )
    sentinel_dcr_immutable_id: str | None = Field(
        default=None,
        description="The real DCR's own immutableId, e.g. dcr-000a00a000a00000a000000aa000a0aa.",
    )
    sentinel_stream_name: str = Field(
        default="Custom-KronOSDetection",
        description="The DCR streamDeclaration name matching SentinelDetectionMapper's schema.",
    )
    sentinel_api_version: str = Field(
        default="2023-01-01",
        description="Logs Ingestion API api-version query parameter (pinned, real, current value).",
    )
    sentinel_tenant_id: str | None = Field(
        default=None, description="Entra ID (Azure AD) tenant id for the OAuth2 token endpoint."
    )
    sentinel_client_id: str | None = Field(
        default=None,
        description="Entra ID app registration's Application (client) ID, granted the DCR's "
        "Monitoring Metrics Publisher role.",
    )
    sentinel_client_secret: SecretStr | None = Field(
        default=None, description="Entra ID app registration's client secret -- never logged."
    )
    sentinel_oauth_scope: str = Field(
        default="https://monitor.azure.com/.default",
        description=(
            "OAuth2 client-credentials scope -- the real, documented Azure "
            "public cloud Logs Ingestion API audience "
            "(https://monitor.azure.com) plus the v2.0 token endpoint's "
            "own '/.default' suffix convention."
        ),
    )
    sentinel_verify_tls: bool = Field(
        default=True,
        description="Whether to verify the Sentinel DCE endpoint's TLS cert (httpx 'verify=').",
    )

    # Microsoft Defender Graph Security API alerts_v2 poll source (roadmap
    # M-integrations/Q4) -- same "all three must be set, honest disabled
    # state otherwise" shape as splunk_hec_url/splunk_hec_token above. No
    # real Entra ID tenant exists in this sandbox (verified: no
    # AZURE_TENANT_ID/AZURE_CLIENT_ID/ENTRA-related config anywhere in this
    # repo's env/secrets setup) -- these three being unset is the honest,
    # expected state until a real deployment provisions a real Entra ID app
    # registration with SecurityAlert.Read.All.
    defender_tenant_id: str | None = Field(
        default=None,
        description=(
            "Entra ID tenant ID (GUID or verified domain) for the Defender "
            "Graph API app registration."
        ),
    )
    defender_client_id: str | None = Field(
        default=None,
        description=(
            "Entra ID app registration (client) ID for the Defender Graph "
            "API OAuth2 client-credentials grant."
        ),
    )
    defender_client_secret: SecretStr | None = Field(
        default=None,
        description="Entra ID app registration client secret -- never logged.",
    )
    defender_graph_base_url: str = Field(
        default="https://graph.microsoft.com/v1.0",
        description=(
            "Microsoft Graph API base URL. Override for a real local stand-in "
            "server in test/dev, or a sovereign-cloud Graph endpoint in prod."
        ),
    )

    # mTLS (internal service-to-service)
    tls_cert_path: str | None = Field(default=None, description="Path to service TLS certificate")
    tls_key_path: str | None = Field(default=None, description="Path to service TLS private key")
    tls_ca_path: str | None = Field(
        default=None, description="Path to CA bundle for mTLS verification"
    )
