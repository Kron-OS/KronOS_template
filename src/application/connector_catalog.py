"""Static catalog of connector types the marketplace can offer (`/admin/connectors`).

Parameters are mapped 1:1 from the real ``Settings`` fields already in
``src/config.py`` that these connectors currently read as GLOBAL, env-var-only
config -- this catalog is what lets an org override them per-org via
``ConnectorConfigService`` instead. Kept as a plain module-level tuple + a
thin lookup class rather than a registry-with-plugins pattern (unlike
``ParserRegistry``/``IntegrationSourceRegistry``): there is no runtime
behavior to dispatch here, only static metadata, so a registry abstraction
would be speculative machinery this doesn't need (CLAUDE.md's own
"no premature abstraction" guidance).
"""

from __future__ import annotations

from src.domain.connector import ConnectorDefinition, ConnectorMode, ConnectorParameterSpec

def _push_asset_notes(source_type: str, real_log_path: str, real_daemon: str) -> str:
    """Shared shape for the 3 PUSH connectors' asset-side notes -- the only
    thing that differs is which real log file/daemon ships to which
    source_type suffix. Endpoint path, header name, and TLS behavior are
    verified real (poc/integration_source_suricata_zeek/fluent-bit.conf;
    kronos.local is nginx-TLS-terminated, no client certificate needed)."""
    return (
        f"On the {real_daemon} host, ship {real_log_path} to KronOS: after generating an API key "
        f"below, configure your log shipper (fluent-bit's `http` output plugin is the real, "
        f"verified reference -- see poc/integration_source_suricata_zeek/fluent-bit.conf) to POST "
        f"each event as JSON to https://kronos.local/api/integrations/push/{source_type} with the "
        f"header `X-KronOS-Source-Key: <your API key>`. Standard HTTPS (TLS terminated by KronOS's "
        f"own nginx reverse proxy) -- no client certificate is required on your side."
    )


_PUSH_CONNECTORS: tuple[ConnectorDefinition, ...] = (
    ConnectorDefinition(
        source_type="wazuh",
        display_name="Wazuh",
        mode=ConnectorMode.PUSH,
        description="Wazuh alerts pushed to KronOS via a self-service API key.",
        asset_setup_notes=_push_asset_notes("wazuh", "alerts.json", "Wazuh manager"),
    ),
    ConnectorDefinition(
        source_type="suricata-eve",
        display_name="Suricata (eve.json)",
        mode=ConnectorMode.PUSH,
        description="Suricata eve.json alerts, shipped by fluent-bit, pushed via a self-service API key.",
        asset_setup_notes=_push_asset_notes("suricata-eve", "eve.json", "Suricata sensor"),
    ),
    ConnectorDefinition(
        source_type="zeek-json",
        display_name="Zeek (conn.log)",
        mode=ConnectorMode.PUSH,
        description="Zeek conn.log JSON, shipped by fluent-bit, pushed via a self-service API key.",
        asset_setup_notes=_push_asset_notes("zeek-json", "conn.log (JSON output)", "Zeek sensor"),
    ),
)

_DEFENDER = ConnectorDefinition(
    source_type="ms-defender-alerts",
    display_name="Microsoft Defender",
    mode=ConnectorMode.POLL,
    description="Polls Microsoft Defender for Endpoint alerts via Microsoft Graph on a schedule.",
    parameters=(
        ConnectorParameterSpec(name="defender_tenant_id", label="Tenant ID", secret=False, required=True),
        ConnectorParameterSpec(name="defender_client_id", label="Client ID", secret=False, required=True),
        ConnectorParameterSpec(
            name="defender_client_secret", label="Client Secret", secret=True, required=True
        ),
        ConnectorParameterSpec(
            name="defender_graph_base_url",
            label="Graph API Base URL",
            secret=False,
            required=False,
            default="https://api.security.microsoft.com",
        ),
    ),
    asset_setup_notes=(
        "In your Entra ID (Azure AD) tenant, create an app registration and grant it the "
        "Microsoft Graph *application* permission `SecurityAlert.Read.All`, then have a tenant "
        "admin grant admin consent. Create a client secret for it. No inbound firewall change or "
        "certificate is needed on your side -- KronOS calls out to Microsoft Graph on a schedule "
        "using this app registration's OAuth2 client-credentials grant; enter the tenant ID, "
        "client ID, and client secret here."
    ),
)

_SPLUNK_HEC = ConnectorDefinition(
    source_type="splunk-hec",
    display_name="Splunk HEC",
    mode=ConnectorMode.SINK,
    description="Pushes KronOS Detections to a Splunk HTTP Event Collector endpoint.",
    parameters=(
        ConnectorParameterSpec(name="splunk_hec_url", label="HEC URL", secret=False, required=True),
        ConnectorParameterSpec(name="splunk_hec_token", label="HEC Token", secret=True, required=True),
        ConnectorParameterSpec(
            name="splunk_hec_source", label="Source", secret=False, required=False, default="kronos"
        ),
        ConnectorParameterSpec(
            name="splunk_hec_sourcetype",
            label="Sourcetype",
            secret=False,
            required=False,
            default="_json",
        ),
        ConnectorParameterSpec(name="splunk_hec_index", label="Index", secret=False, required=False),
        ConnectorParameterSpec(
            name="splunk_hec_verify_tls",
            label="Verify TLS",
            secret=False,
            required=False,
            default="true",
        ),
    ),
    asset_setup_notes=(
        "In Splunk, create an HTTP Event Collector token (Settings > Data Inputs > HTTP Event "
        "Collector) and assign it to an index KronOS should write to. Your Splunk instance's HEC "
        "listener (typically port 8443 or 8088) must be reachable from KronOS's backend network. "
        "Enter the full event-collector URL (e.g. https://your-splunk:8088/services/collector/event) "
        "and the token below. If your HEC endpoint uses a self-signed/internal CA certificate, set "
        "Verify TLS to false rather than disabling verification platform-wide."
    ),
)

_CEF_SYSLOG = ConnectorDefinition(
    source_type="cef-syslog",
    display_name="CEF over Syslog",
    mode=ConnectorMode.SINK,
    description="Pushes KronOS Detections as CEF-formatted syslog messages.",
    parameters=(
        ConnectorParameterSpec(name="cef_syslog_host", label="Syslog Host", secret=False, required=True),
        ConnectorParameterSpec(name="cef_syslog_port", label="Syslog Port", secret=False, required=True),
        ConnectorParameterSpec(
            name="cef_syslog_protocol",
            label="Protocol",
            secret=False,
            required=False,
            default="udp",
        ),
        ConnectorParameterSpec(
            name="cef_device_vendor", label="Device Vendor", secret=False, required=False, default="KronOS"
        ),
        ConnectorParameterSpec(
            name="cef_device_product",
            label="Device Product",
            secret=False,
            required=False,
            default="DetectionSink",
        ),
        ConnectorParameterSpec(
            name="cef_device_version", label="Device Version", secret=False, required=False, default="1.0"
        ),
    ),
    asset_setup_notes=(
        "Your syslog receiver (e.g. a QRadar/generic SIEM syslog listener) must be listening on the "
        "host/port you configure below, over plain TCP or UDP -- CEF-over-syslog is unauthenticated "
        "and unencrypted per the standard (no certificate, no login), so this destination must be "
        "reachable from KronOS's backend network but should NOT be exposed to the public internet. "
        "Verified live this session: a real UDP listener on this port received a genuine "
        "RFC 3164-framed CEF line with this exact shape."
    ),
)

_SENTINEL = ConnectorDefinition(
    source_type="sentinel",
    display_name="Microsoft Sentinel",
    mode=ConnectorMode.SINK,
    description="Pushes KronOS Detections to a Microsoft Sentinel Data Collection Endpoint/Rule.",
    parameters=(
        ConnectorParameterSpec(
            name="sentinel_dce_endpoint", label="DCE Endpoint", secret=False, required=True
        ),
        ConnectorParameterSpec(
            name="sentinel_dcr_immutable_id", label="DCR Immutable ID", secret=False, required=True
        ),
        ConnectorParameterSpec(
            name="sentinel_stream_name", label="Stream Name", secret=False, required=True
        ),
        ConnectorParameterSpec(name="sentinel_tenant_id", label="Tenant ID", secret=False, required=True),
        ConnectorParameterSpec(name="sentinel_client_id", label="Client ID", secret=False, required=True),
        ConnectorParameterSpec(
            name="sentinel_client_secret", label="Client Secret", secret=True, required=True
        ),
        ConnectorParameterSpec(
            name="sentinel_oauth_scope",
            label="OAuth Scope",
            secret=False,
            required=False,
            default="https://monitor.azure.com/.default",
        ),
        ConnectorParameterSpec(
            name="sentinel_verify_tls",
            label="Verify TLS",
            secret=False,
            required=False,
            default="true",
        ),
    ),
    asset_setup_notes=(
        "In Microsoft Sentinel, create a Data Collection Endpoint (DCE) and a Data Collection Rule "
        "(DCR) with a custom table whose schema matches KronOS's own detection record shape "
        "(SentinelDetectionMapper). Create an Entra ID app registration and grant it the "
        "'Monitoring Metrics Publisher' role scoped to that DCR. No inbound connectivity or "
        "certificate is needed on your side -- KronOS authenticates outbound via this app "
        "registration's OAuth2 client-credentials grant."
    ),
)

_ALL_CONNECTORS: tuple[ConnectorDefinition, ...] = (
    *_PUSH_CONNECTORS,
    _DEFENDER,
    _SPLUNK_HEC,
    _CEF_SYSLOG,
    _SENTINEL,
)


class ConnectorCatalog:
    """Read-only lookup over the static connector definitions above."""

    def __init__(self, definitions: tuple[ConnectorDefinition, ...] = _ALL_CONNECTORS) -> None:
        self._by_source_type = {d.source_type: d for d in definitions}

    def all(self) -> tuple[ConnectorDefinition, ...]:
        return tuple(self._by_source_type.values())

    def get(self, source_type: str) -> ConnectorDefinition | None:
        return self._by_source_type.get(source_type)
