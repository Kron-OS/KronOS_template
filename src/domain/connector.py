"""Domain value objects for the connector marketplace (`/admin/connectors`).

Pure, framework-free catalog metadata describing *what a connector needs*,
not how it's stored or authenticated -- that lives in
``src/application/connector_catalog.py`` (the static catalog),
``src/application/connector_config.py`` (``ConnectorConfigService``), and
``src/adapter/`` (Postgres + Vault). Deliberately separate from
``src/domain/integration_source.py`` (``IntegrationSourceIdentity``,
``StaticApiKeyProvisioning``) -- that module describes an *authenticated
runtime identity*; this one describes a *catalog entry an admin browses
before anything is configured*. Also deliberately separate from
``ForensicParser``/evidence-upload concerns (``src/domain/evidence.py``) --
a connector here is always a streaming (push/poll) or egress (sink) source,
never a file-upload-triggered parser; see
``reviews/Data_Source_Module_System.md`` for why those two hierarchies are
not unified.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class ConnectorMode(StrEnum):
    """How this connector moves data relative to KronOS.

    PUSH: the external tool calls KronOS (Wazuh/Suricata/Zeek today) --
    self-service via a KronOS-issued API key, no other parameters needed.
    POLL: KronOS calls out on a schedule (Microsoft Defender) -- needs real
    outbound credentials. SINK: KronOS pushes KronOS-originated Detections
    out to an external system (Splunk HEC/CEF syslog/Sentinel) -- also
    needs real outbound credentials, but is egress, not ingestion.
    """

    PUSH = "push"
    POLL = "poll"
    SINK = "sink"


class ConnectorParameterSpec(BaseModel):
    """One configuration field a connector needs from an org admin.

    ``secret`` is the load-bearing field: it decides which store persists
    this value (``ConnectorConfigRepository`` for non-secret,
    ``SecretStore``/Vault for secret) -- see ``ConnectorConfigService.set_config``.
    """

    model_config = {"frozen": True}

    name: str = Field(min_length=1, description="Machine key, e.g. 'client_secret'.")
    label: str = Field(min_length=1, description="Human-readable form label.")
    secret: bool = Field(description="True -> stored via SecretStore, never in Postgres.")
    required: bool = Field(description="True -> ConnectorConfigService.set_config rejects a missing value.")
    default: str | None = Field(default=None, description="Pre-filled suggestion, never a fallback secret.")


class ConnectorDefinition(BaseModel):
    """One catalog entry: a connector type an admin can browse and configure.

    ``source_type`` is the stable identifier used everywhere downstream
    (``connector_configs.source_type``, Vault path segment, route path
    param) -- never renamed once shipped, since it's a durable foreign key
    into persisted per-org config.
    """

    model_config = {"frozen": True}

    source_type: str = Field(min_length=1, description="Stable id, e.g. 'ms-defender-alerts'.")
    display_name: str = Field(min_length=1)
    mode: ConnectorMode
    description: str = Field(default="")
    parameters: tuple[ConnectorParameterSpec, ...] = Field(default_factory=tuple)
    # What has to be configured on the OTHER side of this connection --
    # the org's own Wazuh manager/Suricata host/syslog receiver/Entra ID
    # tenant/Sentinel workspace -- not on KronOS. Deliberately plain text
    # (not further structured): the real setup steps differ enough in
    # *kind* per connector (an HTTP endpoint + header for a PUSH source vs.
    # an Entra ID app registration + Graph permission for Defender vs. a
    # listening port/protocol for a syslog sink) that a common schema would
    # either be too generic to be useful or overfit to one connector family.
    asset_setup_notes: str = Field(default="")

    @property
    def secret_parameter_names(self) -> frozenset[str]:
        return frozenset(p.name for p in self.parameters if p.secret)

    @property
    def required_parameter_names(self) -> frozenset[str]:
        return frozenset(p.name for p in self.parameters if p.required)


class ConnectorConfigSummary(BaseModel):
    """Admin-read-safe view of one org's configured connector: everything
    EXCEPT secret values.

    Structurally cannot leak a secret value -- mirrors
    ``ProvisionedApiKeySummary``'s own "no field to put it in" discipline
    exactly (``src/domain/integration_source.py``): ``non_secret_fields``
    only ever holds parameters whose ``ConnectorParameterSpec.secret`` is
    False, and ``secret_field_names`` names which fields exist without
    exposing their values. ``ConnectorConfigService.resolve_runtime_config``
    is the one and only place plaintext secrets are ever reassembled, and
    it is never exposed via HTTP.
    """

    model_config = {"frozen": True}

    org_id: uuid.UUID
    source_type: str
    enabled: bool
    non_secret_fields: dict[str, str]
    secret_field_names: tuple[str, ...]
    consecutive_failure_count: int = 0
    auto_disabled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @property
    def secrets_set(self) -> bool:
        return len(self.secret_field_names) > 0
