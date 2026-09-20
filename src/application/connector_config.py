"""ConnectorConfigService: orchestrates per-org connector configuration.

The one place that (a) validates submitted values against a
``ConnectorDefinition``'s parameter specs, (b) splits them into the
non-secret (Postgres) and secret (Vault-backed ``SecretStore``) halves,
(c) audits every mutation, and (d) reassembles plaintext for internal
runtime consumers only (``resolve_runtime_config`` -- never exposed via
HTTP; ``get_config`` is the HTTP-safe, redacted counterpart).

No silent global-``Settings`` fallback (a real, recorded decision, not an
oversight): an org with no row here is simply not polled/pushed to --
``resolve_runtime_config`` returns ``None`` and callers (the Defender poll
loop, ``SyncDetectionToSiemAction``) must surface that loudly. Multi-tenant
correctness ("no collision, independent per client") was an explicit
requirement; a fallback to a shared global credential is exactly the
collision vector that requirement rules out.
"""

from __future__ import annotations

import uuid

from src.adapter.repository.connector_config import ConnectorConfigRepository
from src.application.audit_log import AuditLogService
from src.application.connector_catalog import ConnectorCatalog
from src.application.secret_store import SecretStore
from src.domain.audit import AuditEventType
from src.domain.connector import ConnectorConfigSummary
from src.exceptions import ValidationError

_DEFAULT_AUTO_DISABLE_THRESHOLD = 5


class ConnectorConfigService:
    """Per-org connector configuration: validate, persist, audit, resolve."""

    def __init__(
        self,
        catalog: ConnectorCatalog,
        repository: ConnectorConfigRepository,
        secret_store: SecretStore,
        audit_log: AuditLogService,
        *,
        auto_disable_threshold: int = _DEFAULT_AUTO_DISABLE_THRESHOLD,
    ) -> None:
        self._catalog = catalog
        self._repository = repository
        self._secret_store = secret_store
        self._audit = audit_log
        self._auto_disable_threshold = auto_disable_threshold

    async def set_config(
        self,
        org_id: uuid.UUID,
        source_type: str,
        values: dict[str, str],
        *,
        actor_user_id: uuid.UUID,
        actor_username: str | None = None,
    ) -> ConnectorConfigSummary:
        definition = self._catalog.get(source_type)
        if definition is None:
            raise ValidationError(f"Unknown connector source_type: {source_type!r}")

        missing = definition.required_parameter_names - values.keys()
        if missing:
            raise ValidationError(
                f"{source_type}: missing required parameter(s): {sorted(missing)}",
                context={"source_type": source_type, "missing": sorted(missing)},
            )
        known_names = {p.name for p in definition.parameters}
        unknown = values.keys() - known_names
        if unknown:
            raise ValidationError(
                f"{source_type}: unknown parameter(s): {sorted(unknown)}",
                context={"source_type": source_type, "unknown": sorted(unknown)},
            )

        secret_names = definition.secret_parameter_names
        non_secret_fields = {k: v for k, v in values.items() if k not in secret_names}
        secret_fields = {k: v for k, v in values.items() if k in secret_names}

        details = {"source_type": source_type}
        await self._audit.log(
            AuditEventType.CONNECTOR_CONFIG_SET_ATTEMPTED,
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            details=details,
        )
        try:
            if secret_fields:
                await self._secret_store.put(org_id, source_type, secret_fields)
            summary = await self._repository.upsert(
                org_id, source_type, non_secret_fields, tuple(secret_fields.keys())
            )
        except Exception as exc:
            await self._audit.log(
                AuditEventType.CONNECTOR_CONFIG_SET_FAILED,
                org_id=org_id,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                details={**details, "error": str(exc), "error_type": type(exc).__name__},
            )
            raise
        await self._audit.log(
            AuditEventType.CONNECTOR_CONFIG_SET_EXECUTED,
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            details=details,
        )
        return summary

    async def get_config(self, org_id: uuid.UUID, source_type: str) -> ConnectorConfigSummary | None:
        """Redacted read -- never returns secret values (the return type has
        no field to carry them in; see ``ConnectorConfigSummary``'s own docstring)."""
        return await self._repository.get(org_id, source_type)

    async def list_configs(self, org_id: uuid.UUID) -> list[ConnectorConfigSummary]:
        return await self._repository.list_by_org(org_id)

    async def delete_config(
        self,
        org_id: uuid.UUID,
        source_type: str,
        *,
        actor_user_id: uuid.UUID,
        actor_username: str | None = None,
    ) -> None:
        await self._secret_store.delete(org_id, source_type)
        await self._repository.delete(org_id, source_type)
        await self._audit.log(
            AuditEventType.CONNECTOR_CONFIG_REVOKED,
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            details={"source_type": source_type},
        )

    async def set_enabled(
        self,
        org_id: uuid.UUID,
        source_type: str,
        enabled: bool,
        *,
        actor_user_id: uuid.UUID,
        actor_username: str | None = None,
    ) -> ConnectorConfigSummary | None:
        """Reversible kill switch -- distinct from ``delete_config``'s permanent
        removal. Clears any system-set ``auto_disabled_at`` when re-enabling."""
        summary = await self._repository.set_enabled(org_id, source_type, enabled)
        await self._audit.log(
            AuditEventType.CONNECTOR_CONFIG_ENABLED if enabled else AuditEventType.CONNECTOR_CONFIG_DISABLED,
            org_id=org_id,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            details={"source_type": source_type},
        )
        return summary

    async def resolve_runtime_config(self, org_id: uuid.UUID, source_type: str) -> dict[str, str] | None:
        """The only method that ever reassembles plaintext -- for internal
        runtime consumers only (Defender poll loop, sink push path), never
        exposed via HTTP. Returns None if not configured OR disabled
        (both mean "do not act for this org")."""
        row = await self._repository.get(org_id, source_type)
        if row is None or not row.enabled:
            return None
        secrets = await self._secret_store.get(org_id, source_type) if row.secret_field_names else {}
        merged = dict(row.non_secret_fields)
        merged.update(secrets or {})
        definition = self._catalog.get(source_type)
        if definition is not None:
            for spec in definition.parameters:
                if spec.default is not None and spec.name not in merged:
                    merged[spec.name] = spec.default
        return merged

    async def record_success(self, org_id: uuid.UUID, source_type: str) -> None:
        await self._repository.record_success(org_id, source_type)

    async def record_failure(self, org_id: uuid.UUID, source_type: str) -> None:
        updated = await self._repository.record_failure(
            org_id, source_type, auto_disable_threshold=self._auto_disable_threshold
        )
        if updated is not None and updated.auto_disabled_at is not None:
            await self._audit.log(
                AuditEventType.CONNECTOR_CONFIG_AUTO_DISABLED,
                org_id=org_id,
                details={
                    "source_type": source_type,
                    "consecutive_failure_count": updated.consecutive_failure_count,
                },
            )
