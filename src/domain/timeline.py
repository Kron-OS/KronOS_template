"""TimelineRecord domain model: ECS schema + kronos.* provenance block."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class KronosProvenance(BaseModel):
    """Provenance block attached to every ingested timeline record."""

    model_config = {"frozen": True}

    evidence_id: uuid.UUID
    case_id: uuid.UUID
    org_id: uuid.UUID
    org_alias: str = Field(default="", description="Human-readable org alias for querying")
    sha256: str = Field(description="SHA-256 of the source evidence file")
    parser: str = Field(description="Parser name that produced this record (e.g. evtx-rs)")
    parser_version: str
    record_index: int = Field(ge=0, description="Zero-based index within the parsed evidence file")
    ingest_timestamp: datetime = Field(description="UTC time the record was written to OpenSearch")


class ECSBase(BaseModel):
    """Minimal ECS base fields required for all timeline records."""

    model_config = {"frozen": True}

    # @timestamp is the canonical event time in ECS.
    timestamp: datetime = Field(alias="@timestamp")
    message: str | None = None

    # ECS event fields
    event_kind: str | None = Field(None, alias="event.kind")
    event_category: list[str] = Field(default_factory=list, alias="event.category")
    event_type: list[str] = Field(default_factory=list, alias="event.type")
    event_outcome: str | None = Field(None, alias="event.outcome")
    event_original: str | None = Field(None, alias="event.original")

    # ECS host fields
    host_name: str | None = Field(None, alias="host.name")
    host_os_name: str | None = Field(None, alias="host.os.name")

    # ECS user fields
    user_name: str | None = Field(None, alias="user.name")
    user_id: str | None = Field(None, alias="user.id")

    # ECS process fields
    process_pid: int | None = Field(None, alias="process.pid")
    process_name: str | None = Field(None, alias="process.name")

    model_config = {"frozen": True, "populate_by_name": True}


class TimelineRecord(BaseModel):
    """A single parsed forensic event, normalized to ECS + kronos.* provenance."""

    model_config = {"frozen": True, "populate_by_name": True}

    # Deterministic _id for idempotent OpenSearch ingestion.
    # SHA1(evidence_id:parser:record_index) — computed by TimelineIngestionService.
    document_id: str | None = None

    # ECS core fields (flattened for direct OpenSearch mapping)
    timestamp: datetime = Field(alias="@timestamp")
    message: str | None = None
    event_kind: str | None = Field(None, alias="event.kind")
    event_category: list[str] = Field(default_factory=list, alias="event.category")
    event_type: list[str] = Field(default_factory=list, alias="event.type")
    event_outcome: str | None = Field(None, alias="event.outcome")
    event_original: str | None = Field(None, alias="event.original")
    host_name: str | None = Field(None, alias="host.name")
    host_os_name: str | None = Field(None, alias="host.os.name")
    user_name: str | None = Field(None, alias="user.name")
    user_id: str | None = Field(None, alias="user.id")
    process_pid: int | None = Field(None, alias="process.pid")
    process_name: str | None = Field(None, alias="process.name")

    # Format-specific extra fields preserved as-is.
    extra: dict[str, Any] = Field(default_factory=dict)

    # kronos.* provenance block — mandatory for every record.
    kronos: KronosProvenance
