"""Case domain model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class CaseStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    ARCHIVED = "archived"


class CaseMetadata(BaseModel):
    """Descriptive metadata supplied at case-creation time."""

    model_config = {"frozen": True}

    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    reference_number: str | None = None
    classification: str = Field(default="UNCLASSIFIED")


class Case(BaseModel):
    """A forensic investigation case owned by an organization."""

    model_config = {"frozen": True}

    case_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    org_id: uuid.UUID
    org_alias: str
    owner_user_id: uuid.UUID
    metadata: CaseMetadata
    status: CaseStatus = CaseStatus.OPEN
    member_user_ids: frozenset[uuid.UUID] = Field(default_factory=frozenset)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def with_status(self, status: CaseStatus) -> Case:
        return self.model_copy(update={"status": status, "updated_at": datetime.now(UTC)})

    def with_member(self, user_id: uuid.UUID) -> Case:
        return self.model_copy(
            update={
                "member_user_ids": self.member_user_ids | {user_id},
                "updated_at": datetime.now(UTC),
            }
        )
