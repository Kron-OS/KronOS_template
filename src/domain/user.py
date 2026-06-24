"""User, Role, and TenantContext domain models."""

from __future__ import annotations

import uuid
from enum import StrEnum

from pydantic import BaseModel, Field


class Role(StrEnum):
    """Roles scoped per-organization, aligned with the permission matrix."""

    ORG_ADMIN = "org_admin"
    CASE_LEAD = "case_lead"
    ANALYST = "analyst"
    READ_ONLY = "read_only"


class User(BaseModel):
    """Authenticated platform user, sourced from a validated Keycloak JWT."""

    model_config = {"frozen": True}

    user_id: uuid.UUID = Field(description="Keycloak subject claim (sub)")
    username: str = Field(description="Keycloak preferred_username")
    email: str
    org_id: uuid.UUID = Field(description="Organization UUID extracted from the organization claim")
    org_alias: str = Field(description="Organization alias used in index naming")
    roles: frozenset[Role] = Field(default_factory=frozenset)

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    def has_any_role(self, *roles: Role) -> bool:
        return bool(self.roles & set(roles))


class TenantContext(BaseModel):
    """Per-request context derived from the authenticated JWT.

    Injected via FastAPI dependency; never constructed from untrusted input.
    """

    model_config = {"frozen": True}

    org_id: uuid.UUID
    org_alias: str
    user_id: uuid.UUID
    username: str
    roles: frozenset[Role]
    correlation_id: str = Field(description="JWT jti claim for cross-hop tracing")
