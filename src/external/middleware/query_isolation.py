"""Query isolation guard: ensures all data access is scoped to the tenant's org."""

from __future__ import annotations

import logging
import uuid

from src.domain.user import TenantContext
from src.exceptions import AuthorizationError

logger = logging.getLogger(__name__)


class QueryIsolationGuard:
    """Validates that a resource's org matches the authenticated tenant.

    Raise AuthorizationError (→ HTTP 403) on any org_id mismatch to prevent
    cross-tenant data access regardless of how the query was constructed.
    """

    @staticmethod
    def assert_org_scope(tenant: TenantContext, resource_org_id: uuid.UUID) -> None:
        """Raise AuthorizationError if *resource_org_id* differs from tenant.org_id."""
        if tenant.org_id != resource_org_id:
            logger.warning(
                "query_isolation_violation",
                extra={
                    "tenant_org_id": str(tenant.org_id),
                    "resource_org_id": str(resource_org_id),
                },
            )
            raise AuthorizationError(
                "Access denied: resource belongs to a different organization",
                context={
                    "tenant_org_id": str(tenant.org_id),
                    "resource_org_id": str(resource_org_id),
                },
            )
