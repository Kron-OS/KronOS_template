"""RBAC enforcement: requires_role dependency factory."""

# NOTE: No 'from __future__ import annotations' here — FastAPI resolves
# dependency annotations eagerly; string annotations break class-based deps.

from fastapi import Depends, HTTPException, status

from src.domain.user import Role, TenantContext
from src.external.middleware.tenant_context import get_tenant_context


class _RoleChecker:
    """Callable dependency that enforces one of the required roles."""

    def __init__(self, *required_roles: Role) -> None:
        self._required_roles = frozenset(required_roles)

    async def __call__(self, tenant: TenantContext = Depends(get_tenant_context)) -> TenantContext:  # noqa: B008
        if not tenant.roles.intersection(self._required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient privileges: one of "
                    f"{[r.value for r in self._required_roles]} is required"
                ),
            )
        return tenant


def requires_role(*required_roles: Role) -> _RoleChecker:
    """Return a FastAPI dependency that enforces at least one of *required_roles*.

    Usage::

        @router.delete("/{evidence_id}")
        async def delete(tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN))]):
            ...
    """
    return _RoleChecker(*required_roles)
