"""RBAC enforcement: requires_role dependency factory."""

# NOTE: No 'from __future__ import annotations' here — FastAPI resolves
# dependency annotations eagerly; string annotations break class-based deps.

from fastapi import Depends, HTTPException, status

from src.domain.case import Case
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


def assert_case_access(tenant: TenantContext, case: Case) -> None:
    """Enforce the §1 matrix's case-scoping qualifier (AUTH-007).

    org-admin has org-wide access. Everyone else (case-lead, analyst,
    read-only) must either own/lead the case or be listed in
    ``member_user_ids`` — `org_id` equality alone is not sufficient, that
    just proves the case belongs to the caller's tenant, not that the caller
    is entitled to see it.

    Shared by ``cases.py`` and ``evidence.py`` so both routers apply the same
    ownership rule rather than maintaining parallel copies.
    """
    if Role.ORG_ADMIN in tenant.roles:
        return
    if tenant.user_id == case.owner_user_id or tenant.user_id in case.member_user_ids:
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this case")


def assert_case_lead_or_admin(tenant: TenantContext, case: Case) -> None:
    """Enforce the matrix's "(of case)"/"(own)" qualifier for case-lead-gated actions.

    Stricter than :func:`assert_case_access`: a case-lead must own/lead this
    specific case, not merely be a member of it (used for delete, assigning
    members, legal hold, and reading the audit log — all case-lead
    "of case"/"own" rows).
    """
    if Role.ORG_ADMIN in tenant.roles:
        return
    if tenant.user_id == case.owner_user_id:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Only this case's lead or an org-admin may perform this action",
    )
