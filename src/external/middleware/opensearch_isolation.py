"""OpenSearch query builder: injects mandatory tenant isolation into every query."""

from __future__ import annotations

from typing import Any

from src.domain.user import TenantContext


class OpenSearchQueryBuilder:
    """Wraps OpenSearch DSL queries with a hard org_id isolation filter.

    Every query produced here includes ``{"term": {"kronos.org_id": org_id}}``,
    preventing cross-tenant document access even if an index spans multiple orgs.
    """

    def __init__(self, tenant: TenantContext) -> None:
        self._tenant = tenant

    @property
    def org_id_filter(self) -> dict[str, Any]:
        """Return the raw term filter for direct use in bool query clauses."""
        return {"term": {"kronos.org_id": str(self._tenant.org_id)}}

    def build(self, query: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of *query* wrapped with the tenant isolation filter.

        The original query is placed in a ``bool.must`` clause; the org_id
        filter is always added to ``bool.filter`` so it cannot be scored away.
        """
        existing = query.get("query")
        must_clause: list[dict[str, Any]] = [existing] if existing else [{"match_all": {}}]
        return {
            **{k: v for k, v in query.items() if k != "query"},
            "query": {
                "bool": {
                    "must": must_clause,
                    "filter": [self.org_id_filter],
                }
            },
        }
