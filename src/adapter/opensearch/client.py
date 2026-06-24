"""OpenSearch index client: ABC, real implementation, and in-memory test double."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class AbstractTimelineIndex(ABC):
    """Port for OpenSearch bulk-indexing operations."""

    @abstractmethod
    async def bulk_index(self, documents: list[tuple[str, str, dict[str, Any]]]) -> int:
        """Index documents in bulk.

        Args:
            documents: List of (index_name, doc_id, body) triples.

        Returns:
            Number of documents successfully indexed.
        """

    @abstractmethod
    async def ensure_index_template(self) -> None:
        """Create or update the kronos-* index template."""

    @abstractmethod
    async def ensure_ism_policy(self) -> None:
        """Create or update the ISM rollover policy for kronos-* indices."""

    @abstractmethod
    async def ensure_tenant_role(self, org_id: str, org_alias: str) -> None:
        """Create or update the per-tenant DLS security role."""


class OpenSearchClient(AbstractTimelineIndex):
    """Async OpenSearch client backed by opensearch-py AsyncOpenSearch."""

    def __init__(
        self,
        hosts: list[dict[str, Any]],
        *,
        http_auth: tuple[str, str] | None = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
    ) -> None:
        from opensearchpy import AsyncOpenSearch  # noqa: PLC0415

        self._client = AsyncOpenSearch(
            hosts=hosts,
            http_auth=http_auth,
            use_ssl=use_ssl,
            verify_certs=verify_certs,
        )

    async def bulk_index(self, documents: list[tuple[str, str, dict[str, Any]]]) -> int:
        if not documents:
            return 0

        body: list[dict[str, Any]] = []
        for index, doc_id, doc_body in documents:
            body.append({"index": {"_index": index, "_id": doc_id}})
            body.append(doc_body)

        response = await self._client.bulk(body=body)
        errors = [item for item in response["items"] if "error" in item.get("index", {})]
        return len(documents) - len(errors)

    async def ensure_index_template(self) -> None:
        template_path = Path(__file__).parent / "index_template.json"
        with template_path.open() as fh:
            template = json.load(fh)
        await self._client.indices.put_index_template(
            name="kronos-template",
            body=template,
        )

    async def ensure_ism_policy(self) -> None:
        policy_path = Path(__file__).parent / "ism_policy.json"
        with policy_path.open() as fh:
            policy = json.load(fh)
        await self._client.transport.perform_request(
            "PUT",
            "/_plugins/_ism/policies/kronos-rollover",
            body=policy,
        )

    async def ensure_tenant_role(self, org_id: str, org_alias: str) -> None:
        role_name = f"kronos-tenant-{org_id}"
        role_body = {
            "cluster_permissions": [],
            "index_permissions": [
                {
                    "index_patterns": [f"kronos-{org_alias.lower()}-*"],
                    "dls": json.dumps({"term": {"kronos.org_id": org_id}}),
                    "allowed_actions": [
                        "read",
                        "indices:data/read/search",
                    ],
                }
            ],
            "tenant_permissions": [],
        }
        await self._client.transport.perform_request(
            "PUT",
            f"/_plugins/_security/api/roles/{role_name}",
            body=role_body,
        )


class InMemoryOpenSearchClient(AbstractTimelineIndex):
    """In-memory OpenSearch stand-in for unit and integration tests."""

    def __init__(self) -> None:
        self._indices: dict[str, dict[str, dict[str, Any]]] = {}
        self.bulk_calls: list[list[tuple[str, str, dict[str, Any]]]] = []
        self.roles_created: dict[str, dict[str, Any]] = {}
        self.template_set: bool = False
        self.ism_set: bool = False

    async def bulk_index(self, documents: list[tuple[str, str, dict[str, Any]]]) -> int:
        self.bulk_calls.append(list(documents))
        for index, doc_id, body in documents:
            self._indices.setdefault(index, {})[doc_id] = body
        return len(documents)

    async def ensure_index_template(self) -> None:
        self.template_set = True

    async def ensure_ism_policy(self) -> None:
        self.ism_set = True

    async def ensure_tenant_role(self, org_id: str, org_alias: str) -> None:
        self.roles_created[org_id] = {"org_alias": org_alias}

    # ------------------------------------------------------------------
    # Test-inspection helpers
    # ------------------------------------------------------------------

    def get_documents(self, index: str) -> dict[str, dict[str, Any]]:
        """Return all documents stored under *index*."""
        return dict(self._indices.get(index, {}))

    def all_indices(self) -> list[str]:
        """Return all index names that received at least one document."""
        return list(self._indices.keys())

    def total_documents(self) -> int:
        """Return total document count across all indices."""
        return sum(len(docs) for docs in self._indices.values())
