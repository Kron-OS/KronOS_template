"""OpenSearch index client: ABC, real implementation, and in-memory test double."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.exceptions import StorageError

# Verified in poc/keycloak_opensearch_dls/ (steps 3-4): ONE role, ONE static
# mapping to every KronOS realm role (hyphenated -- see
# src/external/middleware/keycloak_auth.py's _ROLE_MAP), created once, ever.
# DLS (${attr.jwt.org_id}) is what actually restricts each query to its own
# org, not this mapping, so mapping broadly here is correct, not an over-grant.
_GENERIC_TENANT_ROLE_NAME = "kronos-generic-tenant"
_GENERIC_TENANT_BACKEND_ROLES = ["org-admin", "case-lead", "analyst", "read-only"]


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
    async def ensure_generic_tenant_role(self) -> None:
        """Create the one generic, org-agnostic DLS security role + its static mapping.

        Called once ever, not per-org: DLS is templated from the caller's
        own JWT (``${attr.jwt.org_id}``) at query time, so a single role
        with a single static role-mapping (to every KronOS realm role)
        correctly isolates every org, including orgs and members created
        after this call — verified in
        ``poc/keycloak_opensearch_dls/`` (steps 3-4). This replaces the
        previous per-org ``ensure_tenant_role(org_id, org_alias)``, which
        created a new role per org but never mapped any user/backend_role
        to it (see ``poc/opensearch_jwt/README.md`` result #3).
        """

    @abstractmethod
    async def close(self) -> None:
        """Release any network resources (aiohttp session, etc.)."""

    @abstractmethod
    async def get_documents_by_id(
        self, index: str, doc_ids: list[str]
    ) -> dict[str, dict[str, Any]]:
        """Fetch specific already-indexed documents by id (roadmap M5/F4).

        Read counterpart to ``bulk_index`` -- added so a consumer (e.g.
        ``DetectionRiskScorer`` via ``DetectionSyncService``) can resolve a
        Detection's own ``matched_document_ids`` back to their real
        ``enrichment.ioc.*``/``enrichment.asset.*`` fields without a full
        search. Returns only the documents that were actually found, keyed
        by doc id -- a missing id is simply absent from the result (an
        honest partial result, never a fabricated placeholder), verified
        for real in ``poc/detection_risk_scoring/`` against the real
        OpenSearch 2.11.1 ``_mget`` response shape (``docs[].found``).
        """


class OpenSearchClient(AbstractTimelineIndex):
    """Async OpenSearch client backed by opensearch-py AsyncOpenSearch."""

    def __init__(
        self,
        hosts: list[dict[str, Any]],
        *,
        http_auth: tuple[str, str] | None = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
        timeout: int = 60,
    ) -> None:
        from opensearchpy import AsyncOpenSearch  # noqa: PLC0415

        self._client = AsyncOpenSearch(
            hosts=hosts,
            http_auth=http_auth,
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            # opensearch-py's own default is a 10s connection/read timeout
            # with retry_on_timeout=False — too tight for a _bulk request
            # under concurrent load (several Celery workers indexing at
            # once) against a resource-constrained node: observed a real
            # request finish at 9.1-9.3s and the very next one killed
            # client-side at 10.35s, which then cascaded into a Celery
            # retry landing on an already-ERROR evidence row
            # (EvidenceStateConflictError). A slow-but-alive cluster isn't
            # the same failure as an unreachable one; give bulk requests
            # real headroom and let the client retry a timeout once before
            # surfacing it as a StorageError.
            timeout=timeout,
            max_retries=2,
            retry_on_timeout=True,
        )

    async def bulk_index(self, documents: list[tuple[str, str, dict[str, Any]]]) -> int:
        if not documents:
            return 0

        body: list[dict[str, Any]] = []
        for index, doc_id, doc_body in documents:
            body.append({"index": {"_index": index, "_id": doc_id}})
            body.append(doc_body)

        response = await self._client.bulk(body=body)

        # Extract per-document errors from the _bulk response.
        # Each item in response["items"] is a dict like:
        #   {"index": {"_index": "...", "_id": "...", "status": 200, ...}}
        # or on error:
        #   {"index": {"_index": "...", "_id": "...", "status": 400,
        #              "error": {"type": "mapper_parsing_exception", "reason": "..."}}}
        errors = []
        for item in response["items"]:
            index_op = item.get("index", {})
            if "error" in index_op:
                errors.append(
                    {
                        "doc_id": index_op.get("_id"),
                        "index_name": index_op.get("_index"),
                        "status": index_op.get("status"),
                        "error": index_op.get("error"),
                    }
                )

        # Fail loudly (CLAUDE.md §1.8): any partial failure is an error, not silent data loss.
        if errors:
            raise StorageError(
                f"OpenSearch bulk indexing had {len(errors)} document(s) fail out of "
                f"{len(documents)} total. Successfully indexed: {len(documents) - len(errors)}. "
                f"This is not a silent failure; the documents that failed are listed in "
                f"context['failed_documents'].",
                context={
                    "total_documents": len(documents),
                    "failed_count": len(errors),
                    "succeeded_count": len(documents) - len(errors),
                    "failed_documents": errors,
                },
            )

        return len(documents)

    async def ensure_index_template(self) -> None:
        """Create/update the ``kronos-template`` composable index template,
        then push its ``dynamic``/``dynamic_templates`` settings onto every
        already-existing ``kronos-*`` index too.

        Gap Audit Milestone UUUU: an index template only ever applies to
        indices created *after* the template changes -- a real, previously
        acknowledged gap (``poc/ecs_schema_hardening/README.md``'s own
        "Existing indices... no reindex was performed... out of scope").
        Since this platform's own index names are keyed to each record's
        *event* timestamp, not wall-clock time
        (``timeline_normalization.build_index_name``), a case's index for a
        given month is typically created exactly once and never rotates
        again — a template-only fix would silently never reach almost all
        real (historical, forensic) data. The live ``_mapping`` PUT below is
        a real, verified-live (``poc/opensearch_auto_index_fields/``) fix:
        changing an index's ``dynamic``/``dynamic_templates`` settings (not
        an existing field's type) is a supported, non-reindexing mapping
        update, so this runs automatically on every ingest — no manual
        admin step, no reindex, and it only affects *future* writes into
        that index. Documents already indexed under the old, stricter
        mapping keep whatever was dropped from the index at write time
        (still present in ``_source``, per the deliberate `dynamic: false`→
        `true` design) until something re-processes them — a real, targeted
        ``_update_by_query`` against the affected index(es) is the
        verified-live way to do that retroactively (same PoC, step 4);
        not run automatically here since it is a real, potentially
        large/slow operation against already-live data, not appropriate to
        fire unattended on every ingest task.

        Tolerates a cluster with zero ``kronos-*`` indices yet (a fresh
        stack): OpenSearch 404s a wildcard ``_mapping`` PUT that matches
        nothing (confirmed live), which is a real no-op here, not a
        failure — new indices get the fixed mapping from the template at
        creation time regardless.
        """
        from opensearchpy.exceptions import NotFoundError  # noqa: PLC0415

        template_path = Path(__file__).parent / "index_template.json"
        with template_path.open() as fh:
            template = json.load(fh)
        await self._client.indices.put_index_template(
            name="kronos-template",
            body=template,
        )

        mappings = template["template"]["mappings"]
        try:
            await self._client.indices.put_mapping(
                index="kronos-*",
                body={
                    "dynamic": mappings["dynamic"],
                    "dynamic_templates": mappings["dynamic_templates"],
                },
            )
        except NotFoundError:
            pass

    async def ensure_ism_policy(self) -> None:
        """Create the ISM rollover policy, tolerating "already exists".

        TimelineIngestionService builds a fresh instance (and so calls this)
        on every single Celery ingest task — see celery_runtime.py's
        per-task-loop-scoped resources. PUT on an *existing* ISM policy
        without ``if_seq_no``/``if_primary_term`` always 409s in OpenSearch,
        so without this the very first ingest after the policy exists (i.e.
        every ingest after the first one ever) raised ConflictError and
        failed the whole parse.
        """
        from opensearchpy.exceptions import ConflictError  # noqa: PLC0415

        policy_path = Path(__file__).parent / "ism_policy.json"
        with policy_path.open() as fh:
            policy = json.load(fh)
        try:
            await self._client.transport.perform_request(
                "PUT",
                "/_plugins/_ism/policies/kronos-rollover",
                body=policy,
            )
        except ConflictError:
            pass

    async def ensure_generic_tenant_role(self) -> None:
        role_body = {
            "cluster_permissions": [],
            "index_permissions": [
                {
                    "index_patterns": ["kronos-*"],
                    "dls": json.dumps({"term": {"kronos.org_id": "${attr.jwt.org_id}"}}),
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
            f"/_plugins/_security/api/roles/{_GENERIC_TENANT_ROLE_NAME}",
            body=role_body,
        )
        await self._client.transport.perform_request(
            "PUT",
            f"/_plugins/_security/api/rolesmapping/{_GENERIC_TENANT_ROLE_NAME}",
            body={"backend_roles": _GENERIC_TENANT_BACKEND_ROLES},
        )

    async def close(self) -> None:
        await self._client.close()

    async def get_documents_by_id(
        self, index: str, doc_ids: list[str]
    ) -> dict[str, dict[str, Any]]:
        if not doc_ids:
            return {}

        # Real opensearch-py 3.2 AsyncOpenSearch.mget signature (verified
        # via inspect.signature against the pinned version --
        # poc/detection_risk_scoring/): body={"docs": [{"_id": ...}, ...]},
        # index=<default index for entries with no _index override>.
        response = await self._client.mget(
            index=index,
            body={"docs": [{"_id": doc_id} for doc_id in doc_ids]},
        )

        # Real response shape confirmed against the live 2.11.1 cluster: a
        # top-level "docs" array, one entry per requested id, in the SAME
        # order requested, each carrying its own "found" bool -- a missing
        # id comes back {"found": false, ...} rather than being omitted
        # from the array entirely, so "found" must be checked explicitly
        # rather than assuming every returned entry has a "_source".
        found: dict[str, dict[str, Any]] = {}
        for doc in response.get("docs", []):
            if doc.get("found"):
                found[doc["_id"]] = doc["_source"]
        return found


class InMemoryOpenSearchClient(AbstractTimelineIndex):
    """In-memory OpenSearch stand-in for unit and integration tests."""

    def __init__(self) -> None:
        self._indices: dict[str, dict[str, dict[str, Any]]] = {}
        self.bulk_calls: list[list[tuple[str, str, dict[str, Any]]]] = []
        self.generic_tenant_role_created: bool = False
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

    async def ensure_generic_tenant_role(self) -> None:
        self.generic_tenant_role_created = True

    async def close(self) -> None:
        pass

    async def get_documents_by_id(
        self, index: str, doc_ids: list[str]
    ) -> dict[str, dict[str, Any]]:
        docs = self._indices.get(index, {})
        return {doc_id: docs[doc_id] for doc_id in doc_ids if doc_id in docs}

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
