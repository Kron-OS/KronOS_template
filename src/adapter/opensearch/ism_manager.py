"""ISM lifecycle management: tiered policies, self-healing attachment, legal hold.

Roadmap M1/B3 (docs/NEXTGEN_SOC_ROADMAP.md). Real, live-cluster investigation
(poc/ism_tiering_legal_hold/) found that ``ensure_ism_policy()``'s reliance on
the ``ism_template`` wildcard to auto-attach a policy at index-creation time
is not self-healing: every real, pre-existing KronOS evidence index on the
dev cluster was found with its managed-index job stuck at
``enabled: false, enabled_time: null`` -- meaning OpenSearch's own ISM
rollover/delete lifecycle had never actually been ticking for any of them,
despite ``ensure_ism_policy()`` reporting success and ``_plugins/_ism/explain``
showing a policy_id attached. Freshly-created indices (both an explicit
``PUT`` and a ``_bulk`` auto-create, tested directly against the live
cluster) attach correctly; the stuck ones are historical, most likely from a
container/process restart the coordinator's periodic sweep never revisits
once a (disabled) managed-index doc already exists for an index. There is no
automatic recovery for that stuck state -- only an explicit
``POST _plugins/_ism/add/{index}`` call resolves it, confirmed directly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx


class IsmLifecycleManager(ABC):
    """Explicit ISM policy attachment, self-healing, and legal-hold control."""

    @abstractmethod
    async def ensure_policy(self, policy_id: str, policy_body: dict) -> None:
        """Create or update a named ISM policy (idempotent)."""

    @abstractmethod
    async def ensure_managed(self, index_name: str, policy_id: str) -> None:
        """Explicitly (re-)attach management to a real index.

        Not a no-op convenience wrapper: this is the fix for the stuck
        ``enabled: false`` state documented in this module's docstring.
        Idempotent -- safe to call on an index that is already correctly
        managed under the same policy.
        """

    @abstractmethod
    async def place_legal_hold(self, index_name: str) -> None:
        """Detach ISM management from a real index, blocking its delete
        transition indefinitely. Mirrors ``Evidence.legal_hold`` at the
        OpenSearch layer -- MinIO's own Object Lock legal hold
        (``S3EvidenceStorage.set_legal_hold``) already blocks deletion of the
        raw evidence object; this blocks deletion of that evidence's parsed
        timeline index the same way.
        """

    @abstractmethod
    async def release_legal_hold(self, index_name: str, policy_id: str) -> None:
        """Re-attach management, resuming normal lifecycle transitions."""

    @abstractmethod
    async def resolve_indices(self, index_pattern: str) -> list[str]:
        """Real index names currently matching a wildcard pattern.

        ISM's add/remove APIs act on concrete index names (or a
        comma-list) -- a caller holding a case/org-scoped wildcard must
        resolve it to real names first, since the pattern itself may not
        exist as a queryable target (e.g. a case that has not yet produced
        an index for the current month).
        """

    @abstractmethod
    async def is_managed_and_enabled(self, index_name: str) -> bool:
        """True only if a real managed-index job exists AND is enabled.

        Distinct from "a policy_id is attached": the stuck-disabled state
        this module fixes still reports a policy_id via ``_ism/explain``
        while never actually running -- checking the real
        ``.opendistro-ism-config`` managed_index doc's ``enabled`` field
        (via ``_plugins/_ism/explain`` verbose output) is what actually
        answers "is this index's lifecycle really ticking".
        """


class OpenSearchIsmLifecycleManager(IsmLifecycleManager):
    """Real OpenSearch 2.11.1 implementation, verified against the live cluster."""

    def __init__(self, base_url: str, admin_username: str, admin_password: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = (admin_username, admin_password)

    async def ensure_policy(self, policy_id: str, policy_body: dict) -> None:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.put(
                f"{self._base_url}/_plugins/_ism/policies/{policy_id}",
                auth=self._auth,
                json=policy_body,
            )
            # A 409 means the policy already exists with different
            # seq_no/primary_term bookkeeping -- tolerated the same way
            # OpenSearchClient.ensure_ism_policy() already does; the policy
            # body itself is not expected to change shape across restarts.
            if resp.status_code not in (200, 201, 409):
                resp.raise_for_status()

    async def ensure_managed(self, index_name: str, policy_id: str) -> None:
        """Idempotent regardless of prior state -- including the real,
        silently-failing case this method exists to fix.

        A real run against the live cluster (poc/ism_tiering_legal_hold/)
        found ``POST _plugins/_ism/add/{index}`` returns HTTP 200 with
        ``{"failures": true, "failed_indices": [...]}`` in the BODY --
        never a non-2xx status -- when the index already has a recorded
        policy_id (even a disabled one). Checking only ``raise_for_status()``
        (as this method originally did) treats that as success: exactly the
        "confident-sounding, unverified code" failure mode CLAUDE.md §F
        exists to catch, and the same class of bug as the historical
        ``bulk_index`` silent-partial-failure fix (roadmap A4). ``remove``
        then ``add`` is the real, confirmed-working sequence regardless of
        whether a policy was already attached.
        """
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            await client.post(f"{self._base_url}/_plugins/_ism/remove/{index_name}", auth=self._auth)
            resp = await client.post(
                f"{self._base_url}/_plugins/_ism/add/{index_name}",
                auth=self._auth,
                json={"policy_id": policy_id},
            )
            resp.raise_for_status()
            self._raise_if_ism_body_reports_failure(resp, index_name)

    async def place_legal_hold(self, index_name: str) -> None:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(
                f"{self._base_url}/_plugins/_ism/remove/{index_name}",
                auth=self._auth,
            )
            resp.raise_for_status()
            self._raise_if_ism_body_reports_failure(resp, index_name)

    @staticmethod
    def _raise_if_ism_body_reports_failure(resp: httpx.Response, index_name: str) -> None:
        body = resp.json()
        if body.get("failures"):
            from src.exceptions import StorageError  # noqa: PLC0415

            raise StorageError(
                f"OpenSearch ISM API reported a real failure for {index_name} despite "
                f"an HTTP 2xx status: {body.get('failed_indices')}",
                context={"index_name": index_name, "response_body": body},
            )

    async def release_legal_hold(self, index_name: str, policy_id: str) -> None:
        await self.ensure_managed(index_name, policy_id)

    async def resolve_indices(self, index_pattern: str) -> list[str]:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.get(
                f"{self._base_url}/_resolve/index/{index_pattern}",
                auth=self._auth,
            )
            resp.raise_for_status()
            return [entry["name"] for entry in resp.json().get("indices", [])]

    async def is_managed_and_enabled(self, index_name: str) -> bool:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            resp = await client.post(
                f"{self._base_url}/.opendistro-ism-config/_search",
                auth=self._auth,
                json={"size": 1, "query": {"match": {"managed_index.name": index_name}}},
            )
            resp.raise_for_status()
            for hit in resp.json().get("hits", {}).get("hits", []):
                mi = hit["_source"].get("managed_index", {})
                if mi.get("name") == index_name:
                    return bool(mi.get("enabled", False))
            return False
