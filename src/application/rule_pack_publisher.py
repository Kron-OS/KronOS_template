"""RulePackPublisher: pushes ACCEPTED rules to the real OpenSearch cluster
and wires them into a real, per-org custom-rule detector.

Roadmap M2/C3 (docs/NEXTGEN_SOC_ROADMAP.md). Deliberately separate from
``RulePackService`` (src/application/rule_pack_service.py): CRUD/versioning
is pure bookkeeping with no OpenSearch dependency, while this class is the
one place a rule pack's content actually reaches the shared, multi-tenant
cluster -- a natural seam matching the codebase's existing
sync-vs-bookkeeping split (``DetectionSyncService`` vs. the ``Detection``
domain model it populates).

Only ever publishes rules whose ``CostGateVerdict.accepted`` is True
(roadmap risk (a) -- a rejected rule can never reach OpenSearch through
this path) and only ever attaches them to a detector scoped to
``kronos-{tenant.org_alias}-*`` (roadmap risk (b) -- computed from the
caller's authenticated ``TenantContext``, never from pack/rule content).

Known, accepted limitation (not silently worked around): when
``update_custom_rule``/``delete_custom_rule`` supersede or remove a rule
from the latest version, that rule's PREVIOUS OpenSearch custom-rule
document and publication record are not deleted -- only excluded from the
next detector resync (which always reflects the CURRENT version's accepted
rules only, so the stale document has zero effect on what actually fires).
A periodic reconciliation sweep to delete truly-orphaned OpenSearch custom
rules would be the natural follow-up (mirrors the "not attempted as
unplanned scope creep" notes elsewhere in this roadmap, e.g. C2's kronos-dev
legacy-index gap) -- tracked here, not attempted in this pass.
"""

from __future__ import annotations

import logging

from src.adapter.opensearch.custom_rule_client import CustomRuleClient
from src.adapter.opensearch.custom_rule_detector_provisioner import CustomRuleDetectorBinder
from src.adapter.repository.rule_pack import RulePackRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.rule_pack import CustomRule
from src.domain.user import TenantContext

logger = logging.getLogger(__name__)


class RulePackPublisher:
    """Publishes a pack's accepted rules to OpenSearch and syncs its detector."""

    def __init__(
        self,
        repository: RulePackRepository,
        custom_rule_client: CustomRuleClient,
        detector_binder: CustomRuleDetectorBinder,
        audit_log: AuditLogService,
    ) -> None:
        self._repo = repository
        self._custom_rule_client = custom_rule_client
        self._detector_binder = detector_binder
        self._audit = audit_log

    async def publish_pack_version(
        self, tenant: TenantContext, pack_name: str, log_type: str
    ) -> int:
        """Push every ACCEPTED, not-yet-published rule of *log_type* in
        *pack_name*'s latest version to OpenSearch, then resync that org's
        custom-rule detector for *log_type* to reference exactly the current
        version's full accepted+published set.

        Returns the count of rules newly published this call (0 if none are
        pending -- safe to call repeatedly/idempotently after every CRUD
        mutation).
        """
        pack = await self._repo.get_or_create_pack(tenant.org_id, pack_name)
        version = await self._repo.get_latest_version(pack.pack_id, tenant.org_id)
        if version is None:
            return 0

        published = 0
        for rule in version.rules_for_log_type(log_type):
            if (
                await self._repo.get_published_opensearch_id(rule.rule_id, tenant.org_id)
                is not None
            ):
                continue
            if await self._publish_one(tenant, pack_name, rule, log_type):
                published += 1

        await self._resync_detector(tenant, log_type, version.rules)
        return published

    async def _publish_one(
        self, tenant: TenantContext, pack_name: str, rule: CustomRule, log_type: str
    ) -> bool:
        try:
            opensearch_id = await self._custom_rule_client.create_rule(rule.sigma_yaml, log_type)
        except Exception as exc:  # noqa: BLE001 -- publish must never crash the caller
            await self._audit.log(
                AuditEventType.RULE_PACK_RULE_PUBLISH_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"pack_name": pack_name, "rule_id": str(rule.rule_id), "error": str(exc)},
            )
            logger.warning(
                "rule_pack_publish_failed",
                extra={"pack_name": pack_name, "rule_id": str(rule.rule_id), "error": str(exc)},
            )
            return False

        await self._repo.record_publication(rule.rule_id, tenant.org_id, opensearch_id)
        await self._audit.log(
            AuditEventType.RULE_PACK_RULE_PUBLISHED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={
                "pack_name": pack_name,
                "rule_id": str(rule.rule_id),
                "title": rule.title,
                "opensearch_rule_id": opensearch_id,
            },
        )
        return True

    async def _resync_detector(
        self, tenant: TenantContext, log_type: str, rules: tuple[CustomRule, ...]
    ) -> None:
        opensearch_ids: list[str] = []
        for rule in rules:
            if rule.log_type != log_type or not rule.is_accepted:
                continue
            published_id = await self._repo.get_published_opensearch_id(rule.rule_id, tenant.org_id)
            if published_id is not None:
                opensearch_ids.append(published_id)
        await self._detector_binder.sync_custom_detector(
            tenant.org_alias, log_type, tuple(opensearch_ids)
        )
