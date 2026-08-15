"""RulePackService: versioned, cost-gated, tenant-scoped custom-rule CRUD.

Roadmap M2/C3 (docs/NEXTGEN_SOC_ROADMAP.md). Deliberately has ZERO
knowledge of OpenSearch -- publishing an accepted rule to the real cluster
and wiring it into a detector is ``RulePackPublisher``'s separate
responsibility (src/application/rule_pack_publisher.py). This service only
ever does bookkeeping: append-only versioning + the pre-execution cost gate
(roadmap risk (a)) + Cosign signature verification for third-party imports.

``org_id``/``org_alias`` are ALWAYS taken from the caller's authenticated
``TenantContext`` -- never from pack or rule content, mirroring
``StructuredArtifact.org_id``/``Detection.org_id`` (CLAUDE.md SS G.3).
"""

from __future__ import annotations

import hashlib
import logging
import uuid

from src.adapter.repository.rule_pack import RulePackRepository
from src.application.audit_log import AuditLogService
from src.application.cost_gate import RuleCostGate
from src.application.pack_signing import PackSignatureVerifier
from src.domain.audit import AuditEventType
from src.domain.rule_pack import CustomRule, RulePack, RulePackSourceTier, RulePackVersion
from src.domain.user import TenantContext
from src.exceptions import RulePackError, ValidationError

logger = logging.getLogger(__name__)


class RulePackService:
    """Versioned CRUD for tenant-authored/signed custom rule packs."""

    def __init__(
        self,
        repository: RulePackRepository,
        cost_gate: RuleCostGate,
        signature_verifier: PackSignatureVerifier,
        audit_log: AuditLogService,
    ) -> None:
        self._repo = repository
        self._cost_gate = cost_gate
        self._signature_verifier = signature_verifier
        self._audit = audit_log

    async def get_or_create_pack(self, tenant: TenantContext, pack_name: str) -> RulePack:
        return await self._repo.get_or_create_pack(tenant.org_id, pack_name)

    async def add_custom_rule(
        self, tenant: TenantContext, pack_name: str, title: str, sigma_yaml: str, log_type: str
    ) -> CustomRule:
        """Cost-gate *sigma_yaml*, then append it as a NEW version of *pack_name*.

        The rule is stored (and its verdict recorded) whether accepted or
        rejected -- a rejected rule is a fact worth an audited, inspectable
        record, never silently dropped (CLAUDE.md SS B.2/SS A.6).
        """
        pack = await self.get_or_create_pack(tenant, pack_name)
        verdict = self._cost_gate.evaluate(sigma_yaml)
        rule = CustomRule(
            title=title, log_type=log_type, sigma_yaml=sigma_yaml, cost_gate_verdict=verdict
        )
        prev = await self._repo.get_latest_version(pack.pack_id, tenant.org_id)
        new_rules = (prev.rules if prev else ()) + (rule,)
        await self._append_version(
            tenant, pack, new_rules, RulePackSourceTier.TENANT_CUSTOM, signature_verified=False
        )
        return rule

    async def update_custom_rule(
        self, tenant: TenantContext, pack_name: str, title: str, sigma_yaml: str, log_type: str
    ) -> CustomRule:
        """Replace the rule named *title* in *pack_name* with new content, as a
        new version. Raises ValidationError if no rule with that title exists
        in the pack's latest version (use add_custom_rule for a new rule).

        A content change always mints a NEW ``rule_id`` (CustomRule is
        immutable) -- the previous rule_id's OpenSearch publication record,
        if any, is simply superseded (no longer referenced by any future
        detector resync); see RulePackPublisher's module docstring for the
        accepted tradeoff this implies.
        """
        pack = await self.get_or_create_pack(tenant, pack_name)
        prev = await self._repo.get_latest_version(pack.pack_id, tenant.org_id)
        if prev is None or not any(r.title == title for r in prev.rules):
            raise ValidationError(
                "No existing rule with this title to update",
                context={"pack_name": pack_name, "title": title},
            )
        verdict = self._cost_gate.evaluate(sigma_yaml)
        new_rule = CustomRule(
            title=title, log_type=log_type, sigma_yaml=sigma_yaml, cost_gate_verdict=verdict
        )
        new_rules = tuple(r for r in prev.rules if r.title != title) + (new_rule,)
        await self._append_version(
            tenant, pack, new_rules, RulePackSourceTier.TENANT_CUSTOM, signature_verified=False
        )
        return new_rule

    async def delete_custom_rule(self, tenant: TenantContext, pack_name: str, title: str) -> None:
        """Remove the rule named *title* from *pack_name*, as a new version.

        Bookkeeping only -- does not itself touch OpenSearch. Call
        ``RulePackPublisher.publish_pack_version`` afterward to resync the
        org's real detector so it stops referencing the removed rule.
        """
        pack = await self.get_or_create_pack(tenant, pack_name)
        prev = await self._repo.get_latest_version(pack.pack_id, tenant.org_id)
        if prev is None:
            return
        remaining = tuple(r for r in prev.rules if r.title != title)
        if len(remaining) == len(prev.rules):
            return  # nothing to delete
        await self._append_version(
            tenant, pack, remaining, prev.source_tier, signature_verified=prev.signature_verified
        )

    async def list_versions(self, pack_id: uuid.UUID) -> list[RulePackVersion]:
        return await self._repo.list_versions(pack_id)

    async def get_latest_version(
        self, pack_id: uuid.UUID, org_id: uuid.UUID
    ) -> RulePackVersion | None:
        return await self._repo.get_latest_version(pack_id, org_id)

    async def import_signed_pack(
        self,
        tenant: TenantContext,
        pack_name: str,
        content: bytes,
        signature: bytes,
        public_key_path: str,
        rule_specs: list[tuple[str, str, str]],
    ) -> RulePackVersion:
        """Verify *content* against *signature* (Cosign) before accepting any
        rule from a third-party pack. Fails closed: an invalid/tampered/
        unsigned pack is rejected wholesale, audited, and never reaches the
        cost gate or a new version at all.

        *rule_specs* is ``(title, log_type, sigma_yaml)`` per rule -- the
        pack's own parsed manifest content, handed in already-extracted
        (this service does not know the pack's on-disk archive format).
        """
        if not self._signature_verifier.verify(content, signature, public_key_path):
            await self._audit.log(
                AuditEventType.RULE_PACK_SIGNATURE_REJECTED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"pack_name": pack_name},
            )
            raise RulePackError(
                "Rule pack signature verification failed -- pack rejected",
                context={"pack_name": pack_name},
            )

        pack = await self.get_or_create_pack(tenant, pack_name)
        prev = await self._repo.get_latest_version(pack.pack_id, tenant.org_id)
        rules = tuple(
            CustomRule(
                title=title,
                log_type=log_type,
                sigma_yaml=sigma_yaml,
                cost_gate_verdict=self._cost_gate.evaluate(sigma_yaml),
            )
            for title, log_type, sigma_yaml in rule_specs
        )
        return await self._append_version(
            tenant,
            pack,
            (prev.rules if prev else ()) + rules,
            RulePackSourceTier.SIGNED_THIRD_PARTY,
            signature_verified=True,
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

    async def _append_version(
        self,
        tenant: TenantContext,
        pack: RulePack,
        rules: tuple[CustomRule, ...],
        source_tier: RulePackSourceTier,
        *,
        signature_verified: bool,
        content_sha256: str | None = None,
    ) -> RulePackVersion:
        prev = await self._repo.get_latest_version(pack.pack_id, tenant.org_id)
        next_version_num = (prev.version + 1) if prev else 1
        version = RulePackVersion(
            pack_id=pack.pack_id,
            version=next_version_num,
            org_id=tenant.org_id,
            source_tier=source_tier,
            rules=rules,
            signature_verified=signature_verified,
            content_sha256=content_sha256,
        )
        try:
            await self._repo.save_version(version)
        except Exception as exc:
            await self._audit.log(
                AuditEventType.RULE_PACK_VERSION_CREATE_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"pack_name": pack.name, "version": next_version_num, "error": str(exc)},
            )
            raise
        await self._audit.log(
            AuditEventType.RULE_PACK_VERSION_CREATED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={
                "pack_name": pack.name,
                "version": next_version_num,
                "rule_count": len(rules),
                "accepted_count": len(version.accepted_rules),
            },
        )
        return version
