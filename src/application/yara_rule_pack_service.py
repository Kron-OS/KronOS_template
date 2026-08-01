"""YaraRulePackService: versioned, signed, tenant-scoped YARA-X rule CRUD +
publish (roadmap E4 -- "same trust model as C3, applied to YARA rulesets").

Mirrors ``src/application/rule_pack_service.py`` (``RulePackService``)
shape-for-shape, with two deliberate differences from the Sigma analogue:

1. **No cost gate.** See ``src/domain/yara_rule_pack.py``'s module
   docstring for the full reasoning -- YARA-X scanning already runs inside
   a wall-clock-bounded sandboxed subprocess (roadmap E2), which is a real,
   existing mitigation for the risk shape a cost gate would otherwise
   exist to catch; Sigma's cost gate exists because ITS risk (a shared
   multi-tenant OpenSearch cluster taking an expensive query) has no
   equivalent bound.
2. **No separate "publisher" class reaching an external system.** C3 needs
   ``RulePackPublisher`` because pushing an accepted rule to OpenSearch and
   wiring a detector is a real network call to a shared cluster, distinct
   from bookkeeping. A YARA rule pack's only "real system" is this
   process's own repository -- ``publish_version`` just flips a local
   pointer (``YaraRulePackRepository.publish_version``), so it lives on
   this service directly rather than a sibling class.

``org_id``/``org_alias`` are ALWAYS taken from the caller's authenticated
``TenantContext`` -- never from pack or rule content, mirroring
``StructuredArtifact.org_id``/``Detection.org_id``/``RulePackVersion.org_id``
(CLAUDE.md SS G.3).
"""

from __future__ import annotations

import hashlib
import logging
import uuid

from src.adapter.repository.yara_rule_pack import YaraRulePackRepository
from src.application.audit_log import AuditLogService
from src.application.pack_signing import PackSignatureVerifier
from src.domain.audit import AuditEventType
from src.domain.rule_pack import RulePackSourceTier
from src.domain.user import TenantContext
from src.domain.yara_rule_pack import YaraRule, YaraRulePack, YaraRulePackVersion
from src.exceptions import RulePackError, ValidationError

logger = logging.getLogger(__name__)


class YaraRulePackService:
    """Versioned CRUD + publish for tenant-authored/signed YARA rule packs."""

    def __init__(
        self,
        repository: YaraRulePackRepository,
        signature_verifier: PackSignatureVerifier,
        audit_log: AuditLogService,
    ) -> None:
        self._repo = repository
        self._signature_verifier = signature_verifier
        self._audit = audit_log

    async def get_or_create_pack(self, tenant: TenantContext, pack_name: str) -> YaraRulePack:
        return await self._repo.get_or_create_pack(tenant.org_id, pack_name)

    async def add_rule(
        self, tenant: TenantContext, pack_name: str, rule_name: str, rule_source: str
    ) -> YaraRule:
        """Append *rule_source* as a NEW version of *pack_name*.

        Unlike C3's ``add_custom_rule``, there is no cost-gate verdict to
        record -- see this module's own docstring for why. The rule is
        appended, not published: a new version never becomes "live" for
        scanning until ``publish_version`` is called explicitly (CLAUDE.md
        SS A.6 -- no silent side effects from a CRUD mutation reaching a
        real scan path unreviewed).
        """
        pack = await self.get_or_create_pack(tenant, pack_name)
        rule = YaraRule(name=rule_name, rule_source=rule_source)
        prev = await self._repo.get_latest_version(pack.pack_id)
        new_rules = (prev.rules if prev else ()) + (rule,)
        await self._append_version(
            tenant, pack, new_rules, RulePackSourceTier.TENANT_CUSTOM, signature_verified=False
        )
        return rule

    async def update_rule(
        self, tenant: TenantContext, pack_name: str, rule_name: str, rule_source: str
    ) -> YaraRule:
        """Replace the rule named *rule_name* in *pack_name* with new
        content, as a new version. Raises ValidationError if no rule with
        that name exists in the pack's latest version (use ``add_rule`` for
        a new rule).
        """
        pack = await self.get_or_create_pack(tenant, pack_name)
        prev = await self._repo.get_latest_version(pack.pack_id)
        if prev is None or not any(r.name == rule_name for r in prev.rules):
            raise ValidationError(
                "No existing rule with this name to update",
                context={"pack_name": pack_name, "rule_name": rule_name},
            )
        new_rule = YaraRule(name=rule_name, rule_source=rule_source)
        new_rules = tuple(r for r in prev.rules if r.name != rule_name) + (new_rule,)
        await self._append_version(
            tenant, pack, new_rules, RulePackSourceTier.TENANT_CUSTOM, signature_verified=False
        )
        return new_rule

    async def delete_rule(self, tenant: TenantContext, pack_name: str, rule_name: str) -> None:
        """Remove the rule named *rule_name* from *pack_name*, as a new
        version. Bookkeeping only -- the previously-published version (if
        any) keeps serving scans until ``publish_version`` is called again
        against the new version.
        """
        pack = await self.get_or_create_pack(tenant, pack_name)
        prev = await self._repo.get_latest_version(pack.pack_id)
        if prev is None:
            return
        remaining = tuple(r for r in prev.rules if r.name != rule_name)
        if len(remaining) == len(prev.rules):
            return  # nothing to delete
        await self._append_version(
            tenant, pack, remaining, prev.source_tier, signature_verified=prev.signature_verified
        )

    async def list_versions(self, pack_id: uuid.UUID) -> list[YaraRulePackVersion]:
        return await self._repo.list_versions(pack_id)

    async def get_latest_version(self, pack_id: uuid.UUID) -> YaraRulePackVersion | None:
        return await self._repo.get_latest_version(pack_id)

    async def import_signed_pack(
        self,
        tenant: TenantContext,
        pack_name: str,
        content: bytes,
        signature: bytes,
        public_key_path: str,
        rule_specs: list[tuple[str, str]],
    ) -> YaraRulePackVersion:
        """Verify *content* against *signature* (Cosign) before accepting any
        rule from a third-party pack. Fails closed: an invalid/tampered/
        unsigned pack is rejected wholesale, audited, and never reaches a
        new version at all -- mirrors ``RulePackService.import_signed_pack``
        exactly (reuses the same ``PackSignatureVerifier`` port/
        ``CosignPackSignatureVerifier`` implementation; see
        ``src/adapter/signing/cosign_verifier.py``'s own docstring for why
        it needed no changes to support this content type).

        *rule_specs* is ``(name, rule_source)`` per rule -- the pack's own
        parsed manifest content, handed in already-extracted (this service
        does not know the pack's on-disk archive format).
        """
        if not self._signature_verifier.verify(content, signature, public_key_path):
            await self._audit.log(
                AuditEventType.YARA_RULE_PACK_SIGNATURE_REJECTED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"pack_name": pack_name},
            )
            raise RulePackError(
                "YARA rule pack signature verification failed -- pack rejected",
                context={"pack_name": pack_name},
            )

        pack = await self.get_or_create_pack(tenant, pack_name)
        prev = await self._repo.get_latest_version(pack.pack_id)
        rules = tuple(
            YaraRule(name=name, rule_source=rule_source) for name, rule_source in rule_specs
        )
        return await self._append_version(
            tenant,
            pack,
            (prev.rules if prev else ()) + rules,
            RulePackSourceTier.SIGNED_THIRD_PARTY,
            signature_verified=True,
            content_sha256=hashlib.sha256(content).hexdigest(),
        )

    async def publish_version(
        self, tenant: TenantContext, pack_name: str, version: int
    ) -> YaraRulePackVersion:
        """Mark *version* of *pack_name* as the currently-active version for
        scanning (what ``SignedYaraRulePackProvider.get_rule_source()``
        reads). Raises ValidationError if *version* does not exist for this
        pack -- the repository's own ``publish_version`` does not
        cross-check, so the service is where that real existence check
        happens before ever touching the pointer.
        """
        pack = await self.get_or_create_pack(tenant, pack_name)
        versions = await self._repo.list_versions(pack.pack_id)
        target = next((v for v in versions if v.version == version), None)
        if target is None:
            await self._audit.log(
                AuditEventType.YARA_RULE_PACK_PUBLISH_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"pack_name": pack_name, "version": version, "error": "no such version"},
            )
            raise ValidationError(
                "No such version to publish",
                context={"pack_name": pack_name, "version": version},
            )

        await self._repo.publish_version(pack.pack_id, version)
        await self._audit.log(
            AuditEventType.YARA_RULE_PACK_VERSION_PUBLISHED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={
                "pack_name": pack_name,
                "version": version,
                "rule_count": len(target.rules),
            },
        )
        return target

    async def get_published_version(self, pack_id: uuid.UUID) -> YaraRulePackVersion | None:
        return await self._repo.get_published_version(pack_id)

    async def _append_version(
        self,
        tenant: TenantContext,
        pack: YaraRulePack,
        rules: tuple[YaraRule, ...],
        source_tier: RulePackSourceTier,
        *,
        signature_verified: bool,
        content_sha256: str | None = None,
    ) -> YaraRulePackVersion:
        prev = await self._repo.get_latest_version(pack.pack_id)
        next_version_num = (prev.version + 1) if prev else 1
        version = YaraRulePackVersion(
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
                AuditEventType.YARA_RULE_PACK_VERSION_CREATE_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"pack_name": pack.name, "version": next_version_num, "error": str(exc)},
            )
            raise
        await self._audit.log(
            AuditEventType.YARA_RULE_PACK_VERSION_CREATED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            details={
                "pack_name": pack.name,
                "version": next_version_num,
                "rule_count": len(rules),
            },
        )
        return version
