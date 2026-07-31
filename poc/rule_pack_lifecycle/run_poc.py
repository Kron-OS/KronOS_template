"""PoC: exercise the real rule-pack lifecycle (roadmap M2/C3) -- versioning,
Cosign signing, custom-rule CRUD, and the pre-execution cost gate -- against
the real, live dev-stack OpenSearch 2.11.1 Security Analytics plugin, real
PostgreSQL, and a real, pinned Cosign v3.1.2 binary. Imports and calls the
exact classes KronOS ships (src/domain/rule_pack.py,
src/application/rule_pack_service.py, src/application/rule_pack_publisher.py,
src/application/cost_gate.py, src/adapter/opensearch/custom_rule_client.py,
src/adapter/opensearch/custom_rule_detector_provisioner.py,
src/adapter/signing/cosign_verifier.py,
src/adapter/repository/postgres_rule_pack.py) -- not a reimplementation.

Cosign setup this script assumes already happened (real, one-time key-pair
generation + signing -- not something KronOS itself ever does; a rule-pack
PUBLISHER does that offline, out of band):

    cosign generate-key-pair --output-key-prefix /tmp/cosign_poc_test/cosign
    echo "hello rule pack content" > /tmp/cosign_poc_test/pack.bin
    echo "tampered content" > /tmp/cosign_poc_test/pack_tampered.bin
    cosign sign-blob --key /tmp/cosign_poc_test/cosign.key \
        --bundle /tmp/cosign_poc_test/pack.bundle /tmp/cosign_poc_test/pack.bin

Real, pinned cosign version used: v3.1.2 (confirmed via `cosign version`,
see README.md for the exact captured output).

Run: source ~/venv/bin/activate && python poc/rule_pack_lifecycle/run_poc.py
Requires the real dev stack up and a real `cosign` binary on PATH.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

import httpx
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.opensearch.custom_rule_client import SecurityAnalyticsCustomRuleClient  # noqa: E402
from src.adapter.opensearch.custom_rule_detector_provisioner import (  # noqa: E402
    SecurityAnalyticsCustomRuleDetectorProvisioner,
)
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_rule_pack import PostgresRulePackRepository  # noqa: E402
from src.adapter.signing.cosign_verifier import CosignPackSignatureVerifier  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.cost_gate import RuleCostGate  # noqa: E402
from src.application.rule_pack_publisher import RulePackPublisher  # noqa: E402
from src.application.rule_pack_service import RulePackService  # noqa: E402
from src.domain.rule_pack import RulePackSourceTier  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.exceptions import RulePackError  # noqa: E402

OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")
DB_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
COSIGN_DIR = Path("/tmp/cosign_poc_test")

# A synthetic, clean org alias -- NOT kronos-dev. kronos-dev has ~40 legacy
# case indices with inconsistent field mappings that trip OpenSearch SA's
# cross-index alias-consistency check on ANY org-wildcard detector
# (documented in poc/detector_provisioning/README.md, C2). That is a data-
# quality artifact of this dev org's own PoC history, not a defect in this
# rule-pack mechanism -- proven clean here exactly the way C2's own Part 1
# proved detector creation clean against a synthetic org.
ORG_ALIAS = f"c3-poc-{uuid.uuid4().hex[:8]}"
ORG_ID = uuid.uuid4()
USER_ID = uuid.uuid4()

# Real, working shape confirmed via direct curl trial against the live
# cluster before use here: logsource is product/service (zeek-style), not a
# bare "category" field -- that field only exists on OpenSearch's own
# wrapper (passed via the ?category= query param), not inside the Sigma
# YAML itself. description/author/references/falsepositives/tags are all
# required -- omitting any of them reproduces the same real 500
# NullPointerException custom_rule_client.py's docstring documents.
_REASONABLE_RULE = """
title: Reasonable exact-match rule
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: benign exact-match connection rule, used to prove the cost gate accepts reasonable rules
author: kronos-poc
references:
  - https://example.invalid/poc
date: 2026/07/30
logsource:
  product: zeek
  service: conn
detection:
  selection:
    id.resp_p: 4444
  condition: selection
falsepositives:
  - none, this is a PoC rule
level: medium
tags:
  - attack.t1000
"""

_EXPENSIVE_CONTAINS_RULE = """
title: Expensive leading-wildcard rule
id: 22222222-2222-2222-2222-222222222222
status: experimental
description: uses |contains, confirmed to compile to a leading-wildcard query
author: kronos-poc
references:
  - https://example.invalid/poc
date: 2026/07/30
logsource:
  product: zeek
  service: conn
detection:
  selection:
    process.command_line|contains: 'evil'
  condition: selection
falsepositives:
  - none, this is a PoC rule
level: high
tags:
  - attack.t1000
"""

_EXPENSIVE_REGEX_RULE = """
title: Expensive unanchored regex rule
id: 33333333-3333-3333-3333-333333333333
status: experimental
description: uses an unanchored |re, confirmed to compile to a raw regex query
author: kronos-poc
references:
  - https://example.invalid/poc
date: 2026/07/30
logsource:
  product: zeek
  service: dns
detection:
  selection:
    dns.question.name|re: '.*\\.evil\\..*\\.com$'
  condition: selection
falsepositives:
  - none, this is a PoC rule
level: high
tags:
  - attack.t1000
"""

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def make_tenant() -> TenantContext:
    return TenantContext(
        org_id=ORG_ID,
        org_alias=ORG_ALIAS,
        user_id=USER_ID,
        username="rule-pack-poc",
        roles=frozenset({Role.ORG_ADMIN}),
        correlation_id=str(uuid.uuid4()),
    )


def part0_confirm_real_cosign_and_opensearch_reachable() -> None:
    print("\n=== Part 0: confirm the real, pinned tools are reachable ===")
    import subprocess

    result = subprocess.run(["cosign", "version"], capture_output=True, text=True, timeout=10, check=False)
    check("real cosign binary on PATH", result.returncode == 0, result.stdout.strip().splitlines()[-4:])
    check(
        "real signed bundle + keypair exist from prior offline signing step",
        (COSIGN_DIR / "pack.bundle").exists() and (COSIGN_DIR / "cosign.pub").exists(),
    )

    resp = httpx.get(f"{OS_URL}/", auth=OS_ADMIN, verify=False, timeout=10)
    check("real live OpenSearch cluster reachable", resp.status_code == 200, f"status={resp.status_code}")


async def part1_cost_gate() -> None:
    print("\n=== Part 1: real cost gate -- accept reasonable, reject expensive ===")
    gate = RuleCostGate()

    reasonable_verdict = gate.evaluate(_REASONABLE_RULE)
    check("a genuinely reasonable exact-match rule is ACCEPTED", reasonable_verdict.accepted, str(reasonable_verdict.decision))

    contains_verdict = gate.evaluate(_EXPENSIVE_CONTAINS_RULE)
    check(
        "a |contains rule (real leading-wildcard compile target) is REJECTED",
        not contains_verdict.accepted,
        str([f.reason for f in contains_verdict.findings]),
    )

    regex_verdict = gate.evaluate(_EXPENSIVE_REGEX_RULE)
    check(
        "an unanchored |re rule (real raw-regex compile target) is REJECTED",
        not regex_verdict.accepted,
        str([f.reason for f in regex_verdict.findings]),
    )

    # Confirm OpenSearch itself accepts these expensive shapes with ZERO
    # validation -- the real reason this gate has to exist client-side.
    client = SecurityAnalyticsCustomRuleClient(OS_URL, "admin", "admin")
    opensearch_id = await client.create_rule(_EXPENSIVE_CONTAINS_RULE, "network")
    check(
        "confirmed: OpenSearch's own rule-creation API accepts the expensive "
        "|contains rule with NO cost-related rejection (the real reason "
        "this gate must run BEFORE OpenSearch ever sees the rule)",
        bool(opensearch_id),
        f"opensearch_id={opensearch_id}",
    )
    await client.delete_rule(opensearch_id)


async def part2_versioned_custom_rule_crud(
    rule_pack_service: RulePackService,
) -> None:
    print("\n=== Part 2: real versioned CRUD against real Postgres ===")
    tenant = make_tenant()

    rule_v1 = await rule_pack_service.add_custom_rule(
        tenant, "my-pack", "Rule A", _REASONABLE_RULE, "network"
    )
    check("first rule added, cost-gate accepted", rule_v1.is_accepted)

    pack = await rule_pack_service.get_or_create_pack(tenant, "my-pack")
    v1 = await rule_pack_service.get_latest_version(pack.pack_id)
    check("pack is now at version 1 with 1 rule", v1 is not None and v1.version == 1 and len(v1.rules) == 1)

    rule_v2 = await rule_pack_service.add_custom_rule(
        tenant, "my-pack", "Rule B (expensive)", _EXPENSIVE_CONTAINS_RULE, "network"
    )
    check("second rule added, cost-gate rejected it (stored anyway, not silently dropped)", not rule_v2.is_accepted)

    v2 = await rule_pack_service.get_latest_version(pack.pack_id)
    check("pack is now at version 2 with 2 rules total", v2 is not None and v2.version == 2 and len(v2.rules) == 2)

    all_versions = await rule_pack_service.list_versions(pack.pack_id)
    check(
        "version 1 is still retrievable and unchanged -- creating v2 never lost v1 "
        "(roadmap invariant #6: replayability)",
        len(all_versions) == 2 and all_versions[0].version == 1 and len(all_versions[0].rules) == 1,
        f"versions={[ (v.version, len(v.rules)) for v in all_versions ]}",
    )
    check(
        "only 1 of 2 rules in the latest version is ACCEPTED (the cost-gated one is excluded)",
        len(v2.accepted_rules) == 1,
        f"accepted={[r.title for r in v2.accepted_rules]}",
    )


async def part3_cosign_signed_import(rule_pack_service: RulePackService) -> None:
    print("\n=== Part 3: real Cosign signature verification gates pack import ===")
    tenant = make_tenant()
    content = (COSIGN_DIR / "pack.bin").read_bytes()
    tampered = (COSIGN_DIR / "pack_tampered.bin").read_bytes()
    bundle = (COSIGN_DIR / "pack.bundle").read_bytes()
    pub_key = str(COSIGN_DIR / "cosign.pub")

    version = await rule_pack_service.import_signed_pack(
        tenant,
        "signed-pack",
        content,
        bundle,
        pub_key,
        rule_specs=[("Signed Rule", "network", _REASONABLE_RULE)],
    )
    check(
        "a validly-signed pack is accepted -- real signature_verified=True, "
        "real content_sha256 recorded",
        version.signature_verified is True and version.content_sha256 == __import__("hashlib").sha256(content).hexdigest(),
        f"signature_verified={version.signature_verified}",
    )
    check(
        "the imported version is tagged SIGNED_THIRD_PARTY",
        version.source_tier == RulePackSourceTier.SIGNED_THIRD_PARTY,
    )

    rejected = False
    try:
        await rule_pack_service.import_signed_pack(
            tenant,
            "tampered-pack",
            tampered,
            bundle,  # bundle signs `content`, NOT `tampered` -- real signature mismatch
            pub_key,
            rule_specs=[("Should Never Land", "network", _REASONABLE_RULE)],
        )
    except RulePackError:
        rejected = True
    check(
        "a real signature/content mismatch (tampered bytes, real bundle) is "
        "REJECTED wholesale -- no rule from it ever reaches a new version",
        rejected,
    )
    tampered_pack = await rule_pack_service.get_or_create_pack(tenant, "tampered-pack")
    tampered_version = await rule_pack_service.get_latest_version(tampered_pack.pack_id)
    check(
        "the rejected pack has NO version at all (fails closed before any bookkeeping)",
        tampered_version is None,
    )


async def part4_publish_and_real_detector_scoping(
    rule_pack_service: RulePackService, publisher: RulePackPublisher, rule_pack_repo
) -> None:
    print("\n=== Part 4: publish accepted rules to a real detector, confirm real tenant scoping ===")
    tenant = make_tenant()

    published_count = await publisher.publish_pack_version(tenant, "my-pack", "network")
    check(
        "exactly 1 rule published (the accepted one; the cost-gated one never reaches OpenSearch)",
        published_count == 1,
        f"published={published_count}",
    )

    # Re-run: idempotent, nothing new to publish.
    published_again = await publisher.publish_pack_version(tenant, "my-pack", "network")
    check("re-publish is idempotent -- 0 newly published", published_again == 0)

    detector_name = f"kronos-{ORG_ALIAS}-network-custom-detector"
    resp = httpx.post(
        f"{OS_URL}/_plugins/_security_analytics/detectors/_search",
        auth=OS_ADMIN,
        verify=False,
        timeout=15,
        json={"size": 1, "query": {"nested": {"path": "detector", "query": {"term": {"detector.name.keyword": detector_name}}}}},
    )
    hits = resp.json().get("hits", {}).get("hits", [])
    check("a real custom-rule detector was created for this org+log_type", len(hits) == 1)
    if hits:
        indices = hits[0]["_source"]["inputs"][0]["detector_input"]["indices"]
        check(
            "the detector's index pattern is scoped to THIS org's own wildcard only "
            "(roadmap risk (b): tenant isolation computed from TenantContext, never rule content)",
            indices == [f"kronos-{ORG_ALIAS}-*"],
            str(indices),
        )
        custom_rules = hits[0]["_source"]["inputs"][0]["detector_input"]["custom_rules"]
        check("exactly 1 custom rule id attached (only the accepted one)", len(custom_rules) == 1)

    # Cleanup: delete the real detector this PoC created.
    if hits:
        d = httpx.delete(
            f"{OS_URL}/_plugins/_security_analytics/detectors/{hits[0]['_id']}",
            auth=OS_ADMIN,
            verify=False,
            timeout=15,
        )
        print(f"  cleanup: deleted detector {hits[0]['_id']}, status={d.status_code}")

    # Cleanup: delete the real custom rule this PoC published.
    pack = await rule_pack_service.get_or_create_pack(make_tenant(), "my-pack")
    version = await rule_pack_service.get_latest_version(pack.pack_id)
    for rule in version.accepted_rules if version else ():
        opensearch_id = await rule_pack_repo.get_published_opensearch_id(rule.rule_id)
        if opensearch_id:
            r = httpx.delete(
                f"{OS_URL}/_plugins/_security_analytics/rules/{opensearch_id}",
                auth=OS_ADMIN,
                verify=False,
                timeout=15,
            )
            print(f"  cleanup: deleted custom rule {opensearch_id}, status={r.status_code}")


async def main() -> None:
    part0_confirm_real_cosign_and_opensearch_reachable()
    await part1_cost_gate()

    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    await PostgresRulePackRepository.create_tables(engine)
    await PostgresAuditLogRepository.create_tables(engine)
    rule_pack_repo = PostgresRulePackRepository(engine)
    audit_log = AuditLogService(PostgresAuditLogRepository(engine))
    signature_verifier = CosignPackSignatureVerifier()
    cost_gate = RuleCostGate()

    rule_pack_service = RulePackService(rule_pack_repo, cost_gate, signature_verifier, audit_log)
    custom_rule_client = SecurityAnalyticsCustomRuleClient(OS_URL, "admin", "admin")
    detector_binder = SecurityAnalyticsCustomRuleDetectorProvisioner(OS_URL, "admin", "admin")
    publisher = RulePackPublisher(rule_pack_repo, custom_rule_client, detector_binder, audit_log)

    await part2_versioned_custom_rule_crud(rule_pack_service)
    await part3_cosign_signed_import(rule_pack_service)
    await part4_publish_and_real_detector_scoping(rule_pack_service, publisher, rule_pack_repo)

    await engine.dispose()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
