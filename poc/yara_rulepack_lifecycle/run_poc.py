#!/usr/bin/env python3
"""Verification-first PoC: YARA rule-pack lifecycle -- signed, versioned,
published (roadmap E4, "same trust model as C3, applied to YARA rulesets"),
against real, live dependencies.

Pinned versions (matches poc/rule_pack_lifecycle/, poc/yara_recursion_scanning/):
  - Postgres: docker-postgres-1 (postgres:16-alpine).
  - Cosign: v3.1.2 (confirmed below via `cosign version`; already installed
    to ~/.local/bin/cosign from C3's own session, reused unchanged here --
    NOT re-pinned/reinstalled).
  - yara-x: 1.19.0 (pyproject.toml pin), via the real, unmodified
    YaraXSandboxRunner (roadmap E2) -- real subprocess worker
    (docker/yara/kronos-yarax-worker.py), no in-process rule compilation.

This script drives the real, unmodified production classes:
  YaraRulePackService              (src/application/yara_rule_pack_service.py)
  PostgresYaraRulePackRepository   (src/adapter/repository/postgres_yara_rule_pack.py)
  CosignPackSignatureVerifier      (src/adapter/signing/cosign_verifier.py --
                                    the SAME class C3 uses, reused unchanged)
  SignedYaraRulePackProvider       (src/application/yara_rules.py)
  yara_scan_org_var                (src/application/yara_rules.py)
  ZipArchiveParser.extract_artifacts()  (src/external/parsers/archive.py --
                                    completely unmodified by E4)
  YaraXSandboxRunner               (src/external/sandbox/yara_x_runner.py)

## Cosign setup this script assumes already happened (real, one-time,
## out-of-band -- a rule-pack PUBLISHER does this offline, not KronOS itself):

    mkdir -p /tmp/cosign_poc_yara
    cat > /tmp/cosign_poc_yara/yara_pack_content.bin <<'RULE'
    rule Finds_Evil_Marker_E4Poc
    {
        meta:
            author = "kronos-e4-poc"
            description = "Detects EVIL_MARKER_STRING used by the E4 PoC"
        strings:
            $marker = "EVIL_MARKER_STRING"
        condition:
            $marker
    }
    RULE
    echo "tampered content, not what was signed" > \
        /tmp/cosign_poc_yara/yara_pack_content_tampered.bin
    COSIGN_PASSWORD="" cosign sign-blob --yes \
        --key /tmp/cosign_poc_test/cosign.key \
        --bundle /tmp/cosign_poc_yara/yara_pack.bundle \
        /tmp/cosign_poc_yara/yara_pack_content.bin

(Reuses the SAME cosign.key/cosign.pub key pair `poc/rule_pack_lifecycle/`
already generated at /tmp/cosign_poc_test/ -- not regenerated here; a
signer's key identity is the same real-world artifact whether the content
being signed is a Sigma pack or a YARA pack.)

## What this proves, in order:

Part 0 -- real pinned tool versions (cosign, confirms nothing assumed).
Part 1 -- real Postgres, real append-only versioned CRUD: add_rule creates
          v1, a second add_rule creates v2 WITHOUT losing v1's content.
Part 2 -- real Cosign verify-blob: the valid bundle over the real signed
          content is accepted (SIGNED_THIRD_PARTY, signature_verified=True,
          a real content_sha256 recorded); the SAME bundle over tampered
          content bytes is rejected wholesale (RulePackError, zero versions
          created for that pack -- fails closed before any bookkeeping).
Part 3 -- publish_version + SignedYaraRulePackProvider.get_rule_source():
          before publishing, the org-bound provider returns None (added but
          unpublished content must not leak into scanning); after
          publishing, it returns the real rule text, and ONLY that org's
          published content (a second, unrelated org sees None).
Part 4 -- the full real chain: sign -> publish -> provider -> scan ->
          StructuredArtifact. A real zip evidence file containing a member
          with the marker string is scanned by the real, completely
          unmodified ZipArchiveParser.extract_artifacts(), sourcing its
          rule text through SignedYaraRulePackProvider (not
          DirectoryYaraRuleProvider) via the real YaraXSandboxRunner
          subprocess, and yields a real StructuredArtifact(kind="yara.match")
          naming the exact published rule.

Run: ~/venv/bin/python3 poc/yara_rulepack_lifecycle/run_poc.py
Requires: the real dev-stack Postgres (docker-postgres-1) up, the real
`cosign` binary on PATH, and the one-time signing setup above already done.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text as sa_text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_yara_rule_pack import (  # noqa: E402
    PostgresYaraRulePackRepository,
)
from src.adapter.signing.cosign_verifier import CosignPackSignatureVerifier  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.parser_registry import ParserRegistry  # noqa: E402
from src.application.yara_rule_pack_service import YaraRulePackService  # noqa: E402
from src.application.yara_rules import SignedYaraRulePackProvider, yara_scan_org_var  # noqa: E402
from src.domain.evidence import Evidence, EvidenceMetadata  # noqa: E402
from src.domain.rule_pack import RulePackSourceTier  # noqa: E402
from src.exceptions import RulePackError  # noqa: E402
from src.external.parsers.archive import ZipArchiveParser  # noqa: E402
from src.external.sandbox.yara_x_runner import YaraXSandboxRunner  # noqa: E402
from tests.conftest import InMemoryAuditLogRepository  # noqa: E402
from tests.fixtures.factories import make_tenant_context  # noqa: E402

DB_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

COSIGN_KEY_DIR = Path("/tmp/cosign_poc_test")
COSIGN_YARA_DIR = Path("/tmp/cosign_poc_yara")
PUBLIC_KEY_PATH = str(COSIGN_KEY_DIR / "cosign.pub")
SIGNED_CONTENT_PATH = COSIGN_YARA_DIR / "yara_pack_content.bin"
TAMPERED_CONTENT_PATH = COSIGN_YARA_DIR / "yara_pack_content_tampered.bin"
BUNDLE_PATH = COSIGN_YARA_DIR / "yara_pack.bundle"

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}", flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _make_evidence(sha256: str, org_id: uuid.UUID) -> Evidence:
    return Evidence(
        metadata=EvidenceMetadata(
            original_filename="poc-e4.zip",
            content_type="application/zip",
            size_bytes=1024,
            uploader_user_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=org_id,
            org_alias="poc-e4-org",
        ),
        sha256=sha256,
    )


async def _bytes_stream(data: bytes):
    yield data


def _build_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


async def main() -> int:
    log("=" * 78)
    log("PoC: YARA rule-pack lifecycle -- signed, versioned, published (roadmap E4)")
    log("=" * 78)

    # -----------------------------------------------------------------
    # Part 0: pinned real tool versions
    # -----------------------------------------------------------------
    log("\n" + "=" * 78)
    log("PART 0: real pinned tool versions")
    log("=" * 78)
    cosign_version = subprocess.run(  # noqa: S603
        ["cosign", "version"], capture_output=True, text=True, timeout=15, check=False
    )
    log(cosign_version.stdout)
    check("cosign v3.1.2 confirmed via real `cosign version`", "v3.1.2" in cosign_version.stdout)
    check("real signed content fixture exists", SIGNED_CONTENT_PATH.is_file())
    check("real Cosign bundle fixture exists", BUNDLE_PATH.is_file())

    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    await PostgresYaraRulePackRepository.create_tables(engine)
    repository = PostgresYaraRulePackRepository(engine)
    signature_verifier = CosignPackSignatureVerifier()
    audit_log = AuditLogService(InMemoryAuditLogRepository())
    service = YaraRulePackService(
        repository=repository, signature_verifier=signature_verifier, audit_log=audit_log
    )

    org_alias = f"e4-poc-{uuid.uuid4().hex[:8]}"
    tenant = make_tenant_context()
    tenant = tenant.model_copy(update={"org_alias": org_alias})
    log(f"\nreal synthetic org for this run: org_id={tenant.org_id} org_alias={org_alias}")

    try:
        # ---------------------------------------------------------------
        # Part 1: real Postgres, real append-only versioned CRUD
        # ---------------------------------------------------------------
        log("\n" + "=" * 78)
        log("PART 1: real Postgres append-only versioned CRUD")
        log("=" * 78)

        rule_a_source = 'rule RuleA_Poc { strings: $a = "POC_RULE_A" condition: $a }'
        rule_b_source = 'rule RuleB_Poc { strings: $b = "POC_RULE_B" condition: $b }'
        await service.add_rule(tenant, "custom-pack", "RuleA", rule_a_source)
        pack = await service.get_or_create_pack(tenant, "custom-pack")
        v1 = await service.get_latest_version(pack.pack_id)
        log(
            f"after 1st add_rule: version={v1.version if v1 else None}, "
            f"rule_count={len(v1.rules) if v1 else 0}"
        )
        check("first add_rule creates version 1", v1 is not None and v1.version == 1)
        check("version 1 has exactly 1 rule", v1 is not None and len(v1.rules) == 1)

        await service.add_rule(tenant, "custom-pack", "RuleB", rule_b_source)
        v2 = await service.get_latest_version(pack.pack_id)
        all_versions = await service.list_versions(pack.pack_id)
        log(
            f"after 2nd add_rule: version={v2.version if v2 else None}, "
            f"rule_count={len(v2.rules) if v2 else 0}, total versions={len(all_versions)}"
        )
        check("second add_rule creates version 2", v2 is not None and v2.version == 2)
        check("version 2 has both rules", v2 is not None and len(v2.rules) == 2)
        check(
            "version 1 remains independently retrievable (never lost)",
            any(v.version == 1 and len(v.rules) == 1 for v in all_versions),
        )
        check(
            "org_id on every version is the real tenant's org_id, never content-derived",
            all(v.org_id == tenant.org_id for v in all_versions),
        )

        # ---------------------------------------------------------------
        # Part 2: real Cosign signature gate
        # ---------------------------------------------------------------
        log("\n" + "=" * 78)
        log("PART 2: real Cosign verify-blob signature gate")
        log("=" * 78)

        signed_content = SIGNED_CONTENT_PATH.read_bytes()
        bundle_bytes = BUNDLE_PATH.read_bytes()
        rule_specs = [("SignedRule", signed_content.decode("utf-8"))]

        signed_version = await service.import_signed_pack(
            tenant, "signed-pack", signed_content, bundle_bytes, PUBLIC_KEY_PATH, rule_specs
        )
        log(
            f"real signed import: version={signed_version.version} "
            f"signature_verified={signed_version.signature_verified} "
            f"source_tier={signed_version.source_tier} "
            f"content_sha256={signed_version.content_sha256}"
        )
        check("valid signature: signature_verified=True", signed_version.signature_verified is True)
        check(
            "valid signature: tagged SIGNED_THIRD_PARTY",
            signed_version.source_tier == RulePackSourceTier.SIGNED_THIRD_PARTY,
        )
        check(
            "valid signature: content_sha256 matches the real signed bytes",
            signed_version.content_sha256 == hashlib.sha256(signed_content).hexdigest(),
        )

        tampered_content = TAMPERED_CONTENT_PATH.read_bytes()
        tampered_pack = await service.get_or_create_pack(tenant, "tampered-pack")
        rejected = False
        try:
            await service.import_signed_pack(
                tenant,
                "tampered-pack",
                tampered_content,
                bundle_bytes,
                PUBLIC_KEY_PATH,
                rule_specs,
            )
        except RulePackError as exc:
            rejected = True
            log(f"real rejection (expected): {exc}")
        check("tampered content over the same real bundle is rejected", rejected)
        tampered_version = await service.get_latest_version(tampered_pack.pack_id)
        check(
            "rejected import creates NO version at all (fails closed before bookkeeping)",
            tampered_version is None,
        )

        # ---------------------------------------------------------------
        # Part 3: publish + org-scoped SignedYaraRulePackProvider
        # ---------------------------------------------------------------
        log("\n" + "=" * 78)
        log("PART 3: publish_version + SignedYaraRulePackProvider (org-scoped)")
        log("=" * 78)

        provider = SignedYaraRulePackProvider(repository)

        token = yara_scan_org_var.set(tenant.org_id)
        try:
            pre_publish_source = await provider.get_rule_source()
        finally:
            yara_scan_org_var.reset(token)
        log(f"provider.get_rule_source() BEFORE publish: {pre_publish_source!r}")
        check(
            "added-but-unpublished rules do not leak into the provider",
            pre_publish_source is None,
        )

        published = await service.publish_version(tenant, "custom-pack", 2)
        log(f"published pack 'custom-pack' version {published.version}")

        token = yara_scan_org_var.set(tenant.org_id)
        try:
            post_publish_source = await provider.get_rule_source()
        finally:
            yara_scan_org_var.reset(token)
        log(
            f"provider.get_rule_source() AFTER publish (truncated): "
            f"{(post_publish_source or '')[:120]!r}"
        )
        check(
            "provider returns real published rule text after publish",
            post_publish_source is not None
            and "RuleA_Poc" in post_publish_source
            and "RuleB_Poc" in post_publish_source,
        )

        other_tenant = make_tenant_context()
        token = yara_scan_org_var.set(other_tenant.org_id)
        try:
            other_org_source = await provider.get_rule_source()
        finally:
            yara_scan_org_var.reset(token)
        check(
            "a different org's context sees no rules from this org's published pack",
            other_org_source is None,
        )

        token = yara_scan_org_var.set(None)
        try:
            no_context_source = await provider.get_rule_source()
        finally:
            yara_scan_org_var.reset(token)
        check(
            "no bound org context at all -> honest None, never a fallback ruleset",
            no_context_source is None,
        )

        # ---------------------------------------------------------------
        # Part 4: full real chain -- sign -> publish -> provider -> scan
        # ---------------------------------------------------------------
        log("\n" + "=" * 78)
        log(
            "PART 4: real end-to-end -- ZipArchiveParser.extract_artifacts() "
            "(unmodified) scanning via SignedYaraRulePackProvider"
        )
        log("=" * 78)

        # A fresh pack whose rule text matches the marker embedded in the
        # real zip below, published so the provider will actually serve it.
        marker_rule_source = SIGNED_CONTENT_PATH.read_text()
        await service.add_rule(tenant, "scan-pack", "Finds_Evil_Marker_E4Poc", marker_rule_source)
        scan_pack = await service.get_or_create_pack(tenant, "scan-pack")
        await service.publish_version(tenant, "scan-pack", 1)

        yara_runner = YaraXSandboxRunner()
        registry = ParserRegistry()
        registry.register(
            ZipArchiveParser(registry, yara_runner=yara_runner, yara_rule_provider=provider)
        )

        zip_bytes = _build_zip(
            {
                "benign.txt": b"nothing interesting here at all",
                "evil.bin": b"xxxxEVIL_MARKER_STRINGxxxx",
            }
        )
        evidence_sha256 = hashlib.sha256(zip_bytes).hexdigest()
        evidence = _make_evidence(evidence_sha256, tenant.org_id)

        parser = registry.get_parser("bundle.zip", "application/zip", zip_bytes[:8192])
        assert isinstance(parser, ZipArchiveParser)

        token = yara_scan_org_var.set(tenant.org_id)
        try:
            artifacts = [
                a
                async for a in parser.extract_artifacts(_bytes_stream(zip_bytes), evidence, tenant)
            ]
        finally:
            yara_scan_org_var.reset(token)

        log(f"extract_artifacts() yielded {len(artifacts)} real StructuredArtifact(s)")
        for a in artifacts:
            log(
                f"  kind={a.kind} source_path={a.kronos.source_path} "
                f"rule={a.content['rule_identifier']} "
                f"matched_strings={a.content['matched_strings']}"
            )

        check("real end-to-end scan yields exactly 1 match (evil.bin)", len(artifacts) == 1)
        check(
            "the match names the real rule sourced through SignedYaraRulePackProvider",
            bool(artifacts)
            and artifacts[0].content["rule_identifier"] == "Finds_Evil_Marker_E4Poc",
        )
        check(
            "source_path correctly identifies the matching member",
            bool(artifacts) and artifacts[0].kronos.source_path == "evil.bin",
        )
        check(
            "org_id on the artifact is the real tenant's org_id, never from pack/rule content",
            bool(artifacts) and artifacts[0].kronos.org_id == tenant.org_id,
        )

        # ---------------------------------------------------------------
        # Cleanup / inspection note
        # ---------------------------------------------------------------
        log("\n" + "=" * 78)
        log(
            "Real Postgres rows left in place as inspectable proof of this run "
            "(matching poc/rule_pack_lifecycle/'s own convention) -- packs: "
            f"{pack.pack_id}, {tampered_pack.pack_id}, {scan_pack.pack_id}"
        )
        log("=" * 78)

    finally:
        await engine.dispose()

    log("\n" + "=" * 78)
    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(f"RESULT: {passed}/{total} checks passed")
    log("=" * 78)
    if passed != total:
        for label, ok in CHECKS:
            if not ok:
                log(f"  FAILED: {label}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
