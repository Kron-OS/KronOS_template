#!/usr/bin/env python3
"""Verification-first PoC: YARA scanning in the recursion path -> StructuredArtifact
(roadmap M4/E3), against the real, already-running dev-stack Postgres.

Pinned versions (matches poc/yarax_sandboxed_runner/, poc/tar_container_unwrapping/):
  - Postgres: docker-postgres-1 (postgres:16-alpine).
  - yara-x: 1.19.0 (pyproject.toml pin), real subprocess worker
    (docker/yara/kronos-yarax-worker.py) via the real, unmodified
    YaraXSandboxRunner (roadmap E2).

This script drives the real, unmodified production classes:
  ZipArchiveParser.extract_artifacts()  (src/external/parsers/archive.py)
  TarArchiveParser.extract_artifacts()  (src/external/parsers/tar_archive.py)
  DirectoryYaraRuleProvider             (src/application/yara_rules.py)
  YaraXSandboxRunner                    (src/external/sandbox/yara_x_runner.py)
  PostgresArtifactRepository            (src/adapter/repository/postgres_artifact.py)

Not driven through the full HTTP evidence-intake API: no real ruleset exists
in production yet (E4, ruleset lifecycle, hasn't started) so
configure_dependencies() is deliberately never given a fake default
yara_runner/yara_rule_provider (see src/external/dependencies.py's own
comment on this) -- this PoC instead constructs the real parser + real
runner + real rule provider directly, exactly the level ArtifactIngestService
itself already operates at, and persists through the real repository, the
same honest scope this item's own brief called for.

Scenarios:
  (a) A real zip container with 3 members: one containing a byte pattern a
      real YARA-X rule matches, one that doesn't, and one that is itself a
      nested tar (so the E3 "recurse into nested containers" path is
      exercised too). Confirms exactly the right StructuredArtifact rows
      land in real Postgres with correct source_path/container_sha256/byte
      offsets, and that the non-matching/no-match members produce nothing.
  (b) A malformed ruleset -- confirms a clean compile-error abort (no crash,
      no artifacts, real audit-free continuation).
  (c) Independently measures the real, complete YaraXSandboxRunner.run()
      round-trip cost on this host (not just a bare subprocess launch) --
      this measurement is what corrected ZipArchiveParser.extract_artifacts()'s
      own docstring, which originally quoted a narrower, too-optimistic
      number from an in-process (no real worker) measurement.

Run: ~/venv/bin/python3 poc/yara_recursion_scanning/run_poc.py
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import text as sa_text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.repository.postgres_artifact import PostgresArtifactRepository  # noqa: E402
from src.application.parser_registry import ParserRegistry  # noqa: E402
from src.application.yara_rules import DirectoryYaraRuleProvider  # noqa: E402
from src.domain.evidence import Evidence, EvidenceMetadata  # noqa: E402
from src.external.parsers.archive import ZipArchiveParser  # noqa: E402
from src.external.parsers.tar_archive import TarArchiveParser  # noqa: E402
from src.external.sandbox.yara_x_runner import YaraXSandboxRunner  # noqa: E402
from tests.fixtures.factories import make_tenant_context  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}", flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def _build_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _build_tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_evidence(sha256: str) -> Evidence:
    return Evidence(
        metadata=EvidenceMetadata(
            original_filename="poc-e3.zip",
            content_type="application/zip",
            size_bytes=1024,
            uploader_user_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            org_alias="poc-e3-org",
        ),
        sha256=sha256,
    )


async def _bytes_stream(data: bytes):
    yield data


_RULE_TEXT = """\
rule finds_evil_marker {
    meta:
        author = "kronos-e3-poc"
    strings:
        $marker = "EVIL_MARKER_STRING"
    condition:
        $marker
}
"""

_BROKEN_RULE_TEXT = "this is not valid yara-x syntax {{{"


async def main() -> int:
    log("=" * 78)
    log("PoC: YARA scanning in the recursion path -> StructuredArtifact (roadmap E3)")
    log("=" * 78)

    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    await PostgresArtifactRepository.create_tables(engine)
    repository = PostgresArtifactRepository(engine)

    rules_dir = Path(tempfile.mkdtemp(prefix="kronos_poc_e3_rules_"))
    (rules_dir / "evil.yar").write_text(_RULE_TEXT)
    rule_provider = DirectoryYaraRuleProvider(rules_dir)
    yara_runner = YaraXSandboxRunner()

    try:
        # -------------------------------------------------------------
        # Scenario (a): real zip, real match, real nested-tar recursion
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (a): real zip container, real YARA-X match + nested tar recursion")
        log("=" * 78)

        registry = ParserRegistry()
        # Both parsers registered WITH the same real yara_runner/rule_provider
        # -- exactly the real src/external/dependencies.py::get_parser_registry()
        # wiring pattern. This matters: when ZipArchiveParser recurses into a
        # nested tar member, it resolves the nested parser via
        # self._registry.get_parser(...), i.e. the REGISTRY's own registered
        # instance, not whatever instance extract_artifacts() was called on
        # directly -- so both registered instances must share the same real
        # collaborators for recursive scanning to actually work end to end.
        registry.register(
            ZipArchiveParser(registry, yara_runner=yara_runner, yara_rule_provider=rule_provider)
        )
        registry.register(
            TarArchiveParser(registry, yara_runner=yara_runner, yara_rule_provider=rule_provider)
        )

        inner_tar = _build_tar({"nested_evil.bin": b"prefix-EVIL_MARKER_STRING-suffix"})
        zip_bytes = _build_zip(
            {
                "benign.txt": b"nothing interesting here at all",
                "evil.bin": b"xxxxEVIL_MARKER_STRINGxxxx",
                "nested.tar": inner_tar,
            }
        )
        evidence_sha256 = hashlib.sha256(zip_bytes).hexdigest()
        evidence = _make_evidence(evidence_sha256)
        tenant = make_tenant_context(org_id=evidence.metadata.org_id)

        parser = registry.get_parser("bundle.zip", "application/zip", zip_bytes[:8192])
        assert isinstance(parser, ZipArchiveParser)
        artifacts = [
            a async for a in parser.extract_artifacts(_bytes_stream(zip_bytes), evidence, tenant)
        ]
        log(f"extract_artifacts() yielded {len(artifacts)} real StructuredArtifact(s)")
        for a in artifacts:
            log(
                f"  kind={a.kind} source_path={a.kronos.source_path} "
                f"rule={a.content['rule_identifier']} "
                f"matched_strings={a.content['matched_strings']}"
            )

        # 3 real matches: evil.bin; nested.tar itself (its own raw bytes,
        # which embed the inner tar member's content verbatim, so the outer
        # container-as-a-blob genuinely does contain the marker too -- tar
        # has no compression, member content is stored byte-for-byte); and
        # nested.tar/nested_evil.bin (the correctly-recursed inner member).
        # Scanning the outer member's own raw bytes AND recursing into it is
        # intentional, not double-counting a bug: a real malicious payload
        # appended outside a container's recognized structure (e.g. after
        # the tar's own EOF padding) would only ever be caught by the
        # "also scan the raw member" pass, never by recursion alone.
        check(
            "exactly 3 real matches (evil.bin, nested.tar itself, and its recursed inner member)",
            len(artifacts) == 3,
        )
        source_paths = sorted(a.kronos.source_path for a in artifacts)
        check(
            "real source_paths are evil.bin + nested.tar + its correctly-nested inner member",
            source_paths == ["evil.bin", "nested.tar", "nested.tar/nested_evil.bin"],
        )

        for a in artifacts:
            await repository.save(a)

        # Independent verification: raw SQL against the real structured_artifacts
        # table, not the repository's own round trip.
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    sa_text(
                        "SELECT source_path, container_sha256, content, org_id "
                        "FROM structured_artifacts WHERE evidence_id = :eid ORDER BY source_path"
                    ),
                    {"eid": str(evidence.evidence_id)},
                )
            ).all()
        log(f"\nreal Postgres structured_artifacts rows for this evidence_id: {len(rows)}")
        for row in rows:
            log(
                f"  source_path={row.source_path} container_sha256={row.container_sha256[:16]}... "
                f"org_id={row.org_id}"
            )

        check("real Postgres has exactly 3 rows for this evidence_id", len(rows) == 3)
        check(
            "every real row's container_sha256 matches the real top-level evidence sha256",
            all(row.container_sha256 == evidence_sha256 for row in rows),
        )
        check(
            "every real row's org_id matches the real tenant org_id (never from payload)",
            all(str(row.org_id) == str(evidence.metadata.org_id) for row in rows),
        )

        evil_bin_row = next(r for r in rows if r.source_path == "evil.bin")
        matched = evil_bin_row.content["matched_strings"][0]
        expected_offset = b"xxxxEVIL_MARKER_STRINGxxxx".index(b"EVIL_MARKER_STRING")
        check(
            f"real byte offset for evil.bin's match is correct (expected {expected_offset})",
            matched["offset"] == expected_offset,
        )
        check(
            "real matched length equals len('EVIL_MARKER_STRING')",
            matched["length"] == len("EVIL_MARKER_STRING"),
        )

        nested_row = next(r for r in rows if r.source_path == "nested.tar/nested_evil.bin")
        check(
            "nested-container member's source_path is correctly prefixed with the outer member path",
            nested_row.source_path == "nested.tar/nested_evil.bin",
        )

        # -------------------------------------------------------------
        # Scenario (b): malformed ruleset -> clean abort, no crash
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (b): malformed ruleset -- clean compile-error abort, no crash")
        log("=" * 78)

        broken_rules_dir = Path(tempfile.mkdtemp(prefix="kronos_poc_e3_broken_rules_"))
        (broken_rules_dir / "broken.yar").write_text(_BROKEN_RULE_TEXT)
        broken_provider = DirectoryYaraRuleProvider(broken_rules_dir)
        broken_parser = ZipArchiveParser(
            registry, yara_runner=yara_runner, yara_rule_provider=broken_provider
        )
        broken_evidence = _make_evidence(hashlib.sha256(zip_bytes).hexdigest())
        broken_artifacts = [
            a
            async for a in broken_parser.extract_artifacts(
                _bytes_stream(zip_bytes), broken_evidence, tenant
            )
        ]
        check(
            "malformed ruleset produces zero artifacts, no exception raised", broken_artifacts == []
        )

        # parse() must be completely unaffected by extract_artifacts()'s own
        # (broken-ruleset) troubles for the very same evidence.
        parse_records = [
            r async for r in broken_parser.parse(_bytes_stream(zip_bytes), broken_evidence, tenant)
        ]
        check(
            "parse()'s own TimelineRecord output is unaffected by a broken YARA ruleset",
            parse_records == [],
        )  # no member here has a registered TimelineRecord parser -- expected

        # -------------------------------------------------------------
        # Scenario (c): real measured cost -- sanity-check the E3
        # implementation's own docstring claim, not blindly trust it.
        # -------------------------------------------------------------
        log("\n" + "=" * 78)
        log("SCENARIO (c): real measured subprocess-launch/compile/scan cost")
        log("=" * 78)

        import subprocess

        t0 = time.monotonic()
        subprocess.run([sys.executable, "-c", "pass"], check=True)
        cold_launch_ms = (time.monotonic() - t0) * 1000
        log(f"cold `python3 -c pass` subprocess launch: {cold_launch_ms:.1f}ms")

        t0 = time.monotonic()
        result = await yara_runner.run(_RULE_TEXT, b"xxxxEVIL_MARKER_STRINGxxxx")
        real_runner_call_ms = (time.monotonic() - t0) * 1000
        log(
            f"real end-to-end YaraXSandboxRunner.run() (subprocess launch + compile + scan): "
            f"{real_runner_call_ms:.1f}ms"
        )
        check(
            "a real end-to-end scan completes well within a HEAVY Celery task's budget "
            f"(measured {real_runner_call_ms:.1f}ms per member)",
            real_runner_call_ms < 5000,
        )
        check(
            "YaraXSandboxRunner.run() actually returned the real match in this timing run",
            result.matched,
        )

    finally:
        await engine.dispose()

    log("\n" + "=" * 78)
    failed = [label for label, ok in CHECKS if not ok]
    if failed:
        log(f"PoC FAILED -- {len(failed)}/{len(CHECKS)} checks failed:")
        for label in failed:
            log(f"  - {label}")
        return 1
    log(f"PoC PASSED -- all {len(CHECKS)} checks passed against real Postgres + real YARA-X.")
    log("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
