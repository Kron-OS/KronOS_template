"""PoC: VolatilityModule dual-emit (StructuredArtifact + TimelineRecord)
against the REAL cridex.vmem sample, one real volatility3 subprocess run,
real OpenSearch ingestion and query-back.

Per CLAUDE.md Section F: calls the actual, unmodified
`src.external.parsers.volatility.VolatilityModule.parse()`/
`.extract_artifacts()` methods -- not a reimplementation -- against a real
volatility3==2.28.0 subprocess (via the scratch venv already set up for
poc/volatility_memory_module/) and a real, live dev-stack OpenSearch
2.11.1 index.

Run: ~/venv/bin/python3 poc/volatility_timeline_dual_emit/run_poc.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

SCRATCH_VENV_BIN = "/home/reca/scratch/kronos-poc-volatility/venv/bin"
SCRATCH_PYTHON = f"{SCRATCH_VENV_BIN}/python3"
SAMPLE_VMEM = "/home/reca/scratch/kronos-poc-volatility/cridex.vmem"
WORKER_SCRIPT = REPO_ROOT / "docker" / "volatility" / "kronos-volatility-worker.py"

# The worker script locates the real `vol` CLI via shutil.which("vol") --
# a real subprocess.run([python_bin, worker_script, ...]) child inherits
# THIS process's PATH, which doesn't include the scratch venv's own bin/
# (that venv is never "activated", just pointed at directly). Prepending
# it here is the PoC-only equivalent of activating that venv.
os.environ["PATH"] = f"{SCRATCH_VENV_BIN}:{os.environ.get('PATH', '')}"

checks: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    checks.append((name, condition, detail))
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))


class _FakeSettings:
    """Same minimal stand-in tests/unit/parsers/test_volatility.py uses --
    VolatilityModule only reads volatility_worker_path off Settings; the
    real value is overridden below regardless via RealScratchVenvLauncher.
    """

    volatility_worker_path: str | None = None


async def main() -> None:
    from src.domain.evidence import Evidence, EvidenceMetadata
    from src.domain.timeline import EvidenceProvenance
    from src.domain.user import TenantContext
    from src.domain.user import Role as KronosRole
    from src.external.parsers.volatility import VolatilityModule
    from src.external.sandbox.volatility_launcher import VolatilityLauncher

    if not Path(SAMPLE_VMEM).exists():
        print(f"Real sample not found at {SAMPLE_VMEM} -- see poc/volatility_memory_module/README.md")
        sys.exit(1)

    class RealScratchVenvLauncher(VolatilityLauncher):
        """Same real VolatilityLauncher, just pointed at the scratch venv's
        real volatility3==2.28.0 install instead of this process's own
        interpreter (which doesn't have volatility3 installed) -- the
        exact same class, only python_bin/worker_path are fixed."""

        def __init__(self, **kwargs: object) -> None:
            kwargs.pop("worker_path", None)
            super().__init__(
                worker_path=WORKER_SCRIPT,
                python_bin=SCRATCH_PYTHON,
                timeout_seconds=kwargs.get("timeout_seconds", 300),  # type: ignore[arg-type]
            )

    org_id = uuid.uuid4()
    case_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    evidence = Evidence(
        evidence_id=evidence_id,
        metadata=EvidenceMetadata(
            original_filename="cridex.vmem",
            content_type="application/octet-stream",
            size_bytes=Path(SAMPLE_VMEM).stat().st_size,
            uploader_user_id=uuid.uuid4(),
            case_id=case_id,
            org_id=org_id,
            org_alias="poc-volatility-dual-emit",
        ),
        sha256="02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d",
    )
    tenant = TenantContext(
        org_id=org_id,
        org_alias="poc-volatility-dual-emit",
        user_id=uuid.uuid4(),
        username="poc",
        roles=frozenset({KronosRole.ORG_ADMIN}),
        correlation_id=str(uuid.uuid4()),
        acr="aal2",
    )

    async def stream_sample():
        with open(SAMPLE_VMEM, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                yield chunk

    parser = VolatilityModule()

    with (
        patch("src.config.Settings", _FakeSettings),
        patch(
            "src.external.sandbox.volatility_launcher.VolatilityLauncher",
            RealScratchVenvLauncher,
        ),
    ):
        print("--- Real run 1: parse() alone (real volatility3 subprocess) ---")
        t0 = time.monotonic()
        records = [r async for r in parser.parse(stream_sample(), evidence, tenant)]
        parse_elapsed = time.monotonic() - t0
        print(f"parse() elapsed: {parse_elapsed:.2f}s, {len(records)} TimelineRecord(s)")

        check("parse() yields at least one real TimelineRecord", len(records) > 0, f"{len(records)} records")
        if records:
            r0 = records[0]
            check("record has a real process_pid", r0.process_pid is not None, str(r0.process_pid))
            check("record has a real process_name", r0.process_name is not None, str(r0.process_name))
            check("event_category is ['process']", r0.event_category == ["process"])
            check("event_type is ['start']", r0.event_type == ["start"])
            check(
                "extra carries volatility.plugin",
                "volatility.plugin" in r0.extra,
                str(r0.extra.get("volatility.plugin")),
            )
            check(
                "kronos.evidence_id matches this evidence",
                isinstance(r0.kronos, EvidenceProvenance) and r0.kronos.evidence_id == evidence_id,
            )
            # Real cridex.vmem finding (poc/volatility_memory_module/): pstree
            # returns 0 rows, psscan fallback recovers the real census -- so
            # every dual-emitted record here should be attributed to the
            # fallback plugin, not the (empty) primary.
            check(
                "records are attributed to the real psscan fallback plugin",
                all(r.extra.get("volatility.plugin") == "windows.psscan" for r in records),
            )

        print("\n--- Real run 2: extract_artifacts() reusing the cached scan (should NOT re-run volatility3) ---")
        t1 = time.monotonic()
        artifacts = [a async for a in parser.extract_artifacts(stream_sample(), evidence, tenant)]
        extract_elapsed = time.monotonic() - t1
        print(f"extract_artifacts() elapsed: {extract_elapsed:.2f}s, {len(artifacts)} StructuredArtifact(s)")

        check("extract_artifacts() yields real StructuredArtifacts", len(artifacts) > 0, f"{len(artifacts)} artifacts")
        check(
            "extract_artifacts() reused the cache (did not re-run the ~subprocess-cost scan)",
            extract_elapsed < parse_elapsed * 0.5,
            f"parse={parse_elapsed:.2f}s extract={extract_elapsed:.2f}s",
        )
        psscan_artifacts = [a for a in artifacts if a.kind == "volatility.psscan"]
        check("a real volatility.psscan artifact was emitted", len(psscan_artifacts) > 0)
        if psscan_artifacts:
            total_artifact_rows = sum(len(a.content["rows"]) for a in psscan_artifacts)
            check(
                "TimelineRecord count <= total psscan artifact rows (only rows with real CreateTime emit)",
                len(records) <= total_artifact_rows,
                f"records={len(records)} artifact_rows={total_artifact_rows}",
            )

        print("\n--- Real run 3: extract_artifacts() called standalone (no parse() first) still works ---")
        t2 = time.monotonic()
        standalone_artifacts = [
            a async for a in parser.extract_artifacts(stream_sample(), evidence, tenant)
        ]
        standalone_elapsed = time.monotonic() - t2
        print(f"standalone extract_artifacts() elapsed: {standalone_elapsed:.2f}s")
        check(
            "standalone extract_artifacts() (no prior parse()) re-runs the real scan",
            standalone_elapsed > extract_elapsed * 2,
            f"cached={extract_elapsed:.2f}s standalone={standalone_elapsed:.2f}s",
        )
        check(
            "standalone extract_artifacts() still produces the same real data",
            len(standalone_artifacts) == len(artifacts),
        )

    # ------------------------------------------------------------------
    # Real OpenSearch ingestion + query-back
    # ------------------------------------------------------------------
    print("\n--- Real OpenSearch ingestion of the dual-emitted TimelineRecords ---")
    from src.application.timeline_normalization import ECSNormalizer, build_index_name
    from src.adapter.opensearch.client import OpenSearchClient

    os_client = OpenSearchClient(
        hosts=[{"host": "localhost", "port": 9200}],
        http_auth=("admin", "admin"),
        use_ssl=True,
        verify_certs=False,
    )
    await os_client.ensure_index_template()

    normalizer = ECSNormalizer()
    index_name = None
    doc_ids: list[str] = []
    try:
        docs: list[tuple[str, str, dict]] = []
        for i, record in enumerate(records):
            doc = normalizer.to_document(record)
            index_name = build_index_name("poc-volatility-dual-emit", str(case_id), record.timestamp)
            doc_id = f"poc-vol-dual-emit-{i}"
            doc_ids.append(doc_id)
            docs.append((index_name, doc_id, doc))
        indexed_count = await os_client.bulk_index(docs)

        check(
            "at least one real document indexed",
            index_name is not None and indexed_count > 0,
            f"indexed_count={indexed_count}",
        )

        if index_name is not None:
            await os_client._client.indices.refresh(index=index_name)  # noqa: SLF001 -- PoC only

            pid = records[0].process_pid
            resp = await os_client._client.search(  # noqa: SLF001 -- PoC only
                index=index_name,
                body={"query": {"term": {"process.pid": pid}}},
            )
            hits = resp["hits"]["total"]["value"]
            check(f"real term query on process.pid={pid} returns a hit", hits >= 1, f"{hits} hit(s)")

            resp2 = await os_client._client.search(  # noqa: SLF001 -- PoC only
                index=index_name,
                body={"query": {"term": {"event.category": "process"}}},
            )
            hits2 = resp2["hits"]["total"]["value"]
            check(
                "real term query on event.category='process' returns every dual-emitted record",
                hits2 == len(records),
                f"{hits2} hit(s), expected {len(records)}",
            )

            resp3 = await os_client._client.get(index=index_name, id=doc_ids[0])  # noqa: SLF001
            source = resp3["_source"]
            check(
                "indexed document's kronos.evidence_id round-trips correctly",
                source["kronos"]["evidence_id"] == str(evidence_id),
            )
            check(
                "indexed document carries a real volatility.plugin field (dotted extra -> nested)",
                "volatility" in source and source["volatility"].get("plugin") == "windows.psscan",
            )
    finally:
        if index_name is not None:
            try:
                for doc_id in doc_ids:
                    await os_client._client.delete(  # noqa: SLF001 -- PoC cleanup only
                        index=index_name, id=doc_id, ignore=[404]
                    )
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup warning: {exc}")
        await os_client.close()

    print("\n" + "=" * 70)
    total = len(checks)
    passed = sum(1 for _, ok, _ in checks if ok)
    print(f"RESULT: {passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
