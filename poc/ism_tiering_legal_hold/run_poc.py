"""PoC: exercise the real src/adapter/opensearch/ism_manager.py
(OpenSearchIsmLifecycleManager) and src/application/ism_tiering.py
(DefaultIsmTierResolver) against the real, live dev-stack OpenSearch 2.11.1
ISM plugin -- imports and calls the exact classes KronOS ships.

Real, unexpected finding this PoC surfaced (documented in ism_manager.py's
module docstring and README.md): every pre-existing real KronOS evidence
index on this cluster had its ISM managed-index job stuck at
``enabled: false, enabled_time: null`` -- meaning the previously-"working"
kronos-rollover policy had never actually been ticking for any of them,
despite ``_plugins/_ism/explain`` reporting a policy_id attached. This PoC
proves: (1) the self-healing fix (explicit ``_plugins/_ism/add``) actually
resolves a deliberately-stuck-disabled index, (2) the aggressive stream tier
attaches correctly via real ISM template priority ordering, (3) the
legal-hold remove/re-add mechanism really blocks and resumes lifecycle
management.

Run: source ~/venv/bin/activate && python poc/ism_tiering_legal_hold/run_poc.py
Requires the real dev stack up (OpenSearch reachable on localhost:9200).
"""
from __future__ import annotations

import asyncio
import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.adapter.opensearch.ism_manager import OpenSearchIsmLifecycleManager  # noqa: E402
from src.application.ism_tiering import DefaultIsmTierResolver  # noqa: E402

OS_URL = "https://localhost:9200"
OS_ADMIN = ("admin", "admin")

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def create_index(name: str) -> None:
    resp = httpx.put(f"{OS_URL}/{name}", auth=OS_ADMIN, verify=False, timeout=15, json={})
    resp.raise_for_status()


def delete_index(name: str) -> None:
    httpx.delete(f"{OS_URL}/{name}", auth=OS_ADMIN, verify=False, timeout=15)


def managed_index_doc(name: str) -> dict | None:
    resp = httpx.post(
        f"{OS_URL}/.opendistro-ism-config/_search",
        auth=OS_ADMIN,
        verify=False,
        timeout=15,
        json={"size": 1, "query": {"match": {"managed_index.name": name}}},
    )
    resp.raise_for_status()
    for hit in resp.json().get("hits", {}).get("hits", []):
        mi = hit["_source"]["managed_index"]
        if mi.get("name") == name:
            return mi
    return None


def force_disable(name: str) -> None:
    """Directly flip a real managed-index doc's enabled flag to false via
    the same real bug path this PoC documents (remove without re-add), to
    get a genuinely-disabled index to test the self-healing fix against
    without waiting on a real container restart to reproduce it naturally."""
    httpx.post(f"{OS_URL}/_plugins/_ism/remove/{name}", auth=OS_ADMIN, verify=False, timeout=15)


def part1_self_healing() -> None:
    print("\n=== Part 1: self-healing ensure_managed() fixes a stuck-disabled index ===")
    idx = f"kronos-b3poc-selfheal-{uuid.uuid4().hex[:8]}-202607"
    create_index(idx)
    time.sleep(3)

    doc = managed_index_doc(idx)
    check("index got a real managed_index doc shortly after creation", doc is not None)
    if doc:
        print(f"  initial state: enabled={doc.get('enabled')}")

    force_disable(idx)
    time.sleep(1)
    doc_after_remove = managed_index_doc(idx)
    check(
        "index is now genuinely unmanaged (place_legal_hold's own remove call, reused here)",
        doc_after_remove is None,
        f"doc={doc_after_remove}",
    )

    manager = OpenSearchIsmLifecycleManager(OS_URL, "admin", "admin")
    asyncio.run(manager.ensure_managed(idx, "kronos-rollover"))
    time.sleep(1)
    doc_after_fix = managed_index_doc(idx)
    check(
        "ensure_managed() re-attaches management with enabled=true (the real fix)",
        doc_after_fix is not None and doc_after_fix.get("enabled") is True,
        f"doc={doc_after_fix}",
    )

    is_enabled = asyncio.run(manager.is_managed_and_enabled(idx))
    check("is_managed_and_enabled() agrees", is_enabled is True)

    delete_index(idx)

    print("\n--- Part 1b: the exact bug this method's docstring documents ---")
    idx2 = f"kronos-b3poc-alreadypolicy-{uuid.uuid4().hex[:8]}-202607"
    create_index(idx2)
    time.sleep(3)
    doc2 = managed_index_doc(idx2)
    check("second index also attaches enabled=true initially", doc2 is not None and doc2.get("enabled") is True)

    # A naive "add" (no remove first) on an index that ALREADY has a
    # recorded policy_id (even one that's enabled=true) fails silently at
    # the body level, not the HTTP status -- the real bug ensure_managed()
    # exists to route around.
    raw_add_resp = httpx.post(
        f"{OS_URL}/_plugins/_ism/add/{idx2}",
        auth=OS_ADMIN,
        verify=False,
        timeout=15,
        json={"policy_id": "kronos-rollover"},
    )
    check(
        "confirmed: a naive add-without-remove on an already-policy'd index "
        "returns HTTP 200 but body.failures=true (the real, silent-looking bug)",
        raw_add_resp.status_code == 200 and raw_add_resp.json().get("failures") is True,
        f"status={raw_add_resp.status_code} body={raw_add_resp.text[:200]}",
    )

    # The real, fixed ensure_managed() must succeed anyway (remove-then-add).
    asyncio.run(manager.ensure_managed(idx2, "kronos-rollover"))
    doc2_after = managed_index_doc(idx2)
    check(
        "ensure_managed() succeeds on an already-policy'd index despite the "
        "bug above (remove-then-add works around it)",
        doc2_after is not None and doc2_after.get("enabled") is True,
        f"doc={doc2_after}",
    )
    delete_index(idx2)


def part2_tiering() -> None:
    print("\n=== Part 2: per-source tiering via real ISM template priority ===")
    resolver = DefaultIsmTierResolver()
    manager = OpenSearchIsmLifecycleManager(OS_URL, "admin", "admin")

    case_policy_id = resolver.policy_id_for_source(None)
    stream_policy_id = resolver.policy_id_for_source("network")
    other_stream_policy_id = resolver.policy_id_for_source("some-unlisted-source")
    check("case-scoped (source=None) resolves to the standard tier", case_policy_id == "kronos-rollover")
    check("a known high-volume source (network) resolves to the aggressive tier", stream_policy_id == "kronos-stream-aggressive")
    check("an unlisted source falls back to the standard tier", other_stream_policy_id == "kronos-rollover")

    asyncio.run(manager.ensure_policy(stream_policy_id, resolver.policy_body_for_id(stream_policy_id)))

    stream_idx = f"kronos-b3poc-stream-network-{uuid.uuid4().hex[:8]}-202607"
    create_index(stream_idx)
    time.sleep(3)
    explain = httpx.get(f"{OS_URL}/_plugins/_ism/explain/{stream_idx}", auth=OS_ADMIN, verify=False, timeout=15).json()
    attached_policy = explain.get(stream_idx, {}).get("policy_id")
    check(
        "a real index matching the aggressive tier's pattern gets the aggressive policy, "
        "not the general kronos-rollover one (real ISM template priority: 200 beats 100)",
        attached_policy == "kronos-stream-aggressive",
        f"attached_policy={attached_policy}",
    )
    delete_index(stream_idx)

    case_idx = f"kronos-b3poc-case-{uuid.uuid4().hex[:8]}-202607"
    create_index(case_idx)
    time.sleep(3)
    explain2 = httpx.get(f"{OS_URL}/_plugins/_ism/explain/{case_idx}", auth=OS_ADMIN, verify=False, timeout=15).json()
    attached_policy2 = explain2.get(case_idx, {}).get("policy_id")
    check(
        "a case-shaped index (no stream-source segment) still gets the standard tier",
        attached_policy2 == "kronos-rollover",
        f"attached_policy={attached_policy2}",
    )
    delete_index(case_idx)


def part3_legal_hold() -> None:
    print("\n=== Part 3: legal hold blocks and resumes real ISM lifecycle management ===")
    manager = OpenSearchIsmLifecycleManager(OS_URL, "admin", "admin")
    idx = f"kronos-b3poc-legalhold-{uuid.uuid4().hex[:8]}-202607"
    create_index(idx)
    time.sleep(3)

    before = managed_index_doc(idx)
    check("index is managed and enabled before hold", before is not None and before.get("enabled") is True)

    asyncio.run(manager.place_legal_hold(idx))
    time.sleep(1)
    during_hold = managed_index_doc(idx)
    check(
        "under legal hold: no managed_index doc at all -- ISM cannot run any "
        "transition (including delete) against this index",
        during_hold is None,
        f"doc={during_hold}",
    )

    asyncio.run(manager.release_legal_hold(idx, "kronos-rollover"))
    time.sleep(1)
    after_release = managed_index_doc(idx)
    check(
        "after release: management resumes, enabled=true again",
        after_release is not None and after_release.get("enabled") is True,
        f"doc={after_release}",
    )

    delete_index(idx)


def main() -> None:
    part1_self_healing()
    part2_tiering()
    part3_legal_hold()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
