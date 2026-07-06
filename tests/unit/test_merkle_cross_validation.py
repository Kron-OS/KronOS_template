"""Cross-validation between the two Merkle implementations (AUDIT-04).

``src.domain.merkle`` is the backend's canonical implementation.
``kronos_attest.verifier`` intentionally carries its own copy — it's the
standalone, independently-packaged offline auditor tool and must not depend
on the backend's import graph. This test is the guardrail that keeps the two
from silently drifting apart: both must produce identical roots and proofs
for identical inputs.
"""

from __future__ import annotations

import hashlib

from kronos_attest.verifier import build_merkle_root as attest_build_merkle_root
from kronos_attest.verifier import merkle_proof as attest_merkle_proof
from src.domain.merkle import build_merkle_root as domain_build_merkle_root
from src.domain.merkle import merkle_proof as domain_merkle_proof


def _hashes(n: int) -> list[str]:
    return [hashlib.sha256(f"event-{i}".encode()).hexdigest() for i in range(n)]


def test_roots_match_for_empty_and_various_sizes() -> None:
    for n in range(0, 10):
        hashes = _hashes(n)
        assert attest_build_merkle_root(hashes) == domain_build_merkle_root(
            hashes
        ), f"root mismatch at n={n}"


def test_roots_match_for_odd_and_even_sizes() -> None:
    for n in (1, 2, 3, 4, 5, 7, 8, 15, 16, 17):
        hashes = _hashes(n)
        assert attest_build_merkle_root(hashes) == domain_build_merkle_root(
            hashes
        ), f"root mismatch at n={n}"


def test_proof_steps_match_for_every_index() -> None:
    """Both implementations must derive identical (sibling_hash, position) proofs."""
    for n in (1, 2, 3, 4, 5, 6, 7, 8):
        hashes = _hashes(n)
        for i in range(n):
            attest_proof = attest_merkle_proof(hashes, i)
            domain_proof = domain_merkle_proof(hashes, i)
            assert attest_proof == domain_proof, f"proof mismatch at n={n} i={i}"


def test_different_inputs_produce_different_roots_in_both_implementations() -> None:
    a = attest_build_merkle_root(["x", "y"])
    b = attest_build_merkle_root(["x", "z"])
    assert a != b
    a2 = domain_build_merkle_root(["x", "y"])
    b2 = domain_build_merkle_root(["x", "z"])
    assert a2 != b2
    assert a == a2
    assert b == b2
