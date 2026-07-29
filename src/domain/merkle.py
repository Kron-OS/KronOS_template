"""Canonical Merkle-tree hashing for the audit-log hash chain.

RFC 6962-style domain separation: leaf hashes are prefixed with ``0x00`` and
internal-node hashes with ``0x01``.  Without this separation an attacker can
present an internal node's pre-image as if it were a leaf (or vice versa) and
forge an inclusion proof — the CVE-2012-2459 class of second-preimage attack
against naive Merkle trees.

An unpaired node at any layer is *promoted* unchanged to the next layer
rather than duplicated.  Duplicating the last node when a layer is odd makes
a balanced tree with a repeated adjacent pair indistinguishable from an
unbalanced tree that legitimately carries one node forward — promotion
removes that ambiguity.

This is the single source of truth for Merkle root/proof computation inside
the backend (``src/``).  ``kronos_attest`` — the standalone, independently
packaged offline verifier — intentionally carries its own copy (it must
verify audit exports without importing the backend's dependency graph); a
cross-validation test (``tests/unit/test_merkle_cross_validation.py``)
asserts both implementations produce identical roots for identical inputs.
"""

from __future__ import annotations

import hashlib

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

# Empty-tree sentinel — distinguishable from any real leaf/node hash since it
# is neither domain-separated (deliberately: there is nothing to separate).
EMPTY_ROOT = hashlib.sha256(b"empty").hexdigest()


def leaf_hash(data: bytes) -> bytes:
    """Domain-separated hash of a single leaf's raw bytes."""
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    """Domain-separated hash combining two child nodes."""
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def build_merkle_root(leaves: list[str]) -> str:
    """Build the hex Merkle root over a list of row-hash hex strings.

    Each entry in *leaves* is hashed as a domain-separated leaf; internal
    nodes use a different domain-separated prefix.  An unpaired node at any
    layer is promoted unchanged to the next layer instead of being
    duplicated.
    """
    if not leaves:
        return EMPTY_ROOT

    layer: list[bytes] = [leaf_hash(h.encode()) for h in leaves]
    while len(layer) > 1:
        next_layer: list[bytes] = []
        i = 0
        while i + 1 < len(layer):
            next_layer.append(_node_hash(layer[i], layer[i + 1]))
            i += 2
        if i < len(layer):
            next_layer.append(layer[i])  # promote unpaired node, don't duplicate
        layer = next_layer
    return layer[0].hex()


def merkle_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Return the inclusion proof for ``leaves[index]`` as (sibling_hex, position) steps.

    ``position`` is ``"left"`` or ``"right"``, naming which side the sibling
    sits on relative to the node being folded upward.  A promoted (unpaired)
    node contributes no proof step at that layer.
    """
    if not leaves:
        return []

    layer: list[bytes] = [leaf_hash(h.encode()) for h in leaves]
    idx = index
    proof: list[tuple[str, str]] = []

    while len(layer) > 1:
        next_layer: list[bytes] = []
        i = 0
        while i < len(layer):
            if i + 1 < len(layer):
                left, right = layer[i], layer[i + 1]
                if i == idx:
                    proof.append((right.hex(), "right"))
                    idx = len(next_layer)
                elif i + 1 == idx:
                    proof.append((left.hex(), "left"))
                    idx = len(next_layer)
                next_layer.append(_node_hash(left, right))
                i += 2
            else:
                if i == idx:
                    idx = len(next_layer)
                next_layer.append(layer[i])
                i += 1
        layer = next_layer

    return proof


def verify_proof(leaf: str, proof: list[tuple[str, str]], root_hash: str) -> bool:
    """Verify that *leaf* is included in the tree with the given root via *proof*."""
    current = leaf_hash(leaf.encode())
    for sibling_hex, position in proof:
        sibling = bytes.fromhex(sibling_hex)
        current = (
            _node_hash(current, sibling) if position == "right" else _node_hash(sibling, current)
        )
    return current.hex() == root_hash
