"""Hash-chain and Merkle-tree verifiers for offline audit log attestation.

This module deliberately does NOT import from ``src`` (the backend package):
kronos-attest is a standalone offline auditor tool, meant to be runnable by a
third party with only a JSON export + read-only credentials, independent of
the backend's dependency graph. Its Merkle implementation is therefore an
intentional, self-contained duplicate of ``src.domain.merkle`` — kept
identical by construction (RFC 6962-style domain separation, promotion of
unpaired nodes — AUDIT-04) and pinned by
``tests/unit/test_merkle_cross_validation.py``, which fails if the two ever
drift apart.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# Genesis hash: SHA-256("kronos-audit-genesis") — must match AuditLogService.
GENESIS_HASH = hashlib.sha256(b"kronos-audit-genesis").hexdigest()

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"
_EMPTY_ROOT = hashlib.sha256(b"empty").hexdigest()


def _canonical_json(ev: dict[str, Any]) -> bytes:
    """Reproduce the canonical JSON used by AuditLogService.hash_chain."""
    payload = {
        "event_id": ev.get("event_id", ""),
        "event_type": ev.get("event_type", ""),
        "actor_user_id": ev.get("actor_user_id"),
        "actor_username": ev.get("actor_username"),
        "org_id": ev.get("org_id"),
        "case_id": ev.get("case_id"),
        "evidence_id": ev.get("evidence_id"),
        "details": ev.get("details", {}),
        "occurred_at": ev.get("occurred_at", ""),
        "sequence_number": ev.get("sequence_number", 0),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_row_hash(prev_hash: str, ev: dict[str, Any]) -> str:
    """Recompute a row hash from previous hash and event dict."""
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(_canonical_json(ev))
    return digest.hexdigest()


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def build_merkle_root(row_hashes: list[str]) -> str:
    """Compute the Merkle root from a list of row_hash strings (sorted by sequence_number).

    RFC 6962-style domain separation (leaf/node hash prefixes) and promotion
    of an unpaired node to the next layer instead of duplicating it
    (AUDIT-04) — see the module docstring for why this must stay identical
    to ``src.domain.merkle.build_merkle_root``.
    """
    if not row_hashes:
        return _EMPTY_ROOT
    layer: list[bytes] = [_leaf_hash(h.encode()) for h in row_hashes]
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


def merkle_proof(row_hashes: list[str], index: int) -> list[tuple[str, str]]:
    """Return the (sibling_hash_hex, position) proof steps for row_hashes[index].

    ``position`` is ``"left"`` or ``"right"`` — the side the sibling sits on
    relative to the node being folded upward.  A promoted (unpaired) node at
    any layer contributes no proof step.  Position is carried explicitly
    (rather than inferred from index parity) because a promoted layer would
    otherwise desync a purely-parity-based walk in ``verify_proof`` — mirrors
    ``src.domain.merkle.merkle_proof`` exactly; kept in lockstep by
    ``tests/unit/test_merkle_cross_validation.py``.
    """
    if not row_hashes:
        return []
    proof: list[tuple[str, str]] = []
    layer: list[bytes] = [_leaf_hash(h.encode()) for h in row_hashes]
    idx = index
    while len(layer) > 1:
        next_layer: list[bytes] = []
        i = 0
        while i < len(layer):
            if i + 1 < len(layer):
                if i == idx:
                    proof.append((layer[i + 1].hex(), "right"))
                    idx = len(next_layer)
                elif i + 1 == idx:
                    proof.append((layer[i].hex(), "left"))
                    idx = len(next_layer)
                next_layer.append(_node_hash(layer[i], layer[i + 1]))
                i += 2
            else:
                if i == idx:
                    idx = len(next_layer)
                next_layer.append(layer[i])
                i += 1
        layer = next_layer
    return proof


@dataclass
class ChainBreak:
    """Describes a single hash chain integrity failure."""

    sequence_number: int
    event_id: str
    stored_hash: str
    computed_hash: str


@dataclass
class ChainVerificationResult:
    """Result of verifying the full hash chain of an audit log export."""

    valid: bool
    event_count: int
    breaks: list[ChainBreak] = field(default_factory=list)
    merkle_root: str = ""


class ChainVerifier:
    """Verifies the SHA-256 hash chain of a KronOS audit log export (JSON format)."""

    def verify(self, events: list[dict[str, Any]]) -> ChainVerificationResult:
        """Verify hash chain integrity of an exported audit log.

        Events should be sorted by sequence_number (ascending).
        Returns a ChainVerificationResult with any detected breaks.

        SECURITY: We use the running tracked prev_hash, NOT the stored
        prev_row_hash field.  Using the stored field allows an attacker to
        forge a consistent chain by adjusting prev_row_hash on each event,
        bypassing the tamper-detection guarantee.

        For the Merkle root we always use the *stored* row_hash (even if
        tampered), so the computed root matches what the server anchored at the
        time of the anchor operation.  A mismatch between the computed root and
        the stored anchor root therefore indicates tampering.
        """
        sorted_events = sorted(events, key=lambda e: e.get("sequence_number", 0))
        prev_hash = GENESIS_HASH
        breaks: list[ChainBreak] = []
        row_hashes: list[str] = []

        for ev in sorted_events:
            # Recompute using the running tracked hash — not the stored field.
            computed = compute_row_hash(prev_hash, ev)
            stored = ev.get("row_hash", "")
            # Always include the stored hash in the Merkle layer so we can
            # compare against the server-anchored root.
            row_hashes.append(stored if stored else computed)

            if stored and stored != computed:
                breaks.append(
                    ChainBreak(
                        sequence_number=ev.get("sequence_number", -1),
                        event_id=ev.get("event_id", ""),
                        stored_hash=stored,
                        computed_hash=computed,
                    )
                )
            # Advance the running hash: use stored if valid, computed if missing.
            prev_hash = stored if stored else computed

        root = build_merkle_root(row_hashes)
        return ChainVerificationResult(
            valid=len(breaks) == 0,
            event_count=len(sorted_events),
            breaks=breaks,
            merkle_root=root,
        )


class MerkleVerifier:
    """Verifies Merkle inclusion proofs for individual audit events."""

    def verify_proof(
        self,
        leaf_hash: str,
        proof: list[tuple[str, str]],
        root_hash: str,
        index: int | None = None,  # noqa: ARG002 — kept for call-site compatibility
    ) -> bool:
        """Verify that leaf_hash is included in the Merkle tree with the given root.

        ``proof`` is the list of (sibling_hash_hex, position) steps from leaf
        to root, as returned by ``merkle_proof``.  ``index`` is accepted but
        unused: position is now carried explicitly in each proof step rather
        than inferred from index parity, which is what makes verification
        correct even when the path crosses a promoted (unpaired) node.
        """
        current = _leaf_hash(leaf_hash.encode())
        for sibling_hex, position in proof:
            sibling = bytes.fromhex(sibling_hex)
            current = (
                _node_hash(current, sibling)
                if position == "right"
                else _node_hash(sibling, current)
            )
        return current.hex() == root_hash

    def compute_root_from_events(self, events: list[dict[str, Any]]) -> str:
        """Compute Merkle root from a list of event dicts (uses row_hash field)."""
        sorted_events = sorted(events, key=lambda e: e.get("sequence_number", 0))
        row_hashes = [e.get("row_hash") or compute_row_hash(GENESIS_HASH, e) for e in sorted_events]
        return build_merkle_root(row_hashes)
