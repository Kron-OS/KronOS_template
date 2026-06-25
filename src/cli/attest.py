"""kronos-attest: offline forensic audit log verification CLI.

Usage:
    python -m src.cli.attest verify --audit-log export.json --event-id <uuid>
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

import click


def _canonical_json(ev: dict[str, Any]) -> bytes:
    """Reproduce the same canonical JSON used by AuditLogService."""
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


_GENESIS_HASH = hashlib.sha256(b"kronos-audit-genesis").hexdigest()


def _compute_row_hash(prev_hash: str, ev: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(_canonical_json(ev))
    return digest.hexdigest()


def _build_merkle_root(events: list[dict[str, Any]]) -> str:
    if not events:
        return hashlib.sha256(b"empty").hexdigest()
    sorted_events = sorted(events, key=lambda e: e.get("sequence_number", 0))
    layer: list[bytes] = [
        hashlib.sha256((e.get("row_hash") or "").encode()).digest() for e in sorted_events
    ]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            next_layer.append(hashlib.sha256(layer[i] + layer[i + 1]).digest())
        layer = next_layer
    return layer[0].hex()


@click.group()
def cli() -> None:
    """KronOS forensic attestation CLI — offline audit log verification."""


@cli.command()
@click.option("--audit-log", "audit_log_path", required=True, type=click.Path(exists=True), help="JSON audit log export file")
@click.option("--event-id", required=True, help="UUID of the event to verify")
def verify(audit_log_path: str, event_id: str) -> None:
    """Verify hash chain integrity and locate a specific event.

    Exits with code 0 on success, 1 on chain break or missing event.
    """
    with open(audit_log_path) as f:
        events_data: list[dict[str, Any]] = json.load(f)

    sorted_events = sorted(events_data, key=lambda e: e.get("sequence_number", 0))

    prev_hash = _GENESIS_HASH
    chain_ok = True
    target_event: dict[str, Any] | None = None

    for ev in sorted_events:
        expected = _compute_row_hash(ev.get("prev_row_hash") or prev_hash, ev)
        stored = ev.get("row_hash", "")
        if stored != expected:
            click.echo(
                f"CHAIN BROKEN at seq={ev.get('sequence_number')} event_id={ev.get('event_id')}",
                err=True,
            )
            chain_ok = False
        if ev.get("event_id") == event_id:
            target_event = ev
        prev_hash = stored or expected

    if chain_ok:
        click.echo("Chain intact")
    else:
        click.echo("Chain integrity FAILED", err=True)

    if target_event:
        click.echo(
            f"Event {event_id}: {target_event.get('event_type')} at {target_event.get('occurred_at')}"
        )
    else:
        click.echo(f"Event {event_id} not found in audit log", err=True)

    if not chain_ok or target_event is None:
        sys.exit(1)


@cli.command()
@click.option("--audit-log", "audit_log_path", required=True, type=click.Path(exists=True), help="JSON audit log export file")
def merkle_root(audit_log_path: str) -> None:
    """Compute and print the Merkle root of the audit log."""
    with open(audit_log_path) as f:
        events_data: list[dict[str, Any]] = json.load(f)
    root = _build_merkle_root(events_data)
    click.echo(root)


if __name__ == "__main__":
    cli()
