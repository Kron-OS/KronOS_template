"""kronos-attest CLI: offline forensic audit log verification and attestation."""

from __future__ import annotations

import json
import sys
from typing import Any

import click

from kronos_attest.report import AttestationReport
from kronos_attest.verifier import ChainVerifier, merkle_proof


@click.group()
def cli() -> None:
    """KronOS forensic attestation CLI — offline audit log verification."""


@cli.command()
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True),
    help="JSON audit log export file (list of event objects)",
)
@click.option("--event-id", required=True, help="UUID of the event to verify")
@click.option(
    "--tsa-cert",
    "tsa_cert_path",
    default=None,
    type=click.Path(exists=True),
    help="TSA CA certificate chain — if given, also verifies any daily "
    "Merkle anchor's RFC 3161 signature found in the log (AUDIT-07/08).",
)
def verify(audit_log_path: str, event_id: str, tsa_cert_path: str | None) -> None:
    """Verify hash chain integrity and locate a specific event.

    Exits with code 0 on success (chain intact + event found, and TSA
    anchors valid if --tsa-cert was given), code 1 otherwise.
    """
    events = _load(audit_log_path)
    result = ChainVerifier().verify(events)

    if result.valid:
        click.echo(f"Chain intact ({result.event_count} events, root={result.merkle_root[:16]}…)")
    else:
        click.echo(f"Chain BROKEN: {len(result.breaks)} break(s)", err=True)
        for b in result.breaks:
            click.echo(f"  seq={b.sequence_number} event={b.event_id}", err=True)

    target = next((e for e in events if e.get("event_id") == event_id), None)
    if target:
        click.echo(
            f"Event {event_id}: {target.get('event_type')} at {target.get('occurred_at')}"
        )
    else:
        click.echo(f"Event {event_id} not found", err=True)

    tsa_ok = True
    if tsa_cert_path is not None:
        tsa_ok = _verify_all_tsa_anchors(events, tsa_cert_path)

    if not result.valid or target is None or not tsa_ok:
        sys.exit(1)


def _verify_all_tsa_anchors(events: list[dict[str, Any]], tsa_cert_path: str) -> bool:
    """Verify every daily Merkle anchor's TSA signature found in the export.

    Prints one line per anchor day and returns False if any fail — used by
    ``verify --tsa-cert`` (AUDIT-07: the CLI never called the TSA verifier
    at all before this).
    """
    from kronos_attest.tsa import verify_merkle_anchor  # noqa: PLC0415

    all_ok = True
    for ev in events:
        if ev.get("event_type") != "audit.merkle_anchored":
            continue
        details = ev.get("details") or {}
        day = details.get("day", "unknown")
        root_hash = details.get("root_hash")
        tsa_token_hex = details.get("tsa_token")
        if not root_hash or not tsa_token_hex:
            click.echo(f"TSA anchor {day}: no token present (not TSA-anchored)", err=True)
            all_ok = False
            continue
        try:
            ok = verify_merkle_anchor(bytes.fromhex(tsa_token_hex), root_hash, tsa_cert_path)
        except Exception as exc:  # noqa: BLE001
            click.echo(f"TSA anchor {day}: verification error ({exc})", err=True)
            all_ok = False
            continue
        click.echo(f"TSA anchor {day}: {'valid' if ok else 'INVALID'}")
        all_ok = all_ok and ok
    return all_ok


@cli.command(name="merkle-root")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True),
    help="JSON audit log export file",
)
def merkle_root_cmd(audit_log_path: str) -> None:
    """Compute and print the Merkle root of the full audit log."""
    events = _load(audit_log_path)
    result = ChainVerifier().verify(events)
    click.echo(result.merkle_root)


@cli.command(name="merkle-proof")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True),
    help="JSON audit log export file",
)
@click.option("--event-id", required=True, help="UUID of the event to prove")
def merkle_proof_cmd(audit_log_path: str, event_id: str) -> None:
    """Emit a Merkle inclusion proof for a single event (JSON output)."""
    events = _load(audit_log_path)
    sorted_events = sorted(events, key=lambda e: e.get("sequence_number", 0))
    idx = next((i for i, e in enumerate(sorted_events) if e.get("event_id") == event_id), None)
    if idx is None:
        click.echo(json.dumps({"error": f"event {event_id} not found"}))
        sys.exit(1)

    row_hashes = [e.get("row_hash", "") for e in sorted_events]
    from kronos_attest.verifier import build_merkle_root  # noqa: PLC0415

    proof = merkle_proof(row_hashes, idx)
    root = build_merkle_root(row_hashes)
    leaf = row_hashes[idx]
    click.echo(
        json.dumps(
            {
                "event_id": event_id,
                "index": idx,
                "leaf_hash": leaf,
                "proof": [
                    {"sibling_hash": sibling_hash, "position": position}
                    for sibling_hash, position in proof
                ],
                "root_hash": root,
            },
            indent=2,
        )
    )


@cli.command(name="day-report")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True),
    help="JSON audit log export file",
)
@click.option("--day", required=True, help="ISO date (YYYY-MM-DD) to report on")
@click.option(
    "--tsa-cert",
    "tsa_cert_path",
    default=None,
    type=click.Path(exists=True),
    help="TSA CA certificate chain — required for tsa_anchored to reflect a "
    "real verified signature rather than 'no cert supplied, assumed false'.",
)
def day_report_cmd(audit_log_path: str, day: str, tsa_cert_path: str | None) -> None:
    """Generate an attestation report for a single day."""
    events = _load(audit_log_path)
    report = AttestationReport().day_report(events, day, tsa_cert_path)
    click.echo(
        json.dumps(
            {
                "day": report.day,
                "event_count": report.event_count,
                "merkle_root": report.merkle_root,
                "chain_valid": report.chain_valid,
                "break_count": report.break_count,
                "tsa_anchored": report.tsa_anchored,
                "tsa_gen_time": report.tsa_gen_time,
            },
            indent=2,
        )
    )


@cli.command(name="case-report")
@click.option(
    "--audit-log",
    "audit_log_path",
    required=True,
    type=click.Path(exists=True),
    help="JSON audit log export file",
)
@click.option("--case-id", required=True, help="Case UUID to report on")
def case_report_cmd(audit_log_path: str, case_id: str) -> None:
    """Generate an attestation report for a single case."""
    events = _load(audit_log_path)
    report = AttestationReport().case_report(events, case_id)
    click.echo(
        json.dumps(
            {
                "case_id": report.case_id,
                "event_count": report.event_count,
                "merkle_root": report.merkle_root,
                "chain_valid": report.chain_valid,
                "break_count": report.break_count,
                "evidence_ids": report.evidence_ids,
            },
            indent=2,
        )
    )


def _load(path: str) -> list[dict[str, Any]]:
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise click.ClickException("Audit log file must be a JSON array of event objects")
    return data


if __name__ == "__main__":
    cli()
