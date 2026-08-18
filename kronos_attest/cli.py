"""kronos-attest CLI: offline forensic audit log verification and attestation."""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from typing import Any

import click

from kronos_attest.report import AttestationReport
from kronos_attest.verifier import ChainVerifier, merkle_proof


@click.group()
def cli() -> None:
    """KronOS forensic attestation CLI — offline audit log verification."""


def _live_or_offline_options(f: Any) -> Any:
    """Shared ``--audit-log`` / ``--database-url`` / ``--org-id`` options.

    Exactly one source of events is allowed: a static JSON export
    (``--audit-log``), or a live read from the real Postgres source of
    truth (``--database-url`` + ``--org-id`` together). See
    ``_resolve_events`` for the mutual-exclusion validation — kept there
    (not in Click's own callback machinery) so the three commands sharing
    this decorator get identical, testable error messages.
    """
    f = click.option(
        "--org-id",
        "org_id",
        default=None,
        help="Org UUID to stream live from Postgres (required together with "
        "--database-url; mutually exclusive with --audit-log).",
    )(f)
    f = click.option(
        "--database-url",
        "database_url",
        default=None,
        envvar="DATABASE_URL",
        help="Live Postgres DSN, e.g. postgresql+asyncpg://kronos:...@localhost:5432/kronos "
        "-- reads the DATABASE_URL environment variable if not given explicitly "
        "(same convention as migrations/env.py). Mutually exclusive with --audit-log.",
    )(f)
    f = click.option(
        "--audit-log",
        "audit_log_path",
        default=None,
        type=click.Path(exists=True),
        help="JSON audit log export file (list of event objects). Mutually "
        "exclusive with --database-url/--org-id.",
    )(f)
    return f


def _resolve_events(
    audit_log_path: str | None,
    database_url: str | None,
    org_id: str | None,
) -> list[dict[str, Any]]:
    """Resolve the event list from exactly one of offline export or live Postgres.

    Enforces: exactly one of ``--audit-log`` or (``--database-url`` +
    ``--org-id``) must be given. Raises ``click.UsageError`` (Click's own
    "bad invocation" exception -- caught by the group and printed as a
    normal usage error, exit code 2) for every invalid combination.

    ``--org-id`` has no environment-variable fallback (unlike
    ``--database-url``, which reads ``DATABASE_URL`` -- see
    ``_live_or_offline_options``), so it is treated as the sole explicit
    trigger for "live mode was requested". This matters because an ambient
    ``DATABASE_URL`` left set in a developer's shell (common in this repo's
    own PoC workflow, e.g. ``DATABASE_URL=... python poc/.../run_poc.py``)
    must NOT silently turn a plain ``--audit-log`` invocation into a
    "both given" error -- an explicit ``--audit-log`` always wins over an
    ambient env var the user never meant to invoke here.
    """
    if audit_log_path is not None and org_id is not None:
        raise click.UsageError("Provide either --audit-log OR --database-url/--org-id, not both.")

    if audit_log_path is not None:
        # org_id is None here (checked above); an ambient DATABASE_URL env
        # var is deliberately ignored in this branch -- see docstring.
        return _load(audit_log_path)

    # No --audit-log: live mode is the only remaining option, so both
    # --org-id and --database-url (flag or DATABASE_URL env var) are
    # required together.
    if org_id is None and database_url is None:
        raise click.UsageError(
            "Provide either --audit-log <path>, or both --database-url and --org-id."
        )
    if org_id is None:
        raise click.UsageError(
            "--database-url given without --org-id -- both are required together for live mode."
        )
    if database_url is None:
        raise click.UsageError(
            "--org-id given without --database-url -- both are required together for live "
            "mode (--database-url may also come from the DATABASE_URL env var)."
        )

    try:
        org_uuid = uuid.UUID(org_id)
    except ValueError as exc:
        raise click.UsageError(f"--org-id must be a valid UUID: {exc}") from exc

    return asyncio.run(_fetch_live_events(database_url, org_uuid))


async def _fetch_live_events(database_url: str, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """Stream an org's full, unfiltered audit chain from the real Postgres source of truth.

    Uses the exact same repository method (``stream_by_org``) and field
    mapping (``_to_export_dict``) as ``GET /api/audit/export`` -- reusing
    ``_to_export_dict`` rather than re-deriving it is deliberate (see that
    function's own docstring: "any drift here would silently break chain
    verification for every export"). This keeps live mode and offline
    export mode producing byte-identical event dicts for the same data.

    Follows CLAUDE.md SS A.5 resource-lifecycle discipline: the engine is
    disposed in a ``finally`` block so no connection is ever leaked, even
    if streaming raises partway through.
    """
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

    from src.adapter.repository.postgres_audit_log import (  # noqa: PLC0415
        PostgresAuditLogRepository,
    )
    from src.external.routes.audit import _to_export_dict  # noqa: PLC0415

    engine = create_async_engine(database_url)
    try:
        repo = PostgresAuditLogRepository(engine)
        return [_to_export_dict(ev) async for ev in repo.stream_by_org(org_id)]
    finally:
        await engine.dispose()


@cli.command()
@_live_or_offline_options
@click.option("--event-id", required=True, help="UUID of the event to verify")
@click.option(
    "--tsa-cert",
    "tsa_cert_path",
    default=None,
    type=click.Path(exists=True),
    help="TSA CA certificate chain — if given, also verifies any daily "
    "Merkle anchor's RFC 3161 signature found in the log (AUDIT-07/08).",
)
def verify(
    audit_log_path: str | None,
    database_url: str | None,
    org_id: str | None,
    event_id: str,
    tsa_cert_path: str | None,
) -> None:
    """Verify hash chain integrity and locate a specific event.

    Reads events from exactly one of --audit-log or --database-url/--org-id.

    Exits with code 0 on success (chain intact + event found, and TSA
    anchors valid if --tsa-cert was given), code 1 otherwise.
    """
    events = _resolve_events(audit_log_path, database_url, org_id)
    result = ChainVerifier().verify(events)

    if result.valid:
        click.echo(f"Chain intact ({result.event_count} events, root={result.merkle_root[:16]}…)")
    else:
        click.echo(f"Chain BROKEN: {len(result.breaks)} break(s)", err=True)
        for b in result.breaks:
            click.echo(f"  seq={b.sequence_number} event={b.event_id}", err=True)

    target = next((e for e in events if e.get("event_id") == event_id), None)
    if target:
        click.echo(f"Event {event_id}: {target.get('event_type')} at {target.get('occurred_at')}")
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
        # AuditLogService.anchor_day() stores this key as "date" -- see the
        # matching fix/comment in kronos_attest/report.py._verify_tsa_anchor.
        day = details.get("date", "unknown")
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
@_live_or_offline_options
@click.option("--day", required=True, help="ISO date (YYYY-MM-DD) to report on")
@click.option(
    "--tsa-cert",
    "tsa_cert_path",
    default=None,
    type=click.Path(exists=True),
    help="TSA CA certificate chain — required for tsa_anchored to reflect a "
    "real verified signature rather than 'no cert supplied, assumed false'.",
)
def day_report_cmd(
    audit_log_path: str | None,
    database_url: str | None,
    org_id: str | None,
    day: str,
    tsa_cert_path: str | None,
) -> None:
    """Generate an attestation report for a single day.

    Reads events from exactly one of --audit-log or --database-url/--org-id.
    """
    events = _resolve_events(audit_log_path, database_url, org_id)
    report = AttestationReport().day_report(events, day, tsa_cert_path)
    click.echo(
        json.dumps(
            {
                "day": report.day,
                "event_count": report.event_count,
                "merkle_root": report.merkle_root,
                "chain_valid": report.chain_valid,
                "break_count": report.break_count,
                "org_chain_fully_intact": report.org_chain_fully_intact,
                "tsa_anchored": report.tsa_anchored,
                "tsa_gen_time": report.tsa_gen_time,
            },
            indent=2,
        )
    )


@cli.command(name="case-report")
@_live_or_offline_options
@click.option("--case-id", required=True, help="Case UUID to report on")
def case_report_cmd(
    audit_log_path: str | None,
    database_url: str | None,
    org_id: str | None,
    case_id: str,
) -> None:
    """Generate an attestation report for a single case.

    Reads events from exactly one of --audit-log or --database-url/--org-id.
    """
    events = _resolve_events(audit_log_path, database_url, org_id)
    report = AttestationReport().case_report(events, case_id)
    click.echo(
        json.dumps(
            {
                "case_id": report.case_id,
                "event_count": report.event_count,
                "merkle_root": report.merkle_root,
                "chain_valid": report.chain_valid,
                "break_count": report.break_count,
                "org_chain_fully_intact": report.org_chain_fully_intact,
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
