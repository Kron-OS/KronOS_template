"""PoC: does KronOS normalize semantically-equivalent events (a "signin")
consistently across different real log sources?

Real question from the project owner: "does win and lin signin produce
logs where signin is the logtype." This script answers it empirically --
real samples, through the real, currently-registered parser set
(`src.external.dependencies.get_parser_registry()`), reading each real
resulting TimelineRecord's real ECS fields (`event_kind`/`event_category`/
`event_type`/`event_outcome`) -- not by reading code and guessing.

Samples (poc/cross_source_log_alignment/samples/), each with its own real
provenance recorded in a sibling README:
  - windows_security.evtx  -- real Windows Security channel EVTX, genuine
    EventID 4625 (failed logon) record, from the real upstream `evtx`/
    pyevtx-rs project's own test corpus (the pinned Python package's
    actual upstream, not a fabricated file).
  - linux_auth.log         -- a real excerpt of THIS host's own
    /var/log/auth.log, a genuine PAM `session opened`/`session closed`
    login-session sequence for a real local user.
  - custom_container.log   -- real stdout captured from a real, briefly-run
    `redis:7-alpine` container (its own bespoke startup-log format,
    representative of "a custom container's logs" that KronOS has no
    bespoke parser for).
  - nginx.log / apache_access.log -- pre-existing real fixtures
    (tests/fixtures/samples/{nginx.log, real/apache_access.log}), used as
    a positive control: two DIFFERENT real web-server log formats that
    the SAME registered parser (NginxParser) is expected to classify
    identically.

Must run inside docker-celery-worker-plaso-1 (or an equivalent
environment with the real backend package installed AND the real Plaso
binary on PATH) -- windows_security.evtx routes to the HEAVY PlasoParser,
which shells out to a real Plaso subprocess via FirecrackerLauncher.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, "/app")  # real backend package root inside the container

from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState  # noqa: E402
from src.domain.timeline import TimelineRecord  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.dependencies import get_parser_registry  # noqa: E402

SAMPLES_DIR = Path(__file__).parent / "samples"

_ORG_ID = uuid.uuid4()
_CASE_ID = uuid.uuid4()


def _make_evidence(filename: str, size_bytes: int) -> Evidence:
    return Evidence(
        metadata=EvidenceMetadata(
            original_filename=filename,
            content_type="application/octet-stream",
            size_bytes=size_bytes,
            uploader_user_id=uuid.uuid4(),
            case_id=_CASE_ID,
            org_id=_ORG_ID,
            org_alias="poc-cross-source",
        ),
        state=EvidenceState.RECEIVED,
        sha256="0" * 64,
    )


def _make_tenant() -> TenantContext:
    return TenantContext(
        org_id=_ORG_ID,
        org_alias="poc-cross-source",
        user_id=uuid.uuid4(),
        username="poc-script",
        roles=frozenset({Role.ORG_ADMIN}),
        correlation_id=str(uuid.uuid4()),
    )


async def _byte_stream(data: bytes):
    yield data


def _record_summary(record: TimelineRecord) -> dict:
    return {
        "event_kind": record.event_kind,
        "event_category": record.event_category,
        "event_type": record.event_type,
        "event_outcome": record.event_outcome,
        "message": record.message,
    }


async def _run_sample(filename: str) -> dict:
    path = SAMPLES_DIR / filename
    data = path.read_bytes()
    header = data[:8192]

    registry = get_parser_registry()
    parser = registry.get_parser(filename, "application/octet-stream", header)

    result: dict = {
        "filename": filename,
        "size_bytes": len(data),
        "claimed_by_parser": parser.parser_name if parser else None,
    }
    if parser is None:
        result["records"] = []
        return result

    evidence = _make_evidence(filename, len(data))
    tenant = _make_tenant()
    records = []
    try:
        async for record in parser.parse(_byte_stream(data), evidence, tenant):
            records.append(_record_summary(record))
    except Exception as exc:  # noqa: BLE001 -- real failure is itself a real result
        result["parse_error"] = f"{type(exc).__name__}: {exc}"
        result["records"] = records
        return result

    result["records"] = records
    return result


async def main() -> None:
    samples = [
        "windows_security.evtx",
        "linux_auth.log",
        "custom_container.log",
    ]
    # Pre-existing real fixtures, positive control.
    extra_fixture_dir = Path("/app/tests/fixtures/samples")
    nginx_log = extra_fixture_dir / "nginx.log"
    apache_log = extra_fixture_dir / "real" / "apache_access.log"

    results = []
    for name in samples:
        results.append(await _run_sample(name))

    for label, path in [("nginx.log", nginx_log), ("apache_access.log", apache_log)]:
        if path.exists():
            data = path.read_bytes()
            header = data[:8192]
            registry = get_parser_registry()
            parser = registry.get_parser(label, "text/plain", header)
            entry: dict = {
                "filename": label,
                "size_bytes": len(data),
                "claimed_by_parser": parser.parser_name if parser else None,
            }
            if parser is not None:
                evidence = _make_evidence(label, len(data))
                tenant = _make_tenant()
                records = []
                async for record in parser.parse(_byte_stream(data), evidence, tenant):
                    records.append(_record_summary(record))
                entry["total_records"] = len(records)
                entry["records"] = records[:3]  # first few are enough for the control
            results.append(entry)
        else:
            results.append({"filename": label, "error": f"fixture not found at {path}"})

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
