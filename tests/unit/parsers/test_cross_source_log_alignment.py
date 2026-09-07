"""Cross-source log normalization alignment (Milestone HHHHH).

Real question from the project owner: "does win and lin signin produce
logs where signin is the logtype" — i.e. does KronOS classify
semantically-equivalent events (a signin/authentication event) the same
way regardless of which real source produced them? This module answers
that empirically against the REAL, LIVE parser registry
(`src.external.dependencies.get_parser_registry()` — the exact selection
order `execute_parse()` uses in production), not a hand-assembled local
registry, and against real sample bytes (see
`tests/fixtures/samples/real/NOTICE.md` for provenance) — not
hand-crafted fixtures written to match the parser under test, same
reasoning as `test_real_world_samples.py` in this same directory.

Full investigation, the real captured PoC output this module's assertions
are sourced from, and the real gap this surfaced: `poc/cross_source_log_alignment/`
and `docs/GAP_AUDIT_2026-09-08_MILESTONE_HHHHH.md`.

**Real, decisive finding this module locks in as a regression check (not
a desired design)**: a genuine Windows Security EventID 4625 (failed
logon) record, parsed through the REAL live routing (PlasoParser — see
`src/external/parsers/plaso.py`'s own Gap Audit Milestone VVVV docstring
for why `FastEvtxParser` is no longer registered), currently carries
ZERO ECS event classification (`event_category`/`event_type`/`event_kind`/
`event_outcome` are all empty/`None` — confirmed by reading
`FirecrackerLauncher._stream_records`, `src/external/sandbox/firecracker.py`,
which only ever sets `@timestamp`/`message`/`event_original`/`extra`/
`kronos` on every Plaso-derived `TimelineRecord`). A genuine Linux signin
event (a real PAM login-session sequence from this host's own
`/var/log/auth.log`) fares *worse*: no registered parser claims a
plain-text auth log at all, so it never becomes a `TimelineRecord` in the
first place. The answer to the project owner's question is therefore not
"they diverge from each other" — it's "neither side is classified as a
signin event today," for two different real reasons. The nginx/apache
comparison below is the necessary positive control proving the
*mechanism* (a real registered parser, once one exists) does produce
real, consistent classification — the gap is specific to the Plaso path
and to the still-entirely-unsupported plain-text-auth-log/custom-container
formats, not a fundamental limitation of `TimelineRecord`'s own schema.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from src.application.stream_source_registry import StreamSourceNormalizerRegistry
from src.domain.timeline import TimelineRecord
from src.external.dependencies import get_parser_registry
from src.external.parsers.nginx import NginxParser
from tests.fixtures.factories import make_evidence, make_tenant_context

REAL_SAMPLES = Path(__file__).parents[2] / "fixtures" / "samples" / "real"
_HEADER_BYTES = 8192


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


def _read_header(path: Path) -> bytes:
    return path.read_bytes()[:_HEADER_BYTES]


# ---------------------------------------------------------------------------
# Does anything even claim each real sample? (the real, live registry)
# ---------------------------------------------------------------------------


class TestRealLiveRegistryDetection:
    """Uses the REAL, live `get_parser_registry()` -- the exact selection
    KronOS's own `execute_parse()` performs in production -- not a
    locally hand-assembled subset, so this reflects real current routing
    (e.g. `.evtx` -> PlasoParser, not the deregistered FastEvtxParser)."""

    def test_windows_security_evtx_routes_to_plaso(self) -> None:
        fixture = REAL_SAMPLES / "windows_security.evtx"
        registry = get_parser_registry()
        parser = registry.get_parser(
            fixture.name, "application/octet-stream", _read_header(fixture)
        )
        assert parser is not None
        assert parser.parser_name == "plaso"

    def test_linux_auth_log_has_no_claiming_parser(self) -> None:
        """Real, decisive finding: a genuine Linux PAM auth-log excerpt is
        claimed by NOTHING in the real live registry -- it never becomes a
        TimelineRecord at all, a strictly worse outcome than the Windows
        side (which at least parses, just with no classification -- see
        TestSigninEventClassificationGap below)."""
        fixture = REAL_SAMPLES / "linux_auth.log"
        registry = get_parser_registry()
        parser = registry.get_parser(fixture.name, "text/plain", _read_header(fixture))
        assert parser is None

    def test_custom_container_log_has_no_claiming_parser(self) -> None:
        """A real, bespoke-format container log (redis:7-alpine's own real
        startup log) is also claimed by nothing -- KronOS's evidence-upload
        parser registry has no generic fallback for an arbitrary custom
        container's own log format."""
        fixture = REAL_SAMPLES / "custom_container.log"
        registry = get_parser_registry()
        parser = registry.get_parser(fixture.name, "text/plain", _read_header(fixture))
        assert parser is None

    def test_two_different_real_web_log_formats_route_to_the_same_parser(self) -> None:
        """Positive control: nginx's own real access.log format and a real
        Apache combined-log-format file are DIFFERENT real formats but
        both route to the same NginxParser -- the precondition for the
        alignment check below."""
        registry = get_parser_registry()
        nginx_fixture = REAL_SAMPLES.parent / "nginx.log"
        apache_fixture = REAL_SAMPLES / "apache_access.log"
        nginx_parser = registry.get_parser(
            nginx_fixture.name, "text/plain", _read_header(nginx_fixture)
        )
        apache_parser = registry.get_parser(
            apache_fixture.name, "text/plain", _read_header(apache_fixture)
        )
        assert isinstance(nginx_parser, NginxParser)
        assert isinstance(apache_parser, NginxParser)


# ---------------------------------------------------------------------------
# The generic streaming/collector path has no coverage for an arbitrary
# custom source either (a second, independent real ingestion path from
# the evidence-upload one above).
# ---------------------------------------------------------------------------


class TestStreamNormalizerRegistryHasNoGenericCustomSourceSupport:
    def test_unregistered_custom_container_source_id_has_no_normalizer(self) -> None:
        """StreamSourceNormalizerRegistry (src/application/stream_source_registry.py)
        only ever has Zeek/Wazuh/Defender normalizers registered
        (src/external/dependencies.py) -- an arbitrary custom container
        pushed through the generic webhook/poll ingestion path
        (src/external/integration_sources/generic_{webhook,poll}.py) has
        no normalizer to turn its own bespoke fields into TimelineRecord's
        ECS shape at all. Real, not guessed: an unregistered source_id."""
        registry = StreamSourceNormalizerRegistry()
        assert registry.for_source("some-custom-container-source") is None


# ---------------------------------------------------------------------------
# Positive control: when a shared parser DOES exist, alignment is real.
# ---------------------------------------------------------------------------


class TestWebSourceAlignmentPositiveControl:
    """Two genuinely different real web-server log formats, normalized by
    the SAME registered parser, produce IDENTICAL ECS classification --
    proving the alignment mechanism itself works whenever a parser exists
    for both sides being compared. Contrast with the signin case below,
    where no shared classification exists for either side."""

    @pytest.mark.asyncio
    async def test_nginx_and_apache_access_logs_get_identical_ecs_classification(self) -> None:
        nginx_data = (REAL_SAMPLES.parent / "nginx.log").read_bytes()
        apache_data = (REAL_SAMPLES / "apache_access.log").read_bytes()

        nginx_records = await _drain(
            NginxParser().parse(_bytes_stream(nginx_data), make_evidence(), make_tenant_context())
        )
        apache_records = await _drain(
            NginxParser().parse(_bytes_stream(apache_data), make_evidence(), make_tenant_context())
        )
        assert nginx_records and apache_records

        for record in (*nginx_records, *apache_records):
            assert record.event_kind == "event"
            assert record.event_category == ["web"]
            assert record.event_type == ["access"]


# ---------------------------------------------------------------------------
# The headline, real gap: a genuine Windows signin-failure event, parsed
# through the real live (Plaso) path, has NO classification at all.
# Requires a real plaso installation -- class-level skip (NOT a
# module-level `pytest.importorskip`, which would skip every test above
# too) -- run this inside docker-celery-worker-plaso-1's own Python,
# which has real plaso installed, to actually exercise it; skipped
# elsewhere.
# ---------------------------------------------------------------------------

try:
    import plaso as _plaso  # noqa: F401

    _PLASO_AVAILABLE = True
except ImportError:
    _PLASO_AVAILABLE = False

from src.external.parsers.plaso import PlasoParser  # noqa: E402


@pytest.mark.skipif(not _PLASO_AVAILABLE, reason="real plaso not installed in this interpreter")
class TestSigninEventClassificationGap:
    FIXTURE = REAL_SAMPLES / "windows_security.evtx"

    @pytest.mark.asyncio
    async def test_real_failed_logon_event_has_no_ecs_classification(self) -> None:
        """Real, confirmed gap (Milestone HHHHH) -- NOT a desired design.

        Parses a genuine Windows Security EventID 4625 (failed logon,
        RDP LogonType 10) record through the real, live PlasoParser path
        (a real Firecracker/subprocess Plaso invocation, same as
        production). The real event data (account name, logon type,
        failure status) IS present in the record's own `message`/
        `event_original` text -- Plaso itself parsed it correctly -- but
        KronOS never classifies it: `event_category`/`event_type` stay
        empty and `event_kind`/`event_outcome` stay None. If this
        assertion ever starts failing because someone taught
        FirecrackerLauncher/PlasoParser to set real ECS event fields,
        that is a GOOD outcome -- update this test to assert the real
        fixed behavior instead of reverting the fix.
        """
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(
            PlasoParser().parse(_bytes_stream(self.FIXTURE.read_bytes()), evidence, tenant)
        )
        assert records, "real Plaso run against a real Security.evtx produced no records at all"

        failed_logon_records = [
            r
            for r in records
            if "4625" in (r.message or "") or "failed to log on" in (r.message or "").lower()
        ]
        assert failed_logon_records, (
            "the real EventID 4625 record was not found among Plaso's own "
            "real output -- Plaso itself failed to parse the real logon "
            "failure this fixture is known to contain"
        )

        for record in failed_logon_records:
            assert record.event_category == []
            assert record.event_type == []
            assert record.event_kind is None
            assert record.event_outcome is None
