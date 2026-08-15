"""DefenderPollSource: the first real, named-vendor POLL-mode
``IntegrationSource`` (roadmap Q4), reusing Q1's foundation exactly the way
``WazuhPushSource``/``SuricataEvePushSource`` reuse it on the PUSH side.

**Real API contract, verified against Microsoft's own current docs
(CLAUDE.md SS F), not assumed from the roadmap's own SS0 summary.** Fetched
2026-08-09 from ``learn.microsoft.com`` (v1.0, the non-deprecating surface
the roadmap's own SS0 already identified):

- Resource/list shape: `alert resource type
  <https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0>`_
  and `List alerts_v2
  <https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0>`_.
- OAuth2 client-credentials token request/response shape: `OAuth2 client
  credentials flow
  <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow>`_.
- Pagination (``@odata.nextLink``): `Paging Microsoft Graph data
  <https://learn.microsoft.com/en-us/graph/paging>`_.

**Real, reportable correction to this roadmap item's own objective text
(CLAUDE.md SS F "fail loudly," mirrors Q2's Wazuh-version correction and
Q3's fluent-bit-parser-config gap -- reported, not silently applied).** The
roadmap's own Q4 objective and SS0 table both say
``$filter=lastUpdateTime gt ...``. There is no ``lastUpdateTime`` property
on the real ``alert`` resource. The real, documented property -- confirmed
against the "List alerts_v2" page's own "Optional query parameters" section,
which enumerates exactly the properties ``$filter`` supports
(``assignedTo``, ``classification``, ``determination``, ``createdDateTime``,
**``lastUpdateDateTime``**, ``severity``, ``serviceSource``, ``status``) --
is ``lastUpdateDateTime``. This module, its stand-in fixture server, and its
PoC all use the real ``lastUpdateDateTime`` name throughout.

**Real OAuth2 flow reused, not rebuilt.** Uses
``OAuth2ClientCredentialsOutboundAuthStrategy``
(``src/external/middleware/integration_source_auth.py``, built in Q1)
unmodified: the real Entra ID token endpoint (``POST
https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token``,
``grant_type=client_credentials``, form-urlencoded body) and Graph's own
``scope=https://graph.microsoft.com/.default`` convention are exactly the
RFC 6749 SS4.4 shape that strategy already implements and Q1 already
unit-tested against a mocked token endpoint -- nothing new to build there.

**Why one ``poll()`` call fully drains pagination (a real, deliberate
difference from ``GenericPollSource``'s "one page per call" contract, not an
oversight).** ``GenericPollSource`` (Q1) intentionally returns after one
page, since its own stand-in fixture has no pagination to prove. Real Graph
list responses are genuinely paged (``@odata.nextLink``), and Microsoft's
own paging docs are explicit that a client must "continue to call Microsoft
Graph with the ``@odata.nextLink`` property returned in each response until
[it] is no longer returned" to get a complete result set -- stopping after
page 1 would silently drop alerts on any poll cycle that crosses a page
boundary, a real correctness bug for a security-alert feed. This class's
``poll()`` therefore follows ``@odata.nextLink`` to exhaustion internally
before returning one aggregated :class:`PollFetchResult` --
``IntegrationSourceIngestService.run_poll_cycle`` still only calls it once
per cycle, so this is an internal implementation detail of *this* source,
not a change to the ABC's contract (``PollFetchResult`` already declares
"one poll cycle's real, raw output," not "one page's own output").

**Known, pre-existing gap this connector inherits, not fixes (flagged in
Q1's own module docstring, restated here since this is the concrete source
that first hits it).** A real alert's ``evidence`` array (device/file/
process/registry-key entities) is structurally artifact-shaped, not
event-shaped -- ``StreamSourceNormalizer.normalize()`` can only return a
``NormalizedStreamEvent`` today (see
``src/application/integration_source.py``'s own "Known, pre-existing gap"
section). ``DefenderAlertNormalizer``
(``src/application/stream_source_registry.py``) therefore preserves
``evidence`` verbatim under ``extra["ms_defender.evidence"]`` rather than
flattening it into ECS host/user/process fields -- a deliberately
conservative mapping, not a missed opportunity, pending that normalizer-side
gap closing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

import httpx

from src.application.integration_source import (
    IntegrationSource,
    IntegrationSourceError,
    PollFetchResult,
)
from src.domain.integration_source import (
    IntegrationDeliveryMode,
    IntegrationSourceIdentity,
    SourceCursor,
)
from src.external.middleware.integration_source_auth import OutboundAuthStrategy

logger = logging.getLogger(__name__)

# A real alert (any product, any serviceSource) always carries these two
# top-level properties -- verified against the real `alert` resource's own
# documented property table (`id` is the resource's own required identifier;
# `lastUpdateDateTime` is the property this connector's own $filter cursors
# on, so an alert missing it cannot honestly be watermark-tracked).
_REQUIRED_ALERT_KEYS = ("id", "lastUpdateDateTime")

# Defensive cap on @odata.nextLink hops within one poll() call. This is a
# safety valve, not a hard correctness assumption that a real backlog will
# ever fit in 50 pages -- it genuinely won't after a long outage of this
# beat task or for a very active tenant. Two different situations hit this
# cap and are handled differently (see the branch in the loop below):
#   - Genuine truncation of a real, legitimate backlog (at least one alert
#     was fetched across the capped run): pagination is stopped and the
#     partial-but-valid result accumulated so far is returned normally, with
#     its own advanced cursor, rather than discarded. The next scheduled
#     poll cycle (crontab-driven) resumes from that cursor and drains the
#     next slice of backlog -- self-healing, incremental, autonomous
#     recovery, no human intervention required (mirrors CLAUDE.md SS E.4's
#     own philosophy for the evidence pipeline, applied here).
#   - Zero real progress across the *entire* capped run (not a single alert
#     was ever fetched): a real backlog still yields real alerts on every
#     page, so fetching 50 full pages of nothing is a strong signal of a
#     malformed/looping response (e.g. a stand-in or a misbehaving API
#     returning a `@odata.nextLink` that never terminates and never advances
#     the watermark) rather than genuine data. This case still fails loudly
#     -- silently truncating it would hide a real bug instead of recovering
#     from real backlog (CLAUDE.md SS F: fail loudly on a genuine bug).
_MAX_PAGES_PER_POLL = 50


class DefenderPollSource(IntegrationSource):
    """POLL source for Microsoft Graph Security API's ``alerts_v2`` list
    operation (roadmap Q4).

    One ``poll()`` call: builds ``$filter=lastUpdateDateTime gt <cursor>``
    from the caller-supplied :class:`SourceCursor` (omitted entirely on the
    very first call for a given (org, source) -- an unfiltered
    ``GET /security/alerts_v2`` is the real, documented way to fetch "all"
    alerts), follows ``@odata.nextLink`` to exhaustion, and returns the
    watermark as the maximum ``lastUpdateDateTime`` seen across every alert
    fetched in that call (``None`` if none were fetched, so the ingest
    service's own "empty page never advances the cursor" contract holds).
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        base_url: str,
        auth_strategy: OutboundAuthStrategy,
    ) -> None:
        self._http_client = http_client
        self._base_url = base_url.rstrip("/")
        self._auth = auth_strategy

    @property
    def source_type(self) -> str:
        return "ms-defender-alerts"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.POLL

    async def poll(
        self, identity: IntegrationSourceIdentity, cursor: SourceCursor | None
    ) -> PollFetchResult:
        params: dict[str, str] | None = None
        if cursor is not None:
            params = {"$filter": f"lastUpdateDateTime gt {cursor.cursor_value}"}

        raw_events: list[bytes] = []
        newest_seen_dt: datetime | None = None
        newest_seen_str: str | None = None
        next_url: str | None = f"{self._base_url}/security/alerts_v2"
        next_params: dict[str, str] | None = params
        pages_fetched = 0

        while next_url is not None:
            pages_fetched += 1
            if pages_fetched > _MAX_PAGES_PER_POLL:
                if not raw_events:
                    # Zero progress across the whole capped run -- not a
                    # legitimate backlog (see _MAX_PAGES_PER_POLL comment).
                    raise IntegrationSourceError(
                        f"alerts_v2 pagination exceeded {_MAX_PAGES_PER_POLL} pages in one "
                        "poll cycle without fetching a single alert -- aborting rather than "
                        "looping unboundedly (this looks like a malformed/looping response, "
                        "not a real backlog)"
                    )
                # A real, legitimate backlog: every page fetched so far was
                # successfully parsed and is a valid partial result. Stop
                # paginating here and return it normally (same shape as a
                # clean, non-truncated success) instead of discarding it --
                # see _MAX_PAGES_PER_POLL's own comment for why this is safe
                # and self-healing.
                logger.warning(
                    "alerts_v2 pagination truncated at the %d-page cap for org_id=%s "
                    "source_id=%s -- returning %d event(s) fetched so far with an "
                    "advanced cursor; a real backlog remains and will be picked up "
                    "incrementally on subsequent poll cycles",
                    _MAX_PAGES_PER_POLL,
                    identity.org_id,
                    identity.source_id,
                    len(raw_events),
                )
                break

            try:
                headers = await self._auth.headers()
                response = await self._http_client.get(
                    next_url,
                    params=next_params,
                    headers=headers,
                    **self._auth.client_kwargs(),
                )
            except httpx.HTTPError as exc:
                raise IntegrationSourceError(f"alerts_v2 request failed: {exc}") from exc

            if response.status_code != 200:
                raise IntegrationSourceError(
                    f"alerts_v2 endpoint returned status={response.status_code}, "
                    f"body={response.text[:500]!r}"
                )

            try:
                body: dict[str, Any] = response.json()
                alerts = body["value"]
            except (KeyError, ValueError, TypeError) as exc:
                raise IntegrationSourceError(f"alerts_v2 response malformed: {exc}") from exc

            if not isinstance(alerts, list):
                raise IntegrationSourceError(
                    f"alerts_v2 response 'value' field was not a list (got {type(alerts).__name__})"
                )

            for alert in alerts:
                if not isinstance(alert, dict):
                    raise IntegrationSourceError(
                        f"alerts_v2 response contained a non-object alert entry "
                        f"(got {type(alert).__name__})"
                    )
                missing = [key for key in _REQUIRED_ALERT_KEYS if key not in alert]
                if missing:
                    raise IntegrationSourceError(
                        f"alerts_v2 alert missing required field(s) {missing} -- "
                        "not a real alerts_v2 resource"
                    )
                raw_events.append(_canonical_bytes(alert))
                last_update_str = str(alert["lastUpdateDateTime"])
                try:
                    last_update_dt = datetime.fromisoformat(last_update_str)
                except ValueError as exc:
                    raise IntegrationSourceError(
                        f"alerts_v2 alert has malformed lastUpdateDateTime "
                        f"{last_update_str!r}: {exc}"
                    ) from exc
                # Compared as real parsed datetimes, not raw strings --
                # lexicographic string comparison only happens to work for
                # ISO-8601 timestamps sharing identical fractional-second
                # precision/timezone formatting, which the real API does not
                # actually guarantee across every alert (CLAUDE.md SS F: a
                # once-plausible shortcut that was checked, not assumed).
                if newest_seen_dt is None or last_update_dt > newest_seen_dt:
                    newest_seen_dt = last_update_dt
                    newest_seen_str = last_update_str

            next_link = body.get("@odata.nextLink")
            next_url = str(next_link) if next_link else None
            # The nextLink already carries every original query parameter
            # (including $filter) baked into its own URL -- Microsoft's own
            # paging docs are explicit that a caller must use the whole
            # returned URL verbatim, never re-derive/re-attach query params.
            next_params = None

        return PollFetchResult(
            raw_events=raw_events, next_cursor=newest_seen_str if raw_events else None
        )


def _canonical_bytes(alert: dict[str, Any]) -> bytes:
    return json.dumps(alert, sort_keys=True, separators=(",", ":")).encode("utf-8")
