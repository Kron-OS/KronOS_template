"""GenericPollSource: the POLL-shape concrete stand-in proving
``IntegrationSource`` end to end (roadmap Q1).

Not a named vendor (Microsoft Defender is Q4) -- this is the real "lowest
common denominator" cursor-poll shape every poll-style API researched in
the roadmap's own SS0 reduces to: ``GET <base>/events?cursor=<opaque>`` ->
``{"events": [...], "next_cursor": "<opaque>"}``. Registered under
``source_type = "generic-poll"``. Auth is fully pluggable via
:class:`OutboundAuthStrategy` (``src/external/middleware/integration_source_auth.py``)
-- this class never hardcodes a credential scheme, matching the roadmap's
own SS4 requirement that OAuth2/API-key/mTLS all fit the same POLL source
shape.
"""

from __future__ import annotations

import json
import logging
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


class GenericPollSource(IntegrationSource):
    """POLL source: one page per call, resuming from the caller-supplied
    :class:`SourceCursor` (``None`` on the very first call for a given
    (org, source))."""

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
        return "generic-poll"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.POLL

    async def poll(
        self, identity: IntegrationSourceIdentity, cursor: SourceCursor | None
    ) -> PollFetchResult:
        params: dict[str, str] = {}
        if cursor is not None:
            params["cursor"] = cursor.cursor_value

        try:
            headers = await self._auth.headers()
            response = await self._http_client.get(
                f"{self._base_url}/events",
                params=params,
                headers=headers,
                **self._auth.client_kwargs(),
            )
        except httpx.HTTPError as exc:
            raise IntegrationSourceError(f"generic-poll request failed: {exc}") from exc

        if response.status_code != 200:
            raise IntegrationSourceError(
                f"generic-poll endpoint returned status={response.status_code}, "
                f"body={response.text[:500]!r}"
            )

        try:
            body: dict[str, Any] = response.json()
            events = body["events"]
            next_cursor = body.get("next_cursor")
        except (KeyError, ValueError, TypeError) as exc:
            raise IntegrationSourceError(f"generic-poll response malformed: {exc}") from exc

        if not isinstance(events, list):
            raise IntegrationSourceError(
                f"generic-poll response 'events' field was not a list (got {type(events).__name__})"
            )

        raw_events = [_canonical_bytes(event) for event in events]
        # An empty page must never advance the watermark on no real
        # progress (PollFetchResult's own contract) -- even if the server
        # echoed back a next_cursor value on an empty page.
        return PollFetchResult(
            raw_events=raw_events, next_cursor=next_cursor if raw_events else None
        )


def _canonical_bytes(event: object) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
