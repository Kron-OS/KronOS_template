"""GenericWebhookPushSource: the PUSH-shape concrete stand-in proving
``IntegrationSource`` end to end (roadmap Q1).

Not a named vendor (Wazuh is Q2) -- this is the real "lowest common
denominator" webhook shape every push-style EDR/SIEM integration reduces to
(single JSON event per call, OR a batch envelope of the form
``{"events": [...]}``), the same honesty-over-vendor-guessing precedent
``WebhookTicketingSystem`` already established for the sink side
(``src/adapter/ticketing/ticketing_system.py``). Registered under
``source_type = "generic-webhook"`` -- a real, usable connector for any
tool whose webhook posts one-or-many bare JSON events, not a throwaway.
"""

from __future__ import annotations

import json
import logging

from src.application.integration_source import IntegrationSource
from src.domain.integration_source import IntegrationDeliveryMode
from src.exceptions import ParsingError

logger = logging.getLogger(__name__)


class GenericWebhookPushSource(IntegrationSource):
    """PUSH source: splits an inbound webhook body into individual raw
    event payloads, unwrapping a ``{"events": [...]}`` batch envelope if
    present, otherwise (including the ABC's own default path) treats the
    whole body as a single event."""

    @property
    def source_type(self) -> str:
        return "generic-webhook"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.PUSH

    async def parse_push_event(self, raw_body: bytes) -> list[bytes]:
        try:
            decoded = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Not JSON at all -- honor the ABC's own documented default
            # (treat the whole body as one opaque event) rather than
            # failing a genuinely non-JSON webhook body.
            return [raw_body]

        if isinstance(decoded, dict) and isinstance(decoded.get("events"), list):
            events = decoded["events"]
            if not events:
                raise ParsingError(
                    "generic-webhook batch envelope has an empty 'events' list",
                    context={"source_type": self.source_type},
                )
            return [_canonical_bytes(event) for event in events]

        # A bare JSON object/array that isn't a batch envelope -- one event.
        return [raw_body]


def _canonical_bytes(event: object) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
