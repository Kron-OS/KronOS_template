"""HttpJsonIntegrationSink: generic HTTP-JSON push-with-ack transport
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R1) -- the shared shape underlying
Splunk HEC, Sentinel's Logs Ingestion API, QRadar HTTP Receiver, Elastic
Bulk, XSOAR, and TheHive (roadmap SS0/SS4): POST a real JSON body, read
back a real response code/body as the delivery confirmation.

**Deliberately generic-envelope-shaped, not modeled on one named vendor's
own wire format** -- mirrors ``WebhookTicketingSystem``'s own documented
reasoning (``src/adapter/ticketing/ticketing_system.py``) for exactly the
same class of judgment call: R1 targets no specific vendor yet (that's
R2/R4's job), so building this generic-envelope shape and verifying it
against a real local receiver this PoC itself stands up is the honest
choice, not a claim that this IS Splunk HEC's or Sentinel's real wire
contract. R2/R4 will each need their own ``IntegrationSink`` subclass (or
constructor-level envelope customization) once they research and verify
against their own real, pinned API contract.

Auth is fully delegated to an injected ``SinkAuthenticator`` (this class
never knows whether it's holding a static token, an OAuth2-cached one, or
an mTLS cert) -- ``prepare()`` is called before every real POST so a
refreshable-token authenticator can transparently rotate without this
class's own knowledge.
"""

from __future__ import annotations

from collections.abc import Sequence

import httpx

from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.adapter.integration_sink.sink_authenticator import SinkAuthenticator
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAck, SinkAckStatus
from src.exceptions import IntegrationSinkError


class HttpJsonIntegrationSink(IntegrationSink):
    """Real HTTP POST of a JSON envelope ``{"events": [...]}`` to *endpoint_url*.

    The real target's 2xx response body is required to report how many
    events it accepted (``accepted`` field) -- a mismatch against how many
    were actually sent is treated as a real failure (never a partial,
    silently-accepted ``SinkAck``), mirroring ``WebhookTicketingSystem``'s
    own "a 2xx response with no usable ticket_id is still an error" idiom
    applied here to "silently trusting an unverified accepted-count would
    be worse than raising."
    """

    def __init__(
        self,
        endpoint_url: str,
        authenticator: SinkAuthenticator,
        *,
        timeout: float = 15.0,
        max_batch_events: int | None = None,
        max_batch_bytes: int | None = None,
    ) -> None:
        self._endpoint_url = endpoint_url
        self._authenticator = authenticator
        self._timeout = timeout
        self._max_batch_events = max_batch_events
        self._max_batch_bytes = max_batch_bytes

    @property
    def max_batch_events(self) -> int | None:
        return self._max_batch_events

    @property
    def max_batch_bytes(self) -> int | None:
        return self._max_batch_bytes

    async def push_events(self, events: Sequence[MappedSinkEvent]) -> SinkAck:
        if not events:
            raise IntegrationSinkError("push_events called with an empty batch")

        payloads = []
        for event in events:
            if event.payload is None:
                raise IntegrationSinkError(
                    "HttpJsonIntegrationSink requires MappedSinkEvent.payload "
                    "(JSON-family) -- got a raw_text/line-oriented event instead",
                    context={"source_detection_id": event.source_detection_id},
                )
            payloads.append(event.payload)

        auth = await self._authenticator.prepare()
        body = {"events": payloads}

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, verify=auth.verify, cert=auth.cert
            ) as client:
                response = await client.post(
                    self._endpoint_url, json=body, headers=dict(auth.headers)
                )
        except httpx.HTTPError as exc:
            raise IntegrationSinkError(
                "Real HTTP-JSON sink POST failed to complete",
                context={
                    "endpoint_url": self._endpoint_url,
                    "event_count": len(payloads),
                    "error": str(exc),
                },
            ) from exc

        if not (200 <= response.status_code < 300):
            raise IntegrationSinkError(
                "HTTP-JSON sink target rejected the real push",
                context={
                    "endpoint_url": self._endpoint_url,
                    "status_code": response.status_code,
                    "body": response.text[:500],
                },
            )

        try:
            resp_body = response.json()
            accepted = resp_body["accepted"]
        except (ValueError, KeyError, TypeError) as exc:
            raise IntegrationSinkError(
                "HTTP-JSON sink target returned a 2xx response with no usable "
                "'accepted' count -- never fabricating an ack",
                context={
                    "endpoint_url": self._endpoint_url,
                    "body": response.text[:500],
                    "error": str(exc),
                },
            ) from exc

        if accepted != len(payloads):
            raise IntegrationSinkError(
                "HTTP-JSON sink target's own accepted count does not match the "
                "real number of events sent -- treating a partial ack as a real "
                "failure rather than silently trusting it",
                context={
                    "endpoint_url": self._endpoint_url,
                    "sent": len(payloads),
                    "accepted": accepted,
                },
            )

        return SinkAck(
            status=SinkAckStatus.ACKNOWLEDGED,
            detail={
                "status_code": response.status_code,
                "accepted": accepted,
                "body": resp_body,
            },
        )
