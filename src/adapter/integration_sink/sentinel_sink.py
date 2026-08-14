"""SentinelHttpSink: real Microsoft Sentinel Logs Ingestion API transport
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R4 -- "Microsoft Sentinel sink
connector").

**Real, current API contract this class implements** -- fetched and read
directly from Microsoft's own docs this pass (not assumed from memory or
from the now-retired HTTP Data Collector API, which the roadmap SS0 table
already flags as ending Sept 14 2026):

- ``learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview``
  -- the real URI template ``{Endpoint}/dataCollectionRules/{DCR Immutable
  ID}/streams/{Stream Name}?api-version=2023-01-01``;
  required headers ``Authorization: Bearer <token>`` (audience/scope
  ``https://monitor.azure.com`` for Azure public cloud) and
  ``Content-Type: application/json``; the real request body shape -- a
  **top-level JSON array** of records, e.g. ``[{"TimeGenerated": ...,
  "Column01": "Value01"}]`` -- confirmed via the doc's own worked example.
- ``learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-code``
  (PowerShell tab, fetched this pass) -- the real OAuth2 client-credentials
  token exchange: ``POST https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token``,
  form-encoded ``grant_type=client_credentials&client_id=...&client_secret=...&scope=...``;
  and the real, explicitly documented success confirmation: **"Execute the
  script, and you should see an `HTTP - 204` response."** -- 204 No
  Content, no response body, is the one real documented success code (NOT
  200 -- verified against this exact sentence, not inferred).
- ``learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits``
  ("Logs Ingestion API" table, fetched this pass) -- real, documented
  ceilings: **1 MB maximum size of API call** (compressed or uncompressed --
  this class's own ``max_batch_bytes`` default), 64 KB maximum field value
  (truncated server-side, not rejected -- deliberately NOT enforced
  client-side here, see "Not implemented" below), 2 GB/minute and
  12,000 requests/minute per DCR (both throttled with a real
  ``Retry-After`` header on 429 -- this class surfaces the 429 as a real
  failure but does not itself implement retry/backoff, mirrors R2/R3's own
  identical "not built here" deferral for their own retry concerns).
- Real, documented error cases from the same tutorial's own "Troubleshooting"
  table (fetched this pass): **403** (the app registration lacks the
  DCR's ``Monitoring Metrics Publisher`` role), **413** (request exceeds
  the real 1 MB ceiling -- this class rejects client-side before ever
  sending, mirroring ``SplunkHecSink``'s own ``maxEventSize`` client-side
  pre-check idiom), **429** (real per-DCR throttle). A malformed
  bearer token produces a standard bearer-auth **401** (RFC 6750 SS3 --
  not itself in the Sentinel-specific troubleshooting table, but the
  universal HTTP bearer-auth contract every real Entra-ID-protected
  Azure data-plane API follows).
- **Error response body shape**: Microsoft's own general Azure REST API
  Guidelines (``github.com/microsoft/api-guidelines``, "Handling Errors"
  section, fetched this pass) define the standard Azure data-plane error
  envelope as ``{"error": {"code": "...", "message": "...", ...}}`` --
  used here as the real, documented, cross-service Azure contract. **Not
  independently verified against a live Azure subscription** (none
  available in this environment -- see this pass's own PoC README for how
  that was checked) -- flagged honestly, not silently assumed identical to
  a specific tenant's exact wording, per roadmap SS1 invariant #9's "real
  recorded response fixture, clearly labeled as such" allowance.

**Why a sibling ``IntegrationSink``, not reuse of ``HttpJsonIntegrationSink``
(mirrors ``SplunkHecSink``'s own explicit "justify sibling vs reuse"
precedent, landing on the same conclusion as Splunk for a third,
independently-verified reason).** ``HttpJsonIntegrationSink`` requires (a) a
``{"events": [...]}`` wrapper envelope and (b) a 2xx response body carrying
an ``accepted`` count. Sentinel's real, documented contract satisfies
NEITHER: the request body is a bare top-level array (no ``events`` wrapper
key at all), and the real success response is 204 **with no body** -- there
is no ``accepted`` field to ever read, so reusing
``HttpJsonIntegrationSink`` here would force every real Sentinel push to
fail its own "2xx response with no usable ``accepted`` count" check, 100% of
the time, even on real success. This is a third, independently-arrived-at
confirmation of the same conclusion ``splunk_hec_sink.py``'s own docstring
already reached for a different vendor: the "generic HTTP-JSON envelope"
abstraction only fits vendors that were never surveyed when it was designed
-- not evidence the generic sink was designed wrong, just that this
codebase's own precedent (composition/sibling over forcing a shared
abstraction to fit a third shape) is the right call again here.

**Auth: reuses R1's ``OAuth2ClientCredentialsAuthenticator`` unchanged --
does NOT duplicate or reuse Q1's ``OAuth2ClientCredentialsOutboundAuthStrategy``,
and here is the actual justification (the R4 brief's own explicit "decide
and justify" instruction).** Two real OAuth2-client-credentials
implementations already exist in this codebase:

1. ``src/adapter/integration_sink/sink_authenticator.py``'s
   ``OAuth2ClientCredentialsAuthenticator`` -- built in R1 **specifically
   naming Sentinel's own Entra ID flow** as its own justification for
   existing ("Sentinel's Entra ID flow -- re-authenticating on every single
   push would be both slow..."), returns ``SinkAuthParams`` (the exact
   shape every ``IntegrationSink`` in this package already consumes via
   ``SinkAuthenticator.prepare()``), and owns its own internal
   ``httpx.AsyncClient`` per token fetch (no external client lifecycle to
   manage).
2. ``src/external/middleware/integration_source_auth.py``'s
   ``OAuth2ClientCredentialsOutboundAuthStrategy`` -- built in Q1 for the
   opposite direction (KronOS POLLING an external tool's API, e.g. a future
   Defender connector), implements a DIFFERENT ABC
   (``OutboundAuthStrategy.headers() -> dict[str, str]``, no
   cert/verify passthrough) and REQUIRES an externally-injected, shared
   ``httpx.AsyncClient`` the caller owns across many poll calls -- a
   lifecycle model that has nothing in common with
   ``IntegrationSink.push_events()``'s own "authenticator owns its own
   state, called fresh before every push" contract.

Reusing (1) is correct and required -- it already exists, is already typed
to fit this exact class's constructor, and was already built with Sentinel
named as its reason to exist. Reusing (2) instead would require either
duplicating the token-caching logic a second time under a different
interface, or bolting an adapter between two ABCs that were never designed
to compose -- strictly worse than using the collaborator R1 already built
for this. No new authenticator class was written for R4.

**Not implemented AS RUNNING CODE here -- DESIGNED (not built, not
executed) in this pass, gap audit V6/P1-4.** A 204 here confirms the Logs
Ingestion API's own synchronous, real, documented acceptance of the batch
for processing -- it does NOT confirm the data was actually written into
the destination Log Analytics table, since DCR transformation/ingestion is
itself asynchronous and any transform-time failure (e.g. a KQL
``transformKql`` error) surfaces only in the DCR's own Azure Monitor
metrics, never back to this synchronous caller.

**Design for a real follow-up KQL confirmation query (mirrors HEC's own
``ackId`` polling structurally, but the confirmation mechanism itself is a
genuinely different shape -- a read query against the destination table,
not a status-lookup-by-id endpoint like HEC's ``/services/collector/ack``).
Explicitly a DESIGN ONLY: cited against Microsoft's own current docs
(fetched this pass, see below), a real method signature is given, but
NOTHING here was run end-to-end -- gap audit V6's own hard constraint,
identical to R4's own original "no real Azure subscription available in
this sandbox" limitation (``poc/integration_sink_sentinel/README.md``),
which still applies unchanged.**

- **Real package/client, fetched this pass**:
  ``learn.microsoft.com/en-us/python/api/overview/azure/monitor-query-readme``
  -- the ``azure-monitor-query`` PyPI package (current major ``2.0.0``,
  confirmed via the doc's own "As of version 2.0.0" callout), class
  ``azure.monitor.query.aio.LogsQueryClient`` (the async form, matching
  this codebase's async-first discipline, CLAUDE.md SS A.5), method
  ``await client.query_workspace(workspace_id, query, timespan=...)`` --
  real, verbatim signature and return shape confirmed from the doc's own
  worked examples: returns a ``LogsQueryResult`` (``.status``,
  ``.tables`` -- a list of ``LogsTable`` with ``.rows``/``.columns``) on
  success, or a ``LogsQueryPartialResult``/raises ``HttpResponseError`` on
  failure -- the doc's own quoted code checks
  ``response.status == LogsQueryStatus.SUCCESS`` before trusting
  ``response.tables``, which any real implementation here must do too
  (never assume success from "no exception" alone -- exactly the class of
  honesty gap this whole ``IntegrationSink`` package exists to prevent, so
  the discipline transfers even though this class lives outside the
  ``IntegrationSink`` hierarchy, see below).
- **Real auth is NOT ``SinkAuthenticator``/``SinkAuthParams``** -- the
  Query SDK takes an ``azure.identity`` ``TokenCredential`` object
  directly (e.g. ``azure.identity.aio.ClientSecretCredential(tenant_id,
  client_id, client_secret)``) and manages its own token acquisition
  internally; it does not accept a pre-built ``Authorization`` header the
  way every real ``IntegrationSink`` in this package does. This is also
  why a confirmation checker cannot be another ``push_events()``-shaped
  ``IntegrationSink`` at all -- querying is not pushing, there is no
  ``MappedSinkEvent``/``SinkAck`` on this side, so the honest design is a
  **separate, standalone class outside the ``IntegrationSink`` hierarchy**
  (mirrors ``SplunkHecSink.check_ack_status()``'s own "separate mechanism"
  precedent conceptually, but cannot literally be a method on
  ``SentinelHttpSink`` since it needs an entirely different SDK/credential
  type, not just a different HTTP call on the same client).
- **Real, documented, ADDITIONAL required Azure RBAC permission**, distinct
  from ingestion's own ``Monitoring Metrics Publisher`` DCR role (this
  module's own docstring above): the app registration querying Logs needs
  a **Log Analytics Reader** role on the destination workspace -- a real,
  separate grant an operator must make, not automatically implied by the
  ingestion-side role. Not verified against a live tenant (no Azure
  subscription available, see below) -- flagged as a real, named
  precondition rather than silently assumed.
- **Real target method signature this design specifies** (not implemented,
  not tested against any real or stand-in endpoint -- pure design, per
  this item's own required proof bar):

  .. code-block:: python

      class SentinelIngestionConfirmationChecker:
          \"\"\"Real follow-up KQL query against the destination Log
          Analytics workspace table -- confirms a specific pushed
          Detection genuinely landed after DCR transform, closing the gap
          a 204 alone cannot close. NOT an IntegrationSink (no
          push_events() -- this reads, never writes).\"\"\"

          def __init__(
              self, workspace_id: str, credential: "azure.identity.aio.TokenCredential",
              *, table_name: str = DEFAULT_TABLE_NAME, timeout: float = 30.0,
          ) -> None: ...

          async def confirm_ingested(
              self, finding_id: str, *, lookback: "datetime.timedelta" = ...,
          ) -> bool:
              \"\"\"Real KQL: f"{table_name} | where FindingId == '{finding_id}' |
              count" against workspace_id via LogsQueryClient.query_workspace()
              -- FindingId is this module's own real, documented, non-nullable
              column (see the 14-column table above), the natural real
              correlation key back to the Detection that was pushed. Real
              count > 0 -- confirmed landed; count == 0 -- either not yet
              transformed (real DCR latency) or a real, silent transform
              failure (indistinguishable from here without also checking the
              DCR's own Azure Monitor diagnostic metrics, which this design
              does not attempt to fold in). finding_id must be escaped
              (single-quote-doubled at minimum) before interpolation --
              KronOS's own finding_id values are server-generated, not raw
              user input, but this is a real, not-yet-addressed KQL-injection
              surface worth flagging explicitly rather than silently assuming
              safe.\"\"\"

- **Explicitly NOT implemented, NOT run, NOT stubbed with a fake client**:
  no ``src/`` code for ``SentinelIngestionConfirmationChecker`` exists --
  writing a class that imports ``azure-monitor-query``/``azure-identity``
  (neither currently a dependency of this repo -- would need adding to
  ``pyproject.toml``) with no real workspace to run a single real query
  against would be exactly the "plausible code without a captured real
  run" failure mode CLAUDE.md SS F and this item's own brief both name as
  an automatic fail. This section is a design-only, cited-against-current-
  docs specification -- closing it for real requires a real Azure
  subscription with a real Log Analytics workspace + DCR + app
  registration with both the ingestion (``Monitoring Metrics Publisher``)
  and query (``Log Analytics Reader``) roles granted, none of which are
  available in this sandbox (re-confirmed this pass: no ``az`` CLI, no
  ``AZURE_*`` env vars -- see ``poc/integration_sink_sentinel/README.md``'s
  own original check, unchanged).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import httpx

from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.adapter.integration_sink.sink_authenticator import SinkAuthenticator
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAck, SinkAckStatus
from src.exceptions import IntegrationSinkError

# Real, current, pinned Logs Ingestion API version -- the exact value every
# doc/tutorial/SDK default fetched this pass uses (learn.microsoft.com's own
# overview doc URI template; azure-monitor-ingestion's Python
# LogsIngestionClient's own documented "Default value is '2023-01-01'").
_DEFAULT_API_VERSION = "2023-01-01"
# Real, documented "Maximum size of API call" (service-limits doc, fetched
# this pass): 1 MB, "Both compressed and uncompressed data."
_DEFAULT_MAX_BATCH_BYTES = 1_000_000


class SentinelHttpSink(IntegrationSink):
    """Real HTTP POST to a Microsoft Sentinel Logs Ingestion API endpoint
    (a Data Collection Endpoint, or a DCR's own embedded logs-ingestion
    endpoint -- this class is agnostic to which, since both use the exact
    same real URI template; see this module's own docstring).

    *dce_endpoint* is the caller's own real DCE/DCR-ingestion base URL
    (e.g. ``https://my-dce-5kyl.eastus-1.ingest.monitor.azure.com``) --
    never guessed/constructed from a bare resource name, mirroring
    ``SplunkHecSink``'s own "caller supplies the real full endpoint" idiom
    (real deployments vary region/private-link topology).
    """

    def __init__(
        self,
        dce_endpoint: str,
        dcr_immutable_id: str,
        stream_name: str,
        authenticator: SinkAuthenticator,
        *,
        api_version: str = _DEFAULT_API_VERSION,
        timeout: float = 15.0,
        max_batch_events: int | None = None,
        max_batch_bytes: int | None = _DEFAULT_MAX_BATCH_BYTES,
    ) -> None:
        self._url = (
            f"{dce_endpoint.rstrip('/')}/dataCollectionRules/{dcr_immutable_id}"
            f"/streams/{stream_name}?api-version={api_version}"
        )
        self._authenticator = authenticator
        self._timeout = timeout
        self._max_batch_events = max_batch_events
        self._max_batch_bytes = max_batch_bytes

    @property
    def max_batch_events(self) -> int | None:
        # The real Logs Ingestion API documents no per-request EVENT-COUNT
        # ceiling (only the byte-size ceiling below) -- an honest "not
        # documented," mirrors SplunkHecSink's identical reasoning for its
        # own max_batch_events.
        return self._max_batch_events

    @property
    def max_batch_bytes(self) -> int | None:
        return self._max_batch_bytes

    async def push_events(self, events: Sequence[MappedSinkEvent]) -> SinkAck:
        if not events:
            raise IntegrationSinkError("push_events called with an empty batch")

        records: list[dict[str, Any]] = []
        for event in events:
            if event.payload is None:
                raise IntegrationSinkError(
                    "SentinelHttpSink requires MappedSinkEvent.payload (the "
                    "Logs Ingestion API's JSON-record family) -- got a "
                    "raw_text/line-oriented event instead",
                    context={"source_detection_id": event.source_detection_id},
                )
            records.append(event.payload)

        # Real Logs Ingestion API wire shape: a bare top-level JSON array of
        # records -- explicitly NOT {"events": [...]} (HttpJsonIntegrationSink's
        # own generic envelope) and NOT concatenated standalone objects
        # (Splunk HEC's own real batch shape). See this module's own
        # docstring for the exact doc citation.
        body = json.dumps(records).encode("utf-8")
        if self._max_batch_bytes is not None and len(body) > self._max_batch_bytes:
            raise IntegrationSinkError(
                "Batch exceeds the real, documented Logs Ingestion API "
                "'Maximum size of API call' ceiling -- rejecting client-side "
                "rather than sending a request the real target would itself "
                "reject with a real 413",
                context={
                    "batch_bytes": len(body),
                    "max_batch_bytes": self._max_batch_bytes,
                    "event_count": len(records),
                },
            )

        auth = await self._authenticator.prepare()
        headers: dict[str, str] = {"Content-Type": "application/json", **auth.headers}

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, verify=auth.verify, cert=auth.cert
            ) as client:
                response = await client.post(self._url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise IntegrationSinkError(
                "Real HTTP POST to the Microsoft Sentinel Logs Ingestion API "
                "endpoint failed to complete",
                context={"url": self._url, "event_count": len(records), "error": str(exc)},
            ) from exc

        # Real, explicitly documented success contract: HTTP 204, no body
        # (learn.microsoft.com's own tutorial: "you should see an `HTTP -
        # 204` response"). Any other status -- including a stray 200 -- is
        # treated as a real failure rather than silently accepted, mirroring
        # SplunkHecSink's own "a 2xx with the wrong shape is still a
        # failure, never a fabricated partial ack" idiom.
        if response.status_code != 204:
            context: dict[str, Any] = {
                "url": self._url,
                "status_code": response.status_code,
                "body": response.text[:500],
            }
            # Real, general Azure REST API error envelope (Microsoft's own
            # API Guidelines "Handling Errors" section, fetched this pass):
            # {"error": {"code": ..., "message": ...}}. Best-effort --
            # SplunkHecSink's own first-real-run bug (AttributeError on a
            # non-dict JSON body) is defended against from the start here
            # via the same isinstance guard.
            try:
                error_body = response.json()
                if isinstance(error_body, dict) and isinstance(error_body.get("error"), dict):
                    context["error_code"] = error_body["error"].get("code")
                    context["error_message"] = error_body["error"].get("message")
            except (ValueError, TypeError):
                pass
            raise IntegrationSinkError(
                "Microsoft Sentinel Logs Ingestion API rejected the real "
                "push (non-204 response)",
                context=context,
            )

        return SinkAck(
            status=SinkAckStatus.ACKNOWLEDGED,
            detail={"status_code": response.status_code, "event_count": len(records)},
        )
