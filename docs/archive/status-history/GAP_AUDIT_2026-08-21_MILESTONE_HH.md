# Gap Audit — Milestone HH (continuation, 2026-08-21)

Follow-up to `docs/GAP_AUDIT_2026-08-21_MILESTONE_GG.md` (Milestone GG,
fully resolved: no new gap found). GG's own execution plan pointed at the
one remaining unreviewed area from the original P/Q/R/S integration work:
the SINK side (`src/adapter/integration_sink/*.py`). This pass covered it.

---

## Areas reviewed this pass, no new gap found

- **`sink_authenticator.py`** (`NullAuthenticator`, `StaticTokenAuthenticator`,
  `ApiKeyTupleAuthenticator`, `MtlsAuthenticator`,
  `OAuth2ClientCredentialsAuthenticator`): real token caching with a
  30-second refresh margin, never fabricates/returns a stale token past
  expiry, raises rather than silently reusing an unusable response.
- **`splunk_hec_sink.py`** (`SplunkHecSink`): the most complex file in this
  layer (real HEC batch wire format, indexer-ack polling) — every real
  response is checked for its documented shape before being trusted
  (`code`/`text`, `ackId`), never a fabricated `ACKNOWLEDGED` on an
  ambiguous or malformed 2xx. `endpoint_url`/`ack_endpoint_url` are
  constructor-time values, never caller/params-supplied — no SSRF-via-params
  vector analogous to FF1's finding in H3.
- **`sentinel_sink.py`** (`SentinelHttpSink`): same construction-time-URL
  pattern; correctly treats any non-204 response (including a stray 200)
  as a real failure, matching the documented Logs Ingestion API contract.
- **`syslog_sink.py`** (`SyslogIntegrationSink`): writes only
  already-formatted `raw_text` lines — the actual escaping responsibility
  correctly lives in the mapper, not here (checked next).
- **`cef_detection_mapper.py`** (`CefDetectionMapper`): the one place a
  real CRLF-log-injection vector could plausibly hide (a `Detection`
  field embedded in a syslog line could forge additional fake log lines
  downstream). Confirmed this is already defended: both
  `_escape_header_field()` and `_escape_extension_value()` explicitly
  replace `\n`→`\\n` and `\r`→`\\r` (in addition to the CEF-spec-mandated
  backslash/pipe/equals escaping), applied to every field before it's
  embedded in the outbound line.
- **`http_json_sink.py`** (`HttpJsonIntegrationSink`): the generic R1
  foundation — same "never trust an ambiguous 2xx" discipline as the
  named-vendor sinks.
- **`batching.py`** (`chunk_events()`): correct boundary handling
  (an event that alone exceeds `max_batch_bytes` is still yielded, in its
  own chunk, for the concrete sink to reject explicitly — not silently
  dropped or force-raised at the chunking layer).

**Honest conclusion for this pass:** no new actionable gap found — the
second consecutive clean review (after Milestone GG). This sink-side
code is, on direct inspection, some of the most carefully verified in the
repository (extensive real API-doc citations, PoC cross-references, and
already-defensive patterns against exactly the classes of bug this
initiative's own direct-review method has been finding elsewhere). A
non-manufactured "reviewed, solid" outcome, matching this initiative's
own established precedent for valid research/review-only conclusions.

---

## Execution plan

With both the source side (Milestone GG) and now the sink side of the
Kafka/Integrations roadmap (P/Q/R/S) directly reviewed and found clean,
and H1-H4 (SOAR/response, Milestones EE/FF/GG) also directly reviewed
(one real fix found — FF1), the direct-review method has now covered:
X1 (evidence download — DD1 found a real bug), the kronos-attest CLI
(AA1/BB1/CC1 — one real gap found and closed at each stage), H2/H3/H4
(EE1/FF1 — one real fix), and now the full integration source+sink layer
(GG/HH — clean).

**Not yet covered by this method:** the frontend (`frontend/src/`), and
the core domain/application layers outside what X1/DD1 already touched
(evidence intake, case management, audit log core beyond what AA1/BB1/CC1
exercised). Worth a future pass if the well of doc-based findings
(already thin since Milestone CC) and connector/SOAR findings (thinning
as of this pass) continues to run dry.

Remaining low-priority/blocked candidates unchanged:
- `charts/kronos/files/nginx.conf.template` Helm sync — no live
  consequence yet.
- Prod OpenSearch demo-cert gap — needs a real project-owner TLS
  decision, not attempted.
