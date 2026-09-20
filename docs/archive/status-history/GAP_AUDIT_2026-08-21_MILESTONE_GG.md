# Gap Audit — Milestone GG (continuation, 2026-08-21)

Follow-up to `docs/GAP_AUDIT_2026-08-19_MILESTONE_FF.md` (Milestone FF,
fully resolved: FF1 CLOSED). FF's own execution plan pointed at continuing
the direct-review method on H1/H4 and the six EDR/SIEM connectors from
Milestones P/Q/R/S. This pass covered that ground.

---

## Areas reviewed this pass, no new gap found

Applying the same lens that found FF1 ("what happens if this gets used/
wired the way a prior pass wired something similar") plus a general
correctness/security read, across:

- **H4 (`src/adapter/ticketing/ticketing_system.py`,
  `src/application/ticket_sync_action.py`):** `WebhookTicketingSystem`'s
  `webhook_url` is a constructor-time value (never read from per-request
  `params`), so — unlike H3's `artifact_path` — there is no equivalent
  SSRF-via-caller-controlled-target vector even if this were wired up the
  same way H2/H3 were. `SyncDetectionTicketAction` correctly scopes its
  `Detection` lookup by `(detection_id, tenant.org_id)`, mirroring
  `SyncDetectionToSiemAction`'s own already-proven pattern. `_post()`'s
  outbound body is JSON (`httpx`'s own `json=` serialization), not raw
  headers, so no header-injection surface from `title`/`description`/
  `metadata` values either.
- **`src/external/routes/integration_source_push.py`** (the real,
  live-wired inbound webhook route every PUSH-mode `IntegrationSource`
  reaches): authentication is header-only and happens *before*
  `request.body()` is ever read, so an unauthenticated caller cannot
  trigger a body read at all. The route relies on nginx's own
  `client_max_body_size 10m` (confirmed in `docker/nginx/nginx.conf.template`)
  for body-size bounding — the same reliance every other `/api/` route
  already has, not a route-specific gap.
- **`src/external/integration_sources/generic_webhook.py`,
  `wazuh.py`, `suricata_zeek.py`:** pure JSON parsing/validation with no
  filesystem/network side effects and no unbounded recursion/resource
  concerns beyond what nginx's body cap already bounds. `SuricataEveStreamNormalizer.normalize()`
  additionally truncates `event_original` to 32KiB before storage — a
  real, existing safeguard against unbounded per-event storage growth.
- **`src/external/integration_sources/defender.py`:** `base_url` is
  Settings-derived (not caller input); pagination follows Microsoft
  Graph's own standard server-echoed `@odata.nextLink` contract, the
  identical trust model every real Graph SDK already uses — not a
  KronOS-introduced deviation.
- **H1's two example `PlaybookAction`s**
  (`src/application/playbook_actions.py`): `TransitionDetectionTriageAction`
  delegates entirely to the already-reviewed, already-tenant-scoped
  `DetectionTriageService.transition()`; `LogNotificationAction` only
  logs a caller-supplied string via structured `logger.info(...,
  extra={...})` (a field value, never interpolated into a format string
  — no log-injection surface).

**Honest conclusion for this pass:** no new actionable gap was found
beyond FF1 (already landed under Milestone FF, in the same review arc
that continues into this one). This is a legitimate, non-manufactured
outcome — this initiative's own established precedent (V9/V10's research
passes, the Kafka evaluation itself) already treats "reviewed carefully,
confirmed solid" as a valid milestone conclusion, not a failure to find
something. Manufacturing a fix where none is warranted would be worse
than reporting a clean result honestly.

---

## Execution plan

Remaining candidates, unchanged:
- The sink side of P/Q/R/S (`src/adapter/integration_sink/*.py` — Splunk
  HEC, Sentinel, syslog/CEF, the sink authenticator/batching layer) has
  not yet had this same direct-review treatment; the source side (this
  pass) and the ticketing sink (H4) are done.
- `charts/kronos/files/nginx.conf.template` Helm sync — no live
  consequence yet.
- Prod OpenSearch demo-cert gap — needs a real project-owner TLS
  decision, not attempted.

**Note on this pass's own delivery:** FF1's actual fix (the security gap
found by this same review arc) was committed under Milestone FF
(`docs/GAP_AUDIT_2026-08-19_MILESTONE_FF.md`, commit `34642c3`) in the
turn immediately preceding this one — this document records the
continuation of that same review session's remaining scope, which turned
up no further fix.
