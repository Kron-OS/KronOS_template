# Part 4 Review — Workflows and User Experience

- **Date:** 2026-06-16
- **Spec section reviewed:** `Project_Specifications.md` §4
- **Tracking issues:** #4 (category), #15 (today's review)
- **Branch:** `claude/zen-cerf-7gt41s`

---

## 1. What the spec currently says

The spec proposes:

1. **Case lifecycle** — Org Admin or Case Lead creates a case (name, description, reference); team members can then upload evidence.
2. **Evidence processing flow** — UI shows the file walking through states `Uploading → Received → Parsing → Ingesting → Complete`, with "progress indicator or at least a spinner and status text", and ideally a percentage for long parses.
3. **Timeline analysis = OpenSearch Dashboards** — rather than building a bespoke timeline UI, surface OpenSearch Dashboards either embedded in an iframe or via a new tab. Index pattern per case (`case_alpha_*`). SSO so the user does not re-login. Eventually a custom JS app (à la Harfanglab's network-graph view).
4. **Three main views** — Cases List / Dashboard, Case Detail (evidence list, statuses), Timeline (link/embed into Dashboards). Plus an Org Admin section (already touched by §1).
5. **Collaboration** — multiple analysts on the same case at the same time; using Dashboards means independent filters per user without interference.
6. **Error UX** — surface a short, sanitised reason ("Parse failed: invalid format"), retry button, no stack traces.

---

## 2. Work already done in the repo

| Artifact                                         | Status                                                                  |
| ------------------------------------------------ | ----------------------------------------------------------------------- |
| `Project_Specifications.md` §4                   | Narrative only — no wireframes, no component list, no contract          |
| Frontend skeleton (React / Vue / Svelte / …)     | None                                                                    |
| API routes for case / evidence views             | None                                                                    |
| OpenSearch Dashboards configuration              | None — not provisioned, no per-case index-pattern automation            |
| Real-time status channel (poll / SSE / WS)       | None — open question, the spec only says "spinner"                      |
| Error catalogue (parse / ingest / scan)          | Mentioned by §2 (`evidence.error_reason`) but no UI mapping             |

**Conclusion:** §4 is at the "intent / outline" stage. Hand-off inputs are well-defined now: §1 gives the auth/tenant model, §2 gives the upload protocol + evidence FSM, §3 gives the ECS-shaped events under `kronos-{org_alias}-case-{case_id}-{yyyymm}`. §4 has to fuse them into a usable web app.

---

## 3. Feasibility research (state of the art, 2026)

### 3.1 Embedding OpenSearch Dashboards in an iframe

- OpenSearch Dashboards exposes a "Share → Embed Code" action that emits an `<iframe src="…?embed=true&…">` URL. Setting `show-top-menu=false` / `show-query-input=false` / `show-time-filter=false` hides the chrome we don't want analysts to touch.[^os-embed]
- The default OpenSearch Dashboards build sets **no** `X-Frame-Options` header and **no** CSP `frame-ancestors`, which means clickjacking is wide open out of the box. The community RFC #5639 explicitly tracks this gap.[^os-clickjack] Production deployments MUST add CSP `frame-ancestors 'self' https://app.kronos.example` at the reverse-proxy layer (NGINX) before exposing the iframe — otherwise our app embeds OS Dashboards but every other page on the internet can too.
- Cross-origin embedding requires the reverse proxy to also send `Access-Control-Allow-Origin` for the embed assets and to forward the **session cookie**. When OS Dashboards is served on a different sub-domain (`dashboards.kronos.example` vs `app.kronos.example`), the iframe cookie must be `SameSite=None; Secure; Partitioned` (CHIPS) so Chrome 130+ still sends it inside the iframe.[^chips]

### 3.2 SSO handoff from our SPA to Dashboards

- The reliable flow is: the analyst is already authenticated against Keycloak in our SPA (§1, §6). When they click "Open Timeline", we navigate the iframe to `https://dashboards.kronos.example/app/discover#/?_g=(filters:!())&…`. Dashboards is configured as an OIDC RP against the same Keycloak realm (cf. `cht42/opensearch-keycloak`). Because Keycloak already issued the SSO session cookie on first login, the Dashboards OIDC dance completes silently — no second password prompt.[^cht42][^os-keycloak]
- The OS Security plugin maps the JWT `roles` claim to OS roles via `roles_key` (already fixed in §1: flat `roles` claim mandatory). Document-level security on `tenant_id` + `case_id` gives the analyst exactly the indices they can see, which sidesteps OS Dashboards' built-in multi-tenancy entirely.
- Common failure mode (Dashboards' `bypass-sign-in` forum thread): if the iframe lands on the OS login page instead of the dashboard, it is almost always because (a) the JWT auth domain is not the **first** auth domain, or (b) third-party cookies are blocked.[^os-bypass]

### 3.3 Dashboards multi-tenancy vs index-pattern-per-case

- OS Dashboards' built-in multi-tenancy gives each tenant a private space for saved objects (`.kibana_<hash>_<tenant>`). It is designed for tenants ≈ teams, **not** tenants ≈ cases.[^os-mt]
- For Kron-OS the natural unit is the **case**, and an org may run hundreds of cases. Creating one OS tenant per case would explode `.kibana_*` index count.
- The correct pattern: **one OS tenant per org** (`kronos-{org_alias}`), then **per-case index patterns** inside that tenant. Saved searches, dashboards, and Lens visualisations live in the org tenant and reference indices through wildcards (`kronos-{org_alias}-case-{case_id}-*`). The case_id filter is injected by our SPA as a locked URL parameter (`_g=(filters:!((meta:(disabled:!f,key:kronos.case_id),query:(match_phrase:(kronos.case_id:'b2a9…'))))))`.[^os-mt][^os-mt-idx]

### 3.4 Real-time status updates — SSE vs WebSocket vs polling

- The status stream is **unidirectional** (server → client) and low-volume (one event per FSM transition, plus optional percent-progress on long parses). That is the textbook SSE use case.[^sse-vs-ws]
- WebSocket is overkill: we don't need client → server messages on this channel, and WS authentication is materially harder behind corporate proxies. SSE rides plain HTTP/2 and survives corporate proxies that strip the `Upgrade` header.[^sse-vs-ws]
- **EventSource auth caveat:** the W3C `EventSource` API does not allow custom headers, so the `Authorization: Bearer <jwt>` header pattern we use on REST calls does not work. Three workable options:
  - (a) `EventSource(url, { withCredentials: true })` plus a same-site session cookie minted by the backend at SPA load time.[^sse-auth]
  - (b) Polyfill (`@microsoft/fetch-event-source`) that lets us set custom headers — adds a JS dependency but reuses our existing Bearer JWT.
  - (c) Short-lived one-shot token in the URL (`/sse/cases/{id}/status?ticket=…`) minted by `POST /sse/ticket`. Acceptable for v1, the ticket TTL is 60 s.
- Polling fallback (one `GET /cases/{id}/evidence` every 5 s) is still required for environments where SSE is blocked (some inline DLP proxies break long-running responses). The SPA detects after 10 s of `readyState=CONNECTING` and falls back to polling automatically.

### 3.5 Resumable upload UX

- Native `<input type="file">` + `fetch()` does not survive a network blip on a 1 GB upload; we promised resumable in §2. Two production-grade React libraries do this well:
  - **Uppy** — full uploader UI, drag-drop, batch, native `tus.io` and S3 multipart plugins, accurate per-chunk progress.[^uppy] Heaviest bundle (~120 KB gz).
  - **FilePond + chunk plugin** — smaller (~45 KB gz), tus-compatible, but the UI is less rich and the API for parallel multi-file is more manual.[^filepond]
  - **react-dropzone + tus-js-client** — fully bespoke UI; most flexible but we own all the state machine.
- Recommended for v1: **Uppy** with its `@uppy/aws-s3-multipart` plugin (primary path — presigned URLs from §2's `POST /evidence`) and the `@uppy/tus` plugin as fallback (matches §2's tusd fallback). Uppy emits per-chunk progress events, which we surface in the evidence row's progress bar.

### 3.6 Multi-analyst collaboration

- Two distinct levels of "collaboration" must not be conflated:
  - **Independent analysis** — two analysts open the same case in OpenSearch Dashboards. Each has their own URL/filter state; they don't step on each other. OS Dashboards already handles this with per-user transient state.
  - **True co-presence** (shared cursor, live annotations, "Alice tagged event X") — needs a CRDT/presence backend like Yjs + Liveblocks/Hocuspocus.[^crdt-2026][^liveblocks] This is materially more complex (sync server, conflict resolution, annotation index) and is **out of scope for v1**. Timesketch's tagging/story model would be the v2 north star.
- Concretely, v1 ships only the independent-analysis level: each analyst has their own Dashboards iframe; case-level annotations (notes, tags, bookmarks) are **not** in v1.

### 3.7 Error surface UX

- The spec says "Parse failed: invalid format" without exposing stack traces. Concretely we need a small **error catalogue** mapping `evidence.error_reason` (set by §2/§3) to:
  - A short, human-friendly title.
  - A one-sentence remediation hint ("Re-export the EVTX from the source machine and re-upload").
  - A "Retry" affordance when (and only when) the FSM allows retry.
  - A "Copy diagnostic" button that copies an opaque error correlation ID — analysts can give that ID to support without us leaking internals.
- Audit log (§1 / §2) already records the underlying technical details — support reads them through the Org Admin view.

### 3.8 Live "% parsed" estimation

- The spec asks for a percentage during parsing. For text logs (CSV/NDJSON) we know `(bytes_parsed / total_bytes)` from the chunked splitter (§3.5.6). For binary forensic artefacts (EVTX, REGF, SRUM) Plaso emits per-record progress to its task manifest; we tail it and emit `progress` events on the SSE channel.
- For artefacts where Plaso does not give a reliable estimate (SQLite scans, SRUM), the UI shows an **indeterminate** progress bar plus an elapsed-time counter rather than a fake percentage.

---

## 4. Problems identified

### P1. Iframe security is wide open by default
OS Dashboards ships without `X-Frame-Options` / `frame-ancestors`. We must enforce CSP `frame-ancestors 'self' https://app.kronos.example` at the reverse-proxy layer **before** day one, otherwise we ship a clickjacking sink.

### P2. "Index pattern per case" misreads OS Dashboards' tenant model
The spec implies one Dashboards tenant per case (`case_alpha_*`). OS Dashboards tenants are designed per team, not per case. With hundreds of cases per org this would explode `.kibana_*` index count and saved-object management.

### P3. EventSource cannot carry the JWT
`Authorization: Bearer <jwt>` does not work on `EventSource`. The status channel needs a session cookie or a one-shot ticket — neither of which is acknowledged by the spec.

### P4. "Spinner or status text" is not enough UX
A 1 GB EVTX takes minutes; a stale spinner is a support-ticket generator. We need explicit status pills, a progress bar where we *do* know the bytes, and an indeterminate bar plus elapsed time where we don't.

### P5. Retry semantics are not actually defined
The spec mentions a "retry button" but §2's evidence FSM lists `ERROR` as reachable from many transitions. Which retries are safe? `SCANNING/HASHING/PARSING/INGESTING` errors are all retryable per §2; `UPLOADING` errors are not (the upload is gone). The UI must encode this.

### P6. Multi-user collaboration is hand-waved
"Multiple analysts on the same case" without specifying whether v1 supports shared annotations leaves the front-end open to a CRDT-shaped rewrite later. Commit explicitly: v1 = independent analysis only. Shared tagging = v2.

### P7. No commitment to the SPA framework / build pipeline
The spec mentions "js framework" once. Without a concrete choice (React vs Vue vs SvelteKit) we cannot reason about routing, state management, SSE client, or the Uppy integration.

### P8. The "custom front end app for OpenSearch views" promise is unscoped
The recent commit (`Add note on custom front end app for OpenSearch views`) flags Harfanglab-style visualisations as a goal but does not say when. Must be tagged as v2 (or behind a feature flag) — building a Harfanglab-grade graph UI is a 6-month project of its own.

### P9. No spec for "Case Detail" beyond a list
The Case Detail view needs to surface: case meta (name, ref, lead, members, dates), evidence list with per-row status pill / progress / retry / download / legal-hold toggle, "Open Timeline" button, an audit-log peek. The current spec only says "info and list".

### P10. Cross-origin cookies (CHIPS) break Dashboards in Chrome 130+
`SameSite=None; Secure; Partitioned` is the only cookie that survives third-party-cookie phaseout. We need NGINX to rewrite the `Set-Cookie` from OS Dashboards to add `Partitioned`, or to serve Dashboards from the **same** parent domain (`dashboards.app.kronos.example`).

---

## 5. Plan to reach the objective — detailed

### 5.1 SPA stack (v1)

- **React 19** + **TypeScript** + **Vite** for the build. Reasons: react-keycloak is mature; Uppy ships first-class React bindings; TanStack Router gives type-safe routes; TanStack Query handles cache/invalidation and works well alongside SSE for non-stream data.
- State management: TanStack Query for server state; a thin Zustand store for UI state (which case is selected, drawer open, etc.). No Redux.
- Auth: `keycloak-js` v26 with PKCE; access token kept in memory; refresh token in an HTTP-only cookie. Silent refresh via the Keycloak iframe.
- Styling: Tailwind v4 + shadcn/ui for the case list / detail / status pills.

### 5.2 Information architecture (routes)

```
/                                     → /cases
/cases                                → Cases list (org-scoped)
/cases/new                            → Case creation (org-admin, case-lead)
/cases/{caseId}                       → Case detail (evidence list, members, audit-log peek)
/cases/{caseId}/evidence/new          → Drag-and-drop upload modal (Uppy)
/cases/{caseId}/evidence/{evId}       → Evidence detail drawer (chain-of-custody)
/cases/{caseId}/timeline              → OS Dashboards iframe (case-scoped Discover)
/admin/org                            → Org admin (users, roles, retention overrides)
```

### 5.3 OpenSearch Dashboards integration

- **Tenant strategy:** one tenant per org (`kronos-{org_alias}`), **not** one per case. Saved objects (visualisations, dashboards, Lens) belong to the org tenant. Per-case filtering is done at URL-parameter time.
- **Provisioning:** when a case is created, a Celery task `provision_dashboards_index_pattern` calls the OS Dashboards saved-objects API to upsert an index pattern `kronos-{org_alias}-case-{case_id}-*` and a default Discover view scoped to that pattern.
- **Embedding URL (case timeline button):**
  ```
  https://dashboards.kronos.example/app/data-explorer/discover#/?
    embed=true
    &show-top-menu=false&show-query-input=true&show-time-filter=true
    &_g=(filters:!((meta:(disabled:!f,key:kronos.case_id),
                    query:(match_phrase:(kronos.case_id:'{caseId}'))))),
        time:(from:now-30d,to:now))
    &_a=(index:'{indexPatternId}',interval:auto,…)
  ```
- **NGINX reverse-proxy (mandatory before day one):**
  - `add_header Content-Security-Policy "frame-ancestors 'self' https://app.kronos.example" always;`
  - `add_header X-Frame-Options "SAMEORIGIN" always;` (kept as defence in depth on browsers that lag CSP support)
  - Rewrite `Set-Cookie` to append `Partitioned` (CHIPS) when OS Dashboards is on a different sub-domain.
- **OIDC RP config:** authentication domain `openid` is the **first** auth domain in `opensearch-security/config.yml`; `roles_key: roles` (matches the flat claim from §1); `subject_key: preferred_username`.

### 5.4 Evidence processing flow UI

- **Status pill mapping** (§2 FSM):

  | FSM state    | UI label              | Color                   | Progress                                                  |
  | ------------ | --------------------- | ----------------------- | --------------------------------------------------------- |
  | `UPLOADING`  | "Uploading"           | slate                   | Uppy per-chunk bytes percent                              |
  | `SCANNING`   | "Scanning (AV)"       | indigo (indeterminate)  | indeterminate bar                                         |
  | `HASHING`    | "Verifying hash"      | indigo (indeterminate)  | indeterminate bar                                         |
  | `RECEIVED`   | "Queued for parsing"  | blue                    | none                                                      |
  | `PARSING`    | "Parsing"             | amber                   | `parsed_bytes / total_bytes` when text, else indeterminate |
  | `INGESTING`  | "Ingesting"           | amber                   | `indexed_docs / parsed_records` when known                 |
  | `COMPLETE`   | "Ready"               | emerald                 | full                                                      |
  | `ERROR`      | "Error" + reason chip | red                     | retry button if FSM allows                                |
  | `PURGED`     | "Purged (retention)"  | slate (disabled)        | n/a                                                       |

- **Progress channel:** SSE endpoint `GET /sse/cases/{caseId}/evidence?ticket={shortLivedTicket}` emits:
  ```jsonc
  // evt: status
  {"evidence_id":"…","status":"PARSING","progress":{"kind":"bytes","done":314572800,"total":1073741824}}
  // evt: status
  {"evidence_id":"…","status":"COMPLETE"}
  // evt: error
  {"evidence_id":"…","reason_code":"parser_oom","retryable":true}
  ```
- **Ticket flow:** SPA calls `POST /sse/ticket` with its Bearer JWT; receives `{ticket, expires_in: 60}`; opens `EventSource(url + "?ticket=" + ticket)`. The backend keys the ticket to `(user_id, org_id, case_id)`.
- **Fallback to polling:** if `EventSource` does not reach `OPEN` within 10 s, the SPA falls back to `GET /cases/{caseId}/evidence` every 5 s. Same UI, just slower.

### 5.5 Error catalogue (v1)

| `error_reason` (§2/§3)           | UI title                | Hint                                                                 | Retry? |
| -------------------------------- | ----------------------- | -------------------------------------------------------------------- | :----: |
| `upload_hash_mismatch`           | Hash mismatch           | Try uploading again — the file may have been corrupted in transit.   |   ✔    |
| `av_infected`                    | Antivirus blocked       | The file matched a malware signature. Contact your org admin.        |   ✘    |
| `unsupported_format`             | Unsupported file type   | Allowed formats: EVTX, Prefetch, REGF, SRUM, …                       |   ✘    |
| `parser_oom`                     | Parser ran out of memory| Use the "heavy" queue or split the artefact.                         |   ✔    |
| `parser_format_error`            | File could not be parsed| The file may be corrupted. Re-export from the source machine.        |   ✔    |
| `ingest_count_mismatch`          | Ingest verification failed | Auto-retried; if it persists, contact support with the diagnostic ID. |   ✔    |
| `tsa_unreachable`                | Timestamp authority down | Custody timestamp will be retried automatically.                     | auto   |

- Every error row exposes a **diagnostic ID** = `audit_log.id` of the failing transition. Support reads the audit row for the technical detail; the analyst never sees a stack trace.

### 5.6 Case Detail view — component contract

```
<CaseHeader>
  · name, reference, status
  · lead (avatar), members (avatars), created_at
  · "Open Timeline" button   "Add Evidence" button   "..." menu (delete/archive — RBAC-gated)
</CaseHeader>
<CaseTabs>
  · Evidence (default)
  · Timeline   (re-uses /cases/{id}/timeline iframe)
  · Audit log  (paginated `audit_log` rows filtered by case_id; org-admin and case-lead only)
  · Settings   (retention override, members) — case-lead+
</CaseTabs>
<EvidenceList>
  · Row: filename, size, sha256 (truncated, click-to-copy), uploader, uploaded_at, status pill, progress
  · Hover actions: download (§1 permission matrix), legal-hold toggle (org-admin / case-lead), delete (case-lead+, before purge), retry (when ERROR + retryable)
</EvidenceList>
```

### 5.7 Collaboration semantics (v1)

- Multiple analysts can have the same case open simultaneously. Each has their own iframe and their own URL/filter state. No co-presence cursors, no shared annotations.
- A short polling loop refreshes the evidence list every 30 s so two analysts see new evidence appear without a manual refresh. SSE already pushes status transitions.
- v2 candidate (out of scope): shared tags / notes via Yjs + Hocuspocus over a `case-{caseId}` Yjs document; case-bound presence avatars.

### 5.8 Custom OpenSearch view (Harfanglab-style)

- Explicitly **v2**. v1 ships OS Dashboards Discover + a Kron-OS Lens dashboard preset (auth-events, process-tree summary, top-N hosts/users).
- v2 scope to be defined under §4 milestones — likely a React Flow / D3 graph view of process/parent-process edges read from `kronos-…-case-…-*` indices via the OS REST API. Not specced today.

### 5.9 Resumable upload integration

- `<EvidenceUploader>` uses Uppy with two plugins, configured at mount time:
  - `@uppy/aws-s3-multipart` — primary path. The plugin's `getChunkSize`, `createMultipartUpload`, `signPart`, and `completeMultipartUpload` hooks call our `POST /evidence` and `POST /evidence/{id}/complete` (§2).
  - `@uppy/tus` — fallback. Pointed at the tusd endpoint, used when the SPA detects that the primary path failed CORS / proxy-rewrite probes.
- Client-side allowlist check (extension + magic bytes via `file-type` npm package) **before** asking the backend for upload URLs — saves a round-trip for obviously-wrong files. Final enforcement still happens server-side (§2).
- Per-chunk progress drives the row's progress bar via Uppy's `upload-progress` event. On success, the SPA flips the row to `SCANNING` optimistically; the SSE channel confirms transitions thereafter.

### 5.10 Incremental milestones

| Milestone | Content                                                                                                              | Exit criterion                                                                                              |
| --------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| M4.1      | React 19 + Vite skeleton with Keycloak login, protected routes, org-scoped Cases list (read-only)                     | An analyst can log in via Keycloak and see only cases for their org                                         |
| M4.2      | Case Detail with evidence list, status pills, audit-log peek                                                          | RBAC-correct list renders; columns match §5.6                                                               |
| M4.3      | Resumable upload via Uppy (S3 multipart primary, tus.io fallback) with per-chunk progress                             | 1 GB synthetic EVTX uploads end-to-end with a paused network simulated mid-upload                           |
| M4.4      | SSE status channel + ticket auth + polling fallback                                                                   | Status pills move live; `EventSource` blocked → polling kicks in within 10 s                                |
| M4.5      | OS Dashboards iframe embed with CSP `frame-ancestors`, SSO handoff, case-id URL-param filter                          | An analyst clicks "Open Timeline" and lands on a Discover view filtered to that case, no second login       |
| M4.6      | Error catalogue + retry affordances                                                                                   | Each `error_reason` from §2/§3 renders the documented copy; retries respect the FSM                         |
| M4.7      | Org Admin view (users, roles, retention overrides, legal-hold)                                                        | Org admin can invite a user, change a role, set retention on a case                                         |
| M4.8      | Playwright E2E tests covering the upload → parse → ingest → timeline open path                                        | Green on every PR; runs against the docker-compose stack                                                    |

Each milestone lands as its own PR referencing issue #4.

---

## 6. Open questions for the reviewer

1. **SPA framework** — confirm React 19 + Vite + TanStack Router, or prefer SvelteKit/Vue for footprint reasons?
2. **Same-origin Dashboards** — host OS Dashboards on `app.kronos.example/dashboards/` (same-origin, avoids CHIPS) or on `dashboards.kronos.example` (different sub-domain, requires `Partitioned` cookie rewrite)?
3. **OS Dashboards tenant strategy** — confirm one tenant per org (not per case)?
4. **SSE auth** — short-lived ticket in URL vs same-site session cookie? (Ticket is friendlier to a pure JWT stack; cookie is friendlier to the iframe stack.)
5. **Per-case access for Read-Only** — §1 permission matrix forbids downloads for Read-Only in v1; should they still see the timeline iframe (search-only)?
6. **Live `% parsed`** — accept indeterminate progress for binary artefacts in v1, or require Plaso patch to emit reliable per-record counters?
7. **Legal Hold toggle placement** — Case Detail row hover-action vs Evidence Detail drawer only? (UX vs accidental-click risk.)
8. **Custom Harfanglab-style view** — confirmed v2 scope, or expected as part of v1.x?

---

## 7. Next-day plan

Tomorrow's review should target **Part 5 — Security and Compliance**. The reverse-proxy CSP / `frame-ancestors` requirements identified here, the SSE ticket auth, and the per-case access-control semantics all feed into §5's security control catalogue and ISO 27001 mapping. The gVisor / Firecracker parser-sandboxing question (already touched in §3) is the natural §5 owner.

---

## References

[^os-embed]: [Embed OpenSearch Dashboards using iframe — OpenSearch Forum](https://forum.opensearch.org/t/embed-opensearch-dashboards-using-iframe/14549)
[^os-clickjack]: [\[RFC\] Clickjacking Mitigation — opensearch-project/OpenSearch-Dashboards #5639](https://github.com/opensearch-project/OpenSearch-Dashboards/issues/5639)
[^os-bypass]: [Bypass sign-in to an embedded OpenSearch dashboard iframe — OpenSearch Forum](https://forum.opensearch.org/t/bypass-sign-in-to-an-embedded-opensearch-dashboard-iframe/16195)
[^os-mt]: [OpenSearch Dashboards multi-tenancy — OpenSearch Docs](https://docs.opensearch.org/latest/security/multi-tenancy/tenant-index/)
[^os-mt-idx]: [Index pattern on Tenant — OpenSearch Forum](https://forum.opensearch.org/t/index-pattern-on-tenant/24726)
[^cht42]: [cht42/opensearch-keycloak — Minimal working example](https://github.com/cht42/opensearch-keycloak)
[^os-keycloak]: [Securing OpenSearch with OIDC Integration](https://osuite.io/articles/opensearch-oidc-integration/)
[^chips]: [CHIPS — Partitioned cookies (Chrome / MDN)](https://developer.mozilla.org/en-US/docs/Web/Privacy/Privacy_sandbox/Partitioned_cookies)
[^sse-vs-ws]: [WebSockets vs Server-Sent Events: which to use in 2026 — Ably](https://ably.com/blog/websockets-vs-sse)
[^sse-auth]: [Server-Sent Events (SSE) — FastAPI docs](https://fastapi.tiangolo.com/tutorial/server-sent-events/)
[^uppy]: [Best File Upload Libraries for React in 2026 — PkgPulse](https://www.pkgpulse.com/guides/best-file-upload-libraries-react-2026)
[^filepond]: [Top JS File Upload Libraries in 2026 — Resumable.js](https://www.resumablejs.com/guides/top-js-file-upload-libraries-2026/)
[^crdt-2026]: [Multi-user Collaboration: CRDTs and Real-time syncing in 2026](https://blog.weskill.org/2026/04/multi-user-collaboration-crdts-and-real.html)
[^liveblocks]: [Liveblocks Multiplayer — Realtime collaboration](https://liveblocks.io/multiplayer)
