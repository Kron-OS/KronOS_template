# Gap Audit — Milestone TT (2026-08-24)

Continuation of the JJ-SS gap-audit chain (docs/GAP_AUDIT_2026-08-23_MILESTONE_SS.md).
This pass finished the frontend API-module review and covered the largest
remaining page/component files.

---

## 1. Frontend API modules reviewed, no gap

Full direct read of `connectors.ts`, `cases.ts`, `detections.ts`,
`admin.ts`, `containment.ts`, `evidence.ts`. The first four are trivial
thin wrappers around `apiClient` with no client-side logic to get wrong —
org/tenant scoping is entirely server-side, and every id is passed through
untouched. `containment.ts` correctly documents the step-up ticket
contract (a ticket's `resourceId` must match the exact resource the
guarded action later checks it against — Milestone JJ's own fix).
`evidence.ts`'s `filenameFromContentDisposition`/`downloadEvidence` were
cross-checked against the real server-side header format
(`_http_helpers.py`'s sanitizer, Milestone DD1) and confirmed compatible.

---

## 2. `UploadDrawer.tsx`: client-side upload pre-check rejected real `.tar` evidence files — FIXED

**Finding.** `validateFileMagic()` — a client-side UX pre-check only (the
real, enforced boundary is the backend's `MagicByteValidator`,
`src/application/validation.py`) — is a function that has already drifted
out of sync with real backend parser support twice before, both
documented inline in the function itself (SCCA prefetch, EWF). This is the
third instance: no check existed for the POSIX `ustar` tar magic
signature, and `.tar` was missing from the allowed-extensions fallback
list, even though the backend has a full, dedicated `TarArchiveParser`,
and `validation.py`'s own `_MAGIC_TABLE` already checks for exactly this
signature at the real, fixed header offset 257. A real `.tar` file —
including the exact roadmap E1 scenario referenced throughout this
session's earlier parser review (a `forensic2.E01`-named evidence file
that was actually a tar of `image.dd` + `memory.dmp`) — was rejected
client-side with `"Unsupported extension: .tar"` before ever reaching the
server, which fully supports it.

**Fix.** Added the `ustar` magic-byte check (bytes 257–261) alongside the
existing checks, and added `'tar'` to the allowed-extensions fallback,
mirroring the existing checks' own shape exactly. Also extracted
`validateFileMagic()`/`BLOCKED_EXTENSIONS` out of `UploadDrawer.tsx` into a
new `frontend/src/utils/validateFileMagic.ts` module — exporting a
non-component function from a component file broke React Fast Refresh (a
new `oxlint` `react(only-export-components)` warning), and this codebase
already keeps pure logic like this in `utils/` (`jwt.ts`,
`parseTenantContext.ts`).

**Tests.** New `frontend/src/__tests__/validateFileMagic.test.ts` (zero
prior coverage for this function). Confirms a real `ustar` header is
accepted regardless of extension (including a GNU-tar-style mislabeled
`.E01`, mirroring the exact roadmap scenario), and that
unrecognized/blocked extensions are still correctly rejected. Verified via
`git stash` that the tar-specific assertions cannot pass against the
pre-fix source (the function wasn't even exported yet).

**Verification.** Full frontend suite: **93 passed** (88 → 93, +5 new
tests). `oxlint` clean (no new warnings). `tsc -b` clean, `vite build`
succeeds. Committed as `06941a8`.

---

## 3. `AdminPage.tsx`/`CaseDetailPage.tsx`/`ContainmentPanel.tsx` reviewed

- `AdminPage.tsx`: `generatePassword()` correctly uses
  `crypto.getRandomValues` (never `Math.random()`), guarantees at least one
  character from each of 4 character classes, and shuffles with a
  correctly-implemented Fisher-Yates. No bug. **Minor UX gap noted, not
  fixed this pass** (out of this session's security/correctness charter,
  squarely UX-review territory already covered by Milestones KK/MM):
  `UserRow`'s role-change and remove mutations have no `onError` handling
  at all, unlike `InviteModal`'s own `mutation.isError` banner — a failed
  role change or removal fails silently with no feedback, just a quiet
  revert to the prior displayed value.
- `CaseDetailPage.tsx`: the `TimelineTab`'s embedded Dashboards `<iframe>`
  uses `sandbox="allow-same-origin allow-scripts allow-forms allow-popups"`
  — the `allow-same-origin` + `allow-scripts` combination is a well-known
  general anti-pattern (together they can let iframe content strip its own
  sandbox restrictions). Checked whether this is a live gap: the URL is
  gated first by `isTrustedDashboardsUrl()`, already documented (`FE-6`)
  as a deliberate defense-in-depth check with the real trust boundary
  being the backend's own auth/org-scoping on
  `GET /api/cases/{id}/dashboard-url` — not a fresh finding, and the
  sandbox combination itself is a reasonable, unavoidable requirement for
  embedding a first-party, cookie-authenticated SPA like OpenSearch
  Dashboards. No new gap.
- `ContainmentPanel.tsx`: correctly clears a pending step-up ticket
  whenever `userId`/`sessionId` changes (preventing a ticket minted for
  one resource being reused against a different one) and after a
  successful revoke (tickets are single-use). Matches its own existing
  test coverage. No new gap.

---

## Recommendation for the next wake-up cycle

The frontend layer has now had a full security/correctness pass across
`api/*.ts`, the auth stack (`keycloak.ts`/`store/auth.ts`/`utils/*`), and
the largest page/component files. Reasonable next candidates:

1. `src/application/*.py` files not yet named in any prior milestone doc:
   `asset_enrichment.py`, `ioc_enrichment.py`, `ioc_feed_ingestion.py`,
   `stix_ioc_parser.py`, `yara_rules.py`, `cost_gate.py`,
   `sealing_trigger_policy.py`.
2. The remaining, smaller frontend page/component files not read this
   pass: `ConnectorStatusPage.tsx`, `DetectionsPage.tsx`, `CasesPage.tsx`,
   `DetectionDetailPage.tsx`, `Layout.tsx`, `ErrorBoundary.tsx`.
3. (Lower priority, UX-focused, not this session's charter) `AdminPage.tsx`'s
   missing error feedback on role-change/remove-user mutation failure —
   revisit in a future UX-gap pass (Milestone KK/MM's own lineage), not a
   security/correctness item.

Also still open from prior milestones, unchanged:
1. The lower-value optional SIEM/EDR secrets
   (`splunk_hec_token`/`sentinel_client_secret`/`defender_client_secret`)
   confirmed to degrade safely with `secrets_dir` but not yet moved off
   plaintext `environment:` in `docker-compose.prod.yml`.
2. Keycloak's own `KC_DB_PASSWORD`/`KC_ADMIN_PASSWORD` — no native
   file-secret convention exists in Keycloak 26.x itself.
3. The Postgres sync-replica ops-policy decision
   (`docs/POSTGRES_MINIO_HA_RESEARCH.md` §1.6) remains open for the
   project owner.
