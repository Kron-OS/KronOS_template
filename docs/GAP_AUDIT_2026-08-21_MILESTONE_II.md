# Gap Audit — Milestone II (continuation, 2026-08-21)

Follow-up to `docs/GAP_AUDIT_2026-08-21_MILESTONE_HH.md` (Milestone HH,
clean review). HH's own execution plan named two unreviewed areas: the
core domain/application layers (evidence intake specifically) and the
frontend. This pass covered both.

---

## Areas reviewed this pass, no new gap found

- **`src/application/evidence_intake.py`** (805 lines — the core
  chain-of-custody pipeline): read `request_upload`, `start_intake`,
  `process_intake`, `_run_hash`, `delete_evidence`, `set_legal_hold` in
  full. `_cap_stream()` re-enforces the real max-upload-byte ceiling
  server-side regardless of the client's declared size (an under-declared
  upload can't bypass the cap); every lookup is tenant-scoped
  (`get_by_id(id, tenant.org_id)`); a SHA-256 mismatch is a hard,
  audited failure, never silently accepted; TSA anchoring failures are
  logged, never fabricated; `delete_evidence`/`set_legal_hold` correctly
  check legal-hold and Object Lock retention before allowing a purge, with
  a real, honest audit trail on both grant and denial. The MinIO object
  key (`org_alias/case_id/evidence_id/original_filename`) has its first
  three, trust-bearing segments always server-derived — a crafted
  filename in the last segment can't escape into another key's namespace
  (S3/MinIO keys are an opaque flat string space, not filesystem paths
  with real traversal semantics, unlike FF1's local-filesystem
  `artifact_path` finding).
- **Frontend, `frontend/src/`:** zero `dangerouslySetInnerHTML` usage
  anywhere (confirmed by grep) — React's default JSX escaping covers all
  rendering, no hand-rolled HTML injection surface exists. Zero
  `eval`/`new Function` usage. Token storage is already correctly
  hardened by design: `keycloak.ts`'s own comment and an existing test
  (`__tests__/keycloak.test.ts`, "never writes any token to sessionStorage
  or localStorage") confirm tokens live in memory only —
  `localStorage`'s only real user is the dark-mode theme preference, a
  non-sensitive value. The one dynamic `href`/iframe `src` in the
  codebase (`CaseDetailPage.tsx`'s embedded Dashboards link) is gated by
  `isTrustedDashboardsUrl()`, which is itself honestly self-documented as
  defense-in-depth (falls back to permissive if
  `VITE_OPENSEARCH_DASHBOARDS_ORIGIN` isn't configured at build time) —
  the real trust boundary is correctly identified as the backend's own
  tenant-scoped `GET /api/cases/{id}/dashboard-url` route, not this
  client-side check, and that route already follows the same
  `get_by_id(case_id, tenant.org_id)` pattern verified solid elsewhere
  this session.

**Honest conclusion for this pass:** no new actionable gap found — the
fourth consecutive clean review (after Milestone GG's sources, HH's
sinks, and this pass's own evidence-intake read, now joined by the
frontend). This is a genuinely different attack surface than the prior
three passes (client-side XSS/storage vs. backend SSRF/injection/tenant-
scoping), and it is also solid.

---

## Strategy reconsideration (per Milestone HH's own note)

Four consecutive clean reviews is a real signal, not just bad luck: this
initiative's own direct-review method has now covered — across this
session and the milestones immediately preceding it — the evidence
download/upload paths (X1, DD1: **one real bug found**), the
`kronos-attest` CLI (AA1/BB1/CC1: **one gap closed at each of three
stages**), the SOAR/response subsystem (H2/H3/H4, EE1/FF1: **one real
security gap found**), the full integration connector layer, source and
sink (GG/HH: clean), the core evidence-intake service (this pass: clean),
and a frontend security spot-check (this pass: clean). The pattern is
consistent: real bugs turned up in code that had **never been
independently reviewed by anyone other than the agent who originally
wrote it** (X1, the kronos-attest live-mode additions, H2/H3's own
unwired actions) — every area that had *already* been through this same
kind of direct, skeptical re-read (H1's core, H4's ticketing sink, the
connector layer, evidence-intake) has come back clean, because it had
already absorbed scrutiny through its own original, unusually rigorous
build process (real PoCs, real captured output, extensive doc citations
— CLAUDE.md §F's own discipline, applied consistently since this
codebase's inception).

**Recommendation for the next wake-up cycle:** the marginal value of
continuing to cold-read more already-mature files is now genuinely
declining. Two better uses of the next cycle, in priority order:
1. **A second full multi-scenario assessment**, mirroring Task #14's own
   original structure (incident-response walkthrough, security/red-team
   review, UX/onboarding review, scale/reliability review) — but scoped
   to everything that has landed *since* that original assessment
   (Milestones W through II, roughly 30 real, substantive changes). A
   fresh, structured multi-angle review of the delta is more likely to
   surface something a single-file read won't (e.g. an interaction
   *between* two independently-solid pieces, which is exactly the shape
   FF1's own finding took — not a bug in H3 alone, but in what H3 would
   become if EE1's own pattern were blindly reapplied to it).
2. Pick up one of the two remaining, already-identified, currently-blocked
   items honestly rather than manufacturing more review busywork:
   `charts/kronos/files/nginx.conf.template`'s Helm sync (small,
   mechanical, genuinely low value but real) — the prod OpenSearch
   demo-cert gap still needs a project-owner decision this initiative
   cannot make unilaterally.

This document does not itself commit to either path — it hands the
decision to whichever wake-up picks up the next task, with the reasoning
laid out so that choice is informed rather than a coin flip.
