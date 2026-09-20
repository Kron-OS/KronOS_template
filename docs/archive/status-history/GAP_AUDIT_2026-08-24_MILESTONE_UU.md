# Gap Audit — Milestone UU (2026-08-24)

Continuation of the JJ-TT gap-audit chain (docs/GAP_AUDIT_2026-08-24_MILESTONE_TT.md).
This pass covered all of Milestone UU's named candidates: the remaining
seven `src/application/*.py` files and the remaining six named frontend
page/component files.

---

## 1. Remaining seven `src/application/*.py` files reviewed, no gap

Full direct read of `asset_enrichment.py`, `ioc_enrichment.py`,
`ioc_feed_ingestion.py`, `stix_ioc_parser.py`, `yara_rules.py`,
`cost_gate.py`, `sealing_trigger_policy.py`. Highlights:

- `stix_ioc_parser.py` — real, careful untrusted-input handling: hand-written
  fixed regexes (never `eval`/a general STIX pattern evaluator) for the
  exact comparison-expression shapes real threat-intel indicators use,
  every regex `fullmatch`-anchored so a crafted suffix can't smuggle extra
  content, and hard caps on bundle size/object count/pattern length
  enforced *before* any regex runs against untrusted text (closing the
  ReDoS/memory-exhaustion angle).
- `cost_gate.py` — uses `yaml.safe_load` (never the unsafe `yaml.load`);
  its two heuristics' "confirmed against the real live OpenSearch 2.11.1
  cluster" claims for which Sigma modifiers compile to expensive leading-
  wildcard/unanchored-regex queries are consistent with this session's own
  earlier-reviewed `detector_provisioner.py`/`custom_rule_client.py`
  findings.
- `yara_rules.py` — the `yara_scan_org_var` `ContextVar` (how org scoping
  reaches a process-wide singleton parser registry's zero-argument
  `get_rule_source()` call) is set/reset with a proper `Token`, and
  independently confirmed the `set()`/`reset()` pair in
  `parsing_orchestration.py` is correctly wrapped in `try/finally` — no
  context-leak risk across orgs within the same worker process.
- `asset_enrichment.py`/`ioc_enrichment.py`/`ioc_feed_ingestion.py`/
  `sealing_trigger_policy.py` — all small, correctly org-scoped, no issues.

No new gap found in any of the seven.

---

## 2. Remaining six named frontend files reviewed, no gap

Full direct read of `ConnectorStatusPage.tsx`, `DetectionsPage.tsx`,
`CasesPage.tsx`, `DetectionDetailPage.tsx`, `Layout.tsx`,
`ErrorBoundary.tsx`. One specific cross-check performed given this
session's own established pattern of finding client/server drift bugs:
`utils/triageFsm.ts`'s `VALID_TRANSITIONS` table was diffed against the
real backend FSM (`src/domain/detection.py`'s `_VALID_TRANSITIONS`) —
confirmed **byte-for-byte identical**, no drift. `ErrorBoundary.tsx`
deliberately never renders the raw error message/stack to the end user
(a real, deliberate information-disclosure-avoidance choice for a
forensics product), logging via `console.error` only. `Layout.tsx`'s
admin-only nav links are correctly cosmetic (real enforcement is
server-side + `RbacGuard` on the route itself).

No new gap found in any of the six. This closes out Milestone UU's own
named candidate list with no new findings — a genuine diminishing-returns
result after four consecutive milestones (RR, SS, TT, UU) that each found
real, if sometimes minor, issues in the frontend and application layers.

---

## Recommendation for the next wake-up cycle

The application-service and frontend layers have now had a thorough
security/correctness pass across nearly every file in `src/application/`
and `frontend/src/`. Fresh, never-named-in-any-gap-audit-doc candidates
for the next milestone (confirmed via a repo-wide grep against every
`docs/GAP_AUDIT*.md`):

1. `src/adapter/keycloak/admin_client.py` — the real Keycloak Admin REST
   client (`HttpxKeycloakAdminClient`), used by both `admin.py`'s routes
   and `celery_streaming.py`'s org-alias resolution; never had a dedicated
   full-file review pass of its own (only referenced in passing).
2. `src/adapter/signing/cosign_verifier.py` — the real Cosign signature
   verification adapter backing `RulePackService`/`YaraRulePackService`
   `.import_signed_pack()`'s "fails closed on an invalid/tampered/unsigned
   pack" guarantee reviewed this pass; the verifier itself hasn't been
   independently read.
3. `src/adapter/storage/local.py`/`sealed_batch_storage.py` — the local
   (dev/test) evidence storage backend and the sealed-batch WORM storage
   adapter; `s3.py` (the real production `EvidenceStorage`) has had
   scattered attention across many milestones, these siblings have not.

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
4. (Lower priority, UX-focused, not a security/correctness item)
   `AdminPage.tsx`'s `UserRow` role-change/remove-user mutations have no
   `onError` handling, unlike `InviteModal`'s own `mutation.isError`
   banner — noted in Milestone TT, still unaddressed, still deliberately
   out of this audit chain's charter.
