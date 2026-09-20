# Gap Audit — Milestone RR (2026-08-23)

Continuation of the JJ-QQ gap-audit chain (docs/GAP_AUDIT_2026-08-23_MILESTONE_QQ.md).
This pass covered all 15 Postgres repositories in `src/adapter/repository/`,
testing `access-management-review.md`'s own claim ("every repository scopes
its own query by org_id in the WHERE clause") file-by-file rather than
trusting the description. Frontend and the remaining named application
services were not reached this pass — see Recommendation.

---

## 1. 12 of 15 repositories reviewed, no gap

Full direct read of `postgres_quota.py`, `postgres_source_cursor.py`,
`postgres_dead_letter.py`, `postgres_artifact.py`, `postgres_asset.py`,
`postgres_sealed_batch.py`, `postgres_detection_correlation.py`,
`postgres_integration_source_key.py`, `postgres_case.py`,
`postgres_detection.py`, `postgres_evidence.py`. Every query, update, and
delete in these files correctly scopes by `org_id` (or an equivalent
already-org-verified compound key). Confirmed `get_by_key()`-style methods
that intentionally omit `org_id` (`IntegrationSourceKeyRepository
.get_by_key`) are structurally different: they *resolve* an identity from
an opaque, hashed credential rather than fetching a known resource, so
`org_id` is legitimately an output, not a missing input. Cross-org
`stream_all_*` methods (`stream_all_by_state`, `stream_all_quota_held`) are
correctly documented and restricted to system beat tasks per CLAUDE.md §E.5.

---

## 2. `list_versions()`/`delete_publication()` missing defense-in-depth org scoping — FIXED

**Finding.** `RulePackRepository.list_versions()`, `YaraRulePackRepository
.list_versions()`, and `IOCFeedRepository.list_versions()` each took only a
`pack_id`/`feed_id`, with no `org_id` — unlike every sibling method on the
exact same classes (`get_latest_version`, `get_published_version`,
`get_published_opensearch_id`), which already take `org_id` and explicitly
document it as "defense-in-depth org scoping, mirrors
`DetectionRepository.get_by_id`". `RulePackRepository.delete_publication()`
had the identical gap. `test_rule_pack_repository.py`'s/
`test_yara_rule_pack_repository.py`'s own docstrings show the sibling
methods were deliberately hardened for exactly this class of gap in a
prior pass (P2-SEC-3/P2-W10) — `list_versions`/`delete_publication` were
simply missed then, not a deliberate design choice.

Confirmed via repo-wide grep that neither method is reachable from any
FastAPI route today (`RulePackService`/`YaraRulePackService`/
`IOCFeedRepository` have no route callers at all) — not a live,
exploitable cross-tenant leak today. But the class's own header docstring
promises "Org-scoped... persistence" as its whole contract, and the
repository layer is exactly where CLAUDE.md §G.3's "org_id always
server-derived, defense-in-depth" invariant is supposed to hold even if an
upper layer's own check is buggy or absent — leaving these two methods
unscoped would become a real, silent cross-tenant read/delete (another
org's custom Sigma/YARA rule content, or IOC feed version history) the
moment a route is wired to them without separately re-deriving a check.

**Fix.** Added `org_id` to `list_versions()` across all three repository
ABCs + their InMemory/Postgres implementations, and `delete_publication()`
on `RulePackRepository`, filtering every query/check by `org_id`. Updated
the two real call sites (`RulePackService.list_versions`,
`YaraRulePackService.list_versions`, plus `YaraRulePackService
.publish_version`'s internal `list_versions` call — already safe by
construction since its `pack_id` always comes from
`get_or_create_pack(tenant, ...)`, but needed the new parameter threaded
through regardless).

**Tests.** Added cross-org-isolation regression tests for all three
`list_versions` implementations and `delete_publication`, mirroring the
existing `get_latest_version_cross_org_isolation` pattern. Verified via
`git stash` that all four new tests fail against the pre-fix source
(`TypeError: takes 2 positional arguments but 3 were given`) and pass with
the fix.

**Verification.** Full suite: **2035 passed, 2 skipped** (2031 → 2035, +4
new tests). Coverage 90.26% (gate 80%). `ruff`/`black` clean (black also
incidentally reformatted pre-existing long lines in touched files, unrelated
to this change). `mypy` repo-wide: 29 errors, identical to the pre-existing
baseline, zero new. Committed as `8dc63c0`.

---

## 3. `postgres_audit_log.py`/`audit_log.py` reviewed — one real finding, deliberately NOT fixed this pass (documented instead)

`AuditLogRepository.stream_by_case(case_id)` and `.stream_by_evidence
(evidence_id)` (the ABC and its one real implementation,
`PostgresAuditLogRepository`) also take no `org_id` — the same shape as
section 2's finding. Investigated for a live exploit path before deciding
whether to fix immediately:

- `stream_by_evidence` has **zero real callers** anywhere in `src/`.
- `stream_by_case` has **exactly one real caller**:
  `GET /{case_id}/audit` (`src/external/routes/cases.py:476`, via
  `audit_svc._repository.stream_by_case(case_id)` — reaching past
  `AuditLogService`'s own public interface directly into its private
  `_repository`, itself worth cleaning up separately). That route already
  (a) calls `case_repo.get_by_id(case_id, tenant.org_id)` first and 404s if
  the case isn't the caller's own org's, **and** (b) redundantly filters
  `if ev.org_id != tenant.org_id: continue` on every yielded event before
  using it. So this specific call site is double-protected today — not a
  live gap, unlike section 2's finding, which had zero protection anywhere.

**Why not fixed in this same pass:** `AuditLogRepository`/`AnchorRepository`
is one of the most pervasively-depended-on abstractions in the codebase —
`InMemoryAuditLogRepository` (`tests/conftest.py`) is a shared fixture
referenced by 40+ test files (`grep` count), since `AuditLogService` is
injected into nearly every application-layer service under test. Changing
`stream_by_case`/`stream_by_evidence`'s signature is a correct, real
defense-in-depth improvement (mirrors section 2 exactly), but is a
meaningfully larger, higher-blast-radius change than this pass's other
fixes, and — critically — is not fixing a live vulnerability today (unlike
section 2, which had genuinely zero protection anywhere). Per this
initiative's own established discipline (small well-understood fixes done
directly; anything substantial enough to warrant broader verification gets
its own dedicated pass), this is the right size for a **dedicated** future
milestone item, not a rushed addition to this one. Documented here so it
isn't rediscovered from scratch.

---

## Recommendation for the next wake-up cycle

1. **`stream_by_case`/`stream_by_evidence` org-scoping hardening**
   (section 3 above) — a real, well-scoped defense-in-depth fix, sized for
   its own milestone pass given the ~40-file test blast radius. Also worth
   fixing in the same pass: `cases.py:476`'s `audit_svc._repository`
   access reaches past `AuditLogService`'s own public interface; either add
   a proper `AuditLogService.stream_by_case()`-equivalent method or confirm
   there's a reason it was bypassed.
2. Frontend route/component layer (`frontend/src/`) — still not reached by
   a security/correctness direct-read pass (only UX-gap-focused review in
   Milestones KK/MM).
3. `src/application/*.py` files not yet named in any prior milestone doc:
   `asset_enrichment.py`, `ioc_enrichment.py`, `ioc_feed_ingestion.py`,
   `stix_ioc_parser.py`, `yara_rules.py`, `cost_gate.py`,
   `sealing_trigger_policy.py`.

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
