# Gap Audit — Milestone Z (continuation, 2026-08-18)

Follow-up to `docs/GAP_AUDIT_2026-08-17_MILESTONE_Y.md` (Milestone Y, fully
resolved: Y1/Y2 both CLOSED). Re-checked `docs/GAP_AUDIT_2026-08-17.md`'s
"still genuinely blocked" list first — none of those items (V9
customer-log-source scoping, COMP-9 live-Wazuh dependency, Volatility3's
explicit pause, real k8s/gVisor unavailability, deferred v2 features) have
become newly actionable. This pass continued Y's own method: scanning
`docs/*.md`/`poc/*/README.md` for "documented, not fixed" / "out of
scope" / "flagged, not fixed" markers and going deeper on ones with a
small, well-scoped, real fix, rather than a shallow re-scan.

---

## Z1 — Admin API `_to_http_error()`'s 404→503 fallback (V5's own real finding, never fixed)

**STATUS (2026-08-18, commit TBD): CLOSED, verified live.**

Milestone V5 (real-Keycloak integration coverage for `admin.py`'s
invite/role-change/remove routes) found and documented, but explicitly
did not fix, a real, minor bug: `_to_http_error()`
(`src/external/routes/admin.py`) only special-cased Keycloak's 400 and
409 responses; a genuine 404 (e.g. `remove_user` targeting a user who
isn't a member of the caller's org — Keycloak itself rejects the DELETE
as "not found," which is how cross-org isolation is enforced for that
route) fell through to a generic `503 Service Unavailable`. The
underlying tenant-isolation guarantee always held (the target was never
actually removed/re-roled either way) — only the surfaced HTTP status was
misleading, implying an infrastructure failure rather than "not found."

**Confirmed still live before fixing** (not assumed from the V5 doc's own
age): read `_to_http_error()` directly — the 400/409 branches were
present, no 404 branch existed, confirmed via
`poc/admin_routes_real_keycloak/output.txt`'s own standalone probe
capturing the real observed result: `remove_user(org-A-admin, cross-org
target) -> HTTPException status_code=503`.

**Fix:** added an explicit `status_code == 404` branch to
`_to_http_error()`, returning a real `404 Not Found` with a
non-disclosing message (`"User not found in this organization"` — doesn't
confirm whether the target exists at all, just that they aren't in this
org, consistent with this same function's existing AUTH-011 non-disclosure
convention for the 409 case).

**Verified end-to-end, not just unit-mocked:**
- New unit test `test_to_http_error_maps_not_found_to_404_not_503`
  (`tests/unit/test_admin_routes.py`) — 24/24 unit tests pass (was 23,
  +1 new).
- The **real** `tests/integration/test_admin_routes_real_keycloak.py::test_remove_user_cannot_remove_a_cross_org_member`
  test (real Keycloak Admin API calls, zero mocks, against the shared dev
  stack) had its own assertion **strengthened** from the old, loose
  `status_code >= 400` to the exact `status_code == 404` — re-run against
  the real dev Keycloak and passes. All 6/6 tests in that same real-Keycloak
  file still pass (no regression to the other 5).
- Full backend test suite before/after: 1954 → 1955 passed (+1, the new
  unit test), 2 skipped both times. `ruff`/`black`/`mypy` clean on all
  three changed files.

**Priority: P2** — real, already-found bug with a small, precise,
low-risk fix; not a security issue (isolation already held), but a real
UX/API-correctness improvement for org admins.

---

## What was checked and found already resolved (stale finding, doc not yet updated)

- **P2-10** (`docs/GAP_AUDIT_2026-08.md`): "playbook-driven (automated)
  triage transitions record `actor_username: 'unknown'`". Checked
  directly: the literal `"unknown"` username placeholder does not exist
  anywhere in `src/` today, and every automated `TenantContext`
  construction found (e.g. `celery_streaming.py`'s SA-findings sync cycle)
  already uses a real system-actor label (`username="celery-worker"`).
  This appears to have been resolved incidentally by later refactoring
  since Milestone T (this finding's own origin) — not re-verified against
  the exact original code path (which may no longer exist in its
  original form), so not claiming precise root-cause credit, but the
  described symptom is confirmed absent today. Flagging here, mirroring
  how Milestone X's own audit flagged COMP-10 as stale, so a future pass
  doesn't re-investigate it from scratch.

## Execution plan

**Z1**: dispatched and closed this same pass, orchestrator-direct (small,
well-scoped, root cause already fully understood from V5's own prior
investigation — no separate subagent dispatch needed).

Further candidates surfaced by this pass's scan but **not** attempted
(left for a future Milestone, listed here so they aren't re-discovered
from scratch):
- `charts/kronos/files/nginx.conf.template` (Helm's manually-duplicated
  copy) still lacks the real access-log fix `docker/nginx/nginx.conf.template`
  got in V8 — no live consequence yet since Helm/K8s log-shipping is
  entirely unwired (consistent with P2-6), but flagged in
  `docs/GAP_AUDIT_2026-08.md`'s own P1-6(V8) row as "further out of sync."
- `kronos_attest case_report`'s `events: list[dict]` still comes from an
  offline audit-log export rather than live-re-reading MinIO/Postgres/TSA
  at report time (`docs/GAP_AUDIT_2026-08.md` P2-5) — a real credibility
  gap for a "court-admissible chain of custody" flagship claim, but sized
  **L** (large) per that doc's own estimate, not a quick win like Z1.
- `docs/access-management-review.md`'s still-open prod OpenSearch
  demo-cert finding (prod's security setup still relies on bundled
  self-signed demo certs, not real production TLS material) — real,
  prod-relevant, but needs a real TLS material provisioning decision, not
  purely technical.
