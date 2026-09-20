# Gap Audit — Milestone DD (continuation, 2026-08-18)

Follow-up to `docs/GAP_AUDIT_2026-08-18_MILESTONE_CC.md` (Milestone CC,
fully resolved: CC1 CLOSED). CC's own honest note observed that the well
of unilaterally-actionable gaps found via `docs/*.md` grep-scanning was
running dry, and that re-examining this initiative's own most recently
landed code (as CC1 itself did) was likely more productive than
continuing to scan the same docs. This pass did exactly that: a direct
security review of X1 (evidence download), X2a/X2b (Postgres replication
/ Redis role separation), Y2 (Keycloak realm scope changes), and
AA1/BB1/CC1 (kronos-attest live modes) — the substantial new surface area
landed since the original Task #14 multi-scenario assessment.

---

## DD1 — evidence-download / audit-export routes crash on a crafted filename (real availability bug)

**STATUS (2026-08-18, commit TBD): CLOSED, verified live.**

`src/external/routes/cases.py::download_evidence` (X1) and
`src/external/routes/audit.py`'s export route (W3) both build a
`Content-Disposition` header from a user-influenced string, previously
escaped only for double quotes
(`original_filename.replace('"', "")`). `UploadRequestIn.filename` is
intentionally bounded only by length (`max_length=1024`), never content —
correct for a DFIR platform, which must accept evidence with
adversarial/malformed filenames from a compromised host — but that same
unrestricted string reached a raw HTTP header unescaped for CR/LF.

**Confirmed real, live impact against an actual running `uvicorn`
server** (not assumed, not just object inspection — `TestClient`'s
in-process ASGI transport never serializes real HTTP/1.1 bytes and so
never exercises this): a filename containing a raw `\r\n` reaches h11's
own strict header-value grammar, which refuses to serialize the response
at all (`h11._util.LocalProtocolError: Illegal header value`) — the
client sees a hung/empty connection, the server logs an unhandled
exception. **Not exploitable as header injection or response
splitting** — h11 defends against that at the protocol level, confirmed
the same way — but a real, live **availability** bug: any authenticated
user with ordinary evidence-upload permission (not an admin action) can
permanently break the download route for that evidence item, for every
user in the org, with a single crafted filename.

**Fix:** new `src/external/routes/_http_helpers.py::sanitize_content_disposition_filename()`
— strips all C0 control characters and DEL plus the double quote, leaves
real Unicode filenames untouched. Used by both the evidence-download route
and the audit-export route (the latter's filename includes
`tenant.org_alias` — a lower-severity instance of the same class, an org
admin could only ever break their own org's export — fixed for
consistency).

**Verified (`poc/evidence_download_filename_sanitization/`):** real
before/after against a real `uvicorn` server (real crash captured, then
real clean `200 OK` after the fix); a new regression test
(`tests/unit/test_cases_routes.py::TestDownloadEvidence::test_filename_with_crlf_does_not_break_download`)
independently confirmed to genuinely fail against the pre-fix code (fix
temporarily reverted, test re-run in isolation, confirmed it fails on its
own assertion — not a false-positive test). Full backend suite before/after:
1975 → 1976 passed (+1, zero regressions), 2 skipped both times.
`ruff`/`black`/`mypy` clean (also cleaned up a pre-existing, unrelated
import-sort violation in `cases.py`'s own import block while already
editing it for this fix).

**Priority: P1** — real, live, triggerable by any ordinary user (not
privileged), breaks a real user-facing capability (X1's own flagship
"finally close the evidence-download gap" deliverable) for the whole org,
not just the uploader.

---

## Other areas reviewed this pass, no further findings

- **X2a (Postgres replication)/X2b (Redis role separation):** infra-only
  changes (Compose/Helm values), no new application code paths;
  credentials flow through existing, already-reviewed secret-management
  conventions (Docker secrets / K8s `existingSecret`). No new findings.
- **Y2 (Keycloak realm `profile`/`email` scopes):** additive-only scope
  definitions exported from a real, unmodified Keycloak default — no
  custom logic to introduce a bug into.
- **AA1/BB1 (kronos-attest live Postgres/MinIO modes):** reuse
  already-reviewed app-layer repository/storage classes read-only; no new
  write paths. CC1 already closed the one real finding from this pair
  (CLI secret exposure).

## Execution plan

**DD1**: found and closed this pass, orchestrator-direct (self-found via
direct code review, not from a docs/ scan).

Remaining candidates, unchanged, both either low-value or blocked:
- `charts/kronos/files/nginx.conf.template` Helm sync — no live
  consequence yet.
- Prod OpenSearch demo-cert gap — needs a real project-owner TLS
  decision, not attempted.
