# Security / Red-Team Review — KronOS Backend

**Date:** 2026-08-15
**Branch:** `feat/nextgen-soc-cert-platform` @ `bd42ee3`
**Scope:** Code-reading adversarial review only. No live attack was run against
any running system. This review goes broader/deeper than the two prior
security-specific passes already in the repo:

- `docs/GAP_AUDIT_2026-08.md` §0.5 — tenant isolation + secret handling in the
  six new Q/R connectors and the admin routes (already checked, assumed
  correct, not re-derived here).
- `docs/GAP_AUDIT_2026-08.md` V5 — real-Keycloak-verified pass on `admin.py`'s
  membership routes (already checked, assumed correct, not re-derived here).

Background read first: `docs/assessments/incident_response_walkthrough.md`,
which established that `DetectionSyncService.sync_org_findings()`,
`BatchSealingService.seal_pending()`, `StreamNormalizationService
.normalize_batch()`, and `PlaybookExecutionService.execute()` currently have
**zero production callers**. That finding is treated here as context, not as
a reason to skip reviewing those code paths — unreachable code today can ship
with a real vulnerability once wired up, and item 5 below reviews
`PlaybookExecutionService`/`SyncDetectionToSiemAction` on that basis.

---

## §0 Method

Systematic, adversary-mindset code reading, organized by the seven areas the
task specified:

1. **Tenant isolation, broadly.** Read all 11 files in `src/external/routes/`
   in full (`admin.py`, `audit.py`, `auth.py`, `cases.py`,
   `collector_ingest.py`, `detections.py`, `evidence.py`,
   `integration_source_push.py`, `sse.py`, `step_up.py`) plus the shared
   middleware they depend on (`rbac.py`, `tenant_context.py`,
   `step_up_auth.py`, `collector_mtls.py`, `integration_source_auth.py`,
   `keycloak_auth.py`, `opensearch_isolation.py`, `query_isolation.py`). For
   every route, traced where `org_id` comes from and confirmed it is never
   taken from a client-controlled body/query/path parameter without being
   cross-checked against `TenantContext`.
2. **Authorization/RBAC.** Traced every `requires_role(...)`/`_assert_aal2`/
   `assert_case_access`/`assert_case_lead_or_admin` call site; checked for
   routes missing a role guard the permission matrix implies, and for
   duplicated (as opposed to reused) authorization logic that could drift.
3. **Injection surfaces.** `grep`'d every `src/adapter/repository/*.py` for
   raw SQL / `text()` / string-formatted queries (only one `text()` use
   exists, in `_schema_lock.py`, and it is bind-parameterized). Read the six
   new untrusted-input connector parsers (`wazuh.py`, `suricata_zeek.py`,
   `defender.py`, `cef_detection_mapper.py`, plus `suricata.py`,
   `sentinel_detection_mapper.py` by association) end to end. Read
   `firecracker.py` (the one real subprocess-shelling-out path reviewed;
   `volatility_launcher.py`/`yara_x_runner.py` were located but not read in
   full this pass — see §1 gaps below) for command-injection risk.
4. **Secret handling.** Read `src/config.py`'s full `SecretStr` field list;
   grepped the whole repo for `get_secret_value()` call sites (all are
   passed straight into a real client/engine constructor, never logged) and
   for any `logger.*` call whose message references secret/token/password/
   api_key/credential (none found).
5. **SOAR/playbook surface.** Read `playbook.py`, `playbook_execution.py`,
   `playbook_actions.py`, `sync_detection_to_siem_action.py` in full.
6. **Integration-source inbound API-key auth.** Read
   `integration_source_auth.py` in full, focused on
   `StaticApiKeyInboundAuthenticator.authenticate`.
7. **Dependency pinning.** Read `pyproject.toml`'s full dependency list.

Additionally (not explicitly asked but adjacent to item 1): spot-checked
`get_by_id`/`get`/`get_latest_version`-style repository methods across all 20
files in `src/adapter/repository/` for org_id scoping, and traced every
caller of the two cross-org-capable repository methods called out in
CLAUDE.md §E.5 (`stream_all_by_state`) to confirm they are Celery-beat-only.

**Not yet checked / explicitly out of scope for this pass** (see §1 for why
each is flagged, not silently omitted): `volatility_launcher.py` and
`yara_x_runner.py` were located but not read line-by-line for
command/path-injection the way `firecracker.py` was; MinIO/Vault/KES wiring
was not re-reviewed (already covered by GAP_AUDIT §0.5); OpenSearch DLS
policy content itself (as opposed to the query-wrapping code in
`opensearch_isolation.py`) was not re-verified against a live cluster.

---

## §1 Findings

### P1-SEC-1 — SSE ticket issuance bypasses case-level access control

**File:** `src/external/routes/sse.py:44-56` (`create_sse_ticket`), contrasted
with `src/external/routes/cases.py:272-300` (`list_case_evidence`) and
`src/external/middleware/rbac.py:45-63` (`assert_case_access`).

**The gap.** Every other route that returns evidence data for a specific case
(`GET /api/cases/{case_id}/evidence`, `GET /api/cases/{case_id}/dashboard-url`,
`GET /api/cases/{case_id}/audit`) calls `case_repo.get_by_id(case_id,
tenant.org_id)` and then `assert_case_access(tenant, case)` — which, per its
own docstring, requires a non-admin caller to be the case's owner or listed in
`case.member_user_ids`; org membership alone ("this case belongs to the
caller's tenant") is explicitly *not* sufficient, per that function's own
docstring: *"org_id equality alone is not sufficient, that just proves the
case belongs to the caller's tenant, not that the caller is entitled to see
it."*

`POST /api/sse/ticket` (`create_sse_ticket`, `sse.py:44`) does not do this. It
only requires `Depends(get_tenant_context)` — any authenticated org member,
any role — and mints a ticket for `body.caseId` with **no call to
`case_repo.get_by_id`, no call to `assert_case_access`, not even a check that
the case exists**. `GET /api/sse/cases/{case_id}/evidence` (`sse.py:59`) then
streams live evidence-state changes (`evidenceId`, `state`) for that
`(case_id, org_id)` pair using only the ticket's own stored `org_id` (the
ticket-issuer's org, not re-validated against the case).

**Exploit scenario.** A "read-only" or "analyst" user who is a legitimate
member of Case A, but *not* a member of Case B (both cases exist in the same
org they belong to — e.g. Case B is a sensitive HR/insider-threat
investigation intentionally restricted to specific case-lead-selected
members), can: (1) `POST /api/sse/ticket {"caseId": "<case-B-uuid>"}` — succeeds,
no ownership check; (2) `GET /api/sse/cases/{case-B-uuid}/evidence?ticket=...`
— succeeds, streams every evidence item's ID and FSM state (`UPLOADING`,
`SCANNING`, `PARSING`, `COMPLETE`, `ERROR`, etc.) for Case B in real time for
up to 5 minutes. This leaks the existence, count, and processing-status
timeline of evidence in a case the user has no read access to via any other
route in the codebase — a real confidentiality boundary this same codebase
enforces everywhere else evidence-for-a-case is exposed.

**Not exploitable cross-org** (verified): `EvidenceRepository.stream_by_case`
(`postgres_evidence.py:126-139`) filters with `.where(case_id == ..., org_id
== ...)` (AND semantics) — a ticket minted with the *caller's own* org_id
against a case_id belonging to a *different* org returns nothing. The gap is
strictly intra-org, cross-case.

**Suggested fix.** `create_sse_ticket` should resolve `case_repo.get_by_id(
body.caseId, tenant.org_id)` and call `assert_case_access(tenant, case)`
before minting a ticket, mirroring every other case-scoped route in this
codebase (`cases.py`'s three case-scoped GETs already establish the exact
pattern to copy).

**Severity: P1** — real, confirmed authorization gap; bounded blast radius
(metadata only, not evidence content; single-org only; 60-second ticket
window; requires a valid authenticated session in the target org already).

---

### P2-SEC-2 — Inbound integration-source API-key comparison is not constant-time

**File:** `src/external/middleware/integration_source_auth.py:121-137`
(`StaticApiKeyInboundAuthenticator.__init__`/`authenticate`).

```python
def __init__(self, provisioned_keys: Mapping[str, StaticApiKeyProvisioning]) -> None:
    self._provisioned_keys = dict(provisioned_keys)

async def authenticate(self, headers: Mapping[str, str]) -> IntegrationSourceIdentity:
    ...
    api_key = normalized.get(self._HEADER_NAME.lower())
    ...
    provisioning = self._provisioned_keys.get(api_key)
```

The provisioned-key lookup is a plain Python `dict.get()` keyed by the
attacker-supplied `X-KronOS-Source-Key` header value. `dict.get()` hashes the
supplied string and compares against bucket contents — this is not a
constant-time comparison (`hmac.compare_digest` / `secrets.compare_digest`
is the standard mitigation for exactly this pattern: comparing a
secret-bearing value supplied by an untrusted caller). In principle this
permits a timing side-channel against the provisioned key material.

**Exploit scenario (theoretical, not demonstrated).** An attacker positioned
to make many low-jitter requests to `POST /api/integrations/push/{source_type}`
(e.g. on the same LAN segment, or if network jitter is unusually low) could,
in principle, statistically distinguish "no key in the dict at all" (fails
during hashing/lookup, no per-character comparison) from "a key of the right
length hashes into a populated bucket" and attempt to narrow down valid key
material faster than pure brute force. In practice this is a low-severity,
largely theoretical finding for an HTTP-over-TCP transport: Python's string
hashing (SipHash) and dict bucket lookup do not leak *per-character* timing
the way a naive `for i in range(len(a)): if a[i] != b[i])` early-return
comparison would, and real-world network jitter over HTTP typically dominates
any signal — but it is not the constant-time primitive this codebase uses
correctly elsewhere (e.g. TLS-terminated mTLS for the collector path avoids
this class of issue entirely by design).

**Suggested fix.** Replace the dict lookup with an explicit constant-time
scan: `for candidate_key, provisioning in self._provisioned_keys.items(): if
hmac.compare_digest(candidate_key, api_key): return ...`. With a small
number of provisioned keys per deployment this is cheap; if the key count
ever grows large, a keyed-HMAC-of-the-input-then-dict-lookup pattern (compare
`hmac.compare_digest` against a stored HMAC, not the raw key) avoids both the
timing side-channel and an O(n) scan.

**Severity: P2** — real code-level weakness matching a known anti-pattern,
but low practical exploitability over a real network path; genuine hardening
opportunity, not treated as P1 given the mTLS path (the higher-value D2
collector transport) does not have this issue at all.

---

### P2-SEC-3 — `rule_pack`/`yara_rule_pack`/`ioc_feed` repository lookups by version/rule id lack org_id defense-in-depth

**Files:** `src/adapter/repository/postgres_rule_pack.py:130`
(`get_latest_version`), `:173` (`get_published_opensearch_id`),
`src/adapter/repository/postgres_yara_rule_pack.py:138`
(`get_latest_version`), `:182` (`get_published_version`),
`src/adapter/repository/postgres_ioc_feed.py:178` (`get_latest_version`).

These five methods take only a `pack_id`/`feed_id`/`rule_id` — no `org_id` —
and query without an org filter. Confirmed via `grep` that **every current
call site** passes an id previously resolved from an org-scoped
`get_or_create_pack(org_id, name)`/`get_or_create_feed(org_id, name)` call
(`rule_pack_service.py`, `yara_rule_pack_service.py`,
`rule_pack_publisher.py`, `ioc_feed_ingestion.py` — all internal, Celery-task
or service-orchestrated, never given a client-supplied id directly), and
confirmed via `grep -rln` across `src/external/routes/*.py` that **no route
currently exposes `rule_pack_service`/`yara_rule_pack_service` at all** — so
this is not exploitable today.

**Why flagged anyway** (per this review's brief: unreachable code is still
reviewed for correctness, since it can ship with a real vulnerability once
wired up). If a future route is added that lets a tenant list rule-pack
versions or resolve a rule's published OpenSearch id by an id the tenant
supplies directly (a plausible near-term feature — e.g. "show me this rule
pack's version history" in an admin UI), passing a `pack_id`/`rule_id`
belonging to a *different* org straight through to these methods would
return that other org's data with no org check at all. This is exactly the
same class of gap the codebase's own `EvidenceRepository`/`CaseRepository`/
`DetectionRepository` deliberately avoid by requiring `org_id` on every
`get_by_id`.

**Suggested fix.** Add an optional or required `org_id` parameter to these
five methods now, even though no caller needs it yet, so the invariant is
enforced at the repository layer rather than depending on every future
caller remembering to pre-scope the id. This mirrors the defense-in-depth
principle the rest of the repository layer already follows.

**Severity: P2** — not exploitable via any current code path; a real gap in
defense-in-depth that would become P0/P1 the moment a client-supplied id
reaches these methods.

---

### P2-SEC-4 — `python-jose` floor-only pin; verify current patch level

**File:** `pyproject.toml:22` — `"python-jose[cryptography]>=3.3"`.

`python-jose` has no version ceiling. `python-jose` has had at least one
notable JWT-algorithm-confusion-class CVE in its history
(CVE-2024-33663, affecting ECDSA/algorithm-confusion handling); this
repository's own `KeycloakTokenValidator`
(`src/external/middleware/keycloak_auth.py:19,82-85,94`) independently
defends against exactly that class of attack by hard-restricting
`_ALLOWED_ALGORITHMS = frozenset({"RS256", "PS256"})` and checking the
unverified header's `alg` **before** calling `jwt.decode(...,
algorithms=list(_ALLOWED_ALGORITHMS), ...)` — this is the correct mitigation
regardless of the installed `python-jose` version, so the missing ceiling is
not currently a live exploitation path through the algorithm-confusion class
of bug specifically. It is still worth pinning a floor at or above the
patched version explicitly (rather than relying solely on the
application-level mitigation) and adding a reasonable ceiling
(`<4` or similar) so a future major-version bump isn't silently picked up
unreviewed. Every other security-sensitive dependency in this file
(`sqlalchemy>=2.0`, `httpx>=0.27`, `fastapi>=0.111`) has the same
floor-only pattern — consistent within the file, but consistently missing
ceilings across the board.

**Severity: P2** — hardening opportunity; the live application-level
mitigation already neutralizes the specific known CVE class, verified by
reading the actual validation code, not assumed from the CVE title alone.

---

## §2 Checked and found SAFE

- **SQL injection.** Every repository in `src/adapter/repository/` uses
  SQLAlchemy Core `Table.select()/.insert()/.update()/.delete()` with
  bind-parameter substitution end-to-end. The one raw `text()` construct in
  the entire `src/` tree (`_schema_lock.py:32`,
  `sa.text("SELECT pg_advisory_xact_lock(:key)")`) uses a named bind
  parameter, not string interpolation. No `f"...{}..."` or `.format()`
  SQL construction exists anywhere in `src/adapter/repository/`.
- **JWT algorithm-confusion / "alg: none" attacks.**
  `KeycloakTokenValidator.validate_and_extract` explicitly checks the
  unverified header's `alg` against an allow-list of `{RS256, PS256}`
  *before* calling `jwt.decode`, and passes that same allow-list into
  `jwt.decode(algorithms=...)` — a caller cannot force HS256 (which would let
  an attacker sign a forged token using the RSA public key as an HMAC
  secret) or `alg: none`. Audience (`aud`), issuer, expiry, not-before, and
  `typ == "Bearer"` (rejecting ID tokens being used as access tokens) are all
  independently, explicitly verified — including a documented, tested
  correction for python-jose's own `verify_aud` no-op-on-missing-claim
  behavior (AUTH-009 comment in the same file).
- **mTLS collector identity.** `CollectorIdentityExtractor` only parses an
  already-TLS-verified peer certificate's URI SAN; it does not re-implement
  chain/expiry verification (correctly deferred to the TLS transport layer,
  `ssl_cert_reqs=CERT_REQUIRED` in `run_dual_listener.py`), and the org_id it
  extracts is never influenced by anything in the HTTP request body.
- **Playbook engine tenant scoping.** `SyncDetectionToSiemAction.execute`
  resolves the target `Detection` via `self._detections.get_by_id(
  detection_id, tenant.org_id)` — `tenant` is always the authenticated
  caller's own `TenantContext`, injected by `PlaybookExecutionService`, never
  read out of the step's own `params` dict. A malicious/crafted
  `params["detection_id"]` targeting another org's detection correctly
  resolves to `None` and raises `PlaybookError`, not a cross-tenant read.
  This holds even though (per the prior incident-response assessment) no
  route currently invokes `PlaybookExecutionService.execute()` — reviewed as
  if it will be wired up soon, per this review's own brief.
- **Command/path injection via subprocess.** `FirecrackerLauncher.run`
  (`src/external/sandbox/firecracker.py:99-127`) builds its `subprocess.Popen`
  argument list as a real Python list (never `shell=True`, never string
  concatenation into a shell command) — every argument, including
  server-controlled `evidence_path`/`evidence_id`/`case_id`/`org_id`, is
  passed as a discrete argv element, not shell-interpolated.
- **CEF output injection.** `CefDetectionMapper` correctly escapes both
  CEF header/"prefix" fields (backslash then pipe) and extension fields
  (backslash then equals), backslash-first in both zones per the real spec's
  own ordering requirement, and additionally strips/escapes `\n`/`\r` in
  both zones — preventing a `Detection`'s own attacker-influenced fields
  (e.g. a Sigma rule name, an ATT&CK tag) from injecting extra syslog lines
  or corrupting the CEF field structure of the outbound message.
  Independently, `WazuhPushSource`/`SuricataEvePushSource`/`ZeekJsonPushSource`
  /`DefenderPollSource` all validate untrusted inbound JSON strictly
  (real required-field checks, explicit `ParsingError`/`IntegrationSourceError`
  on anything malformed, a bounded `_MAX_PAGES_PER_POLL = 50` pagination
  loop guard on the Defender connector) rather than trusting shape.
- **Secret handling (broadened beyond the six connectors).** Every
  credential-bearing field in `src/config.py` (`database_url`, `redis_url`,
  `minio_access_key`/`minio_secret_key`, `opensearch_username`/`password`,
  `keycloak_client_secret`, `vault_token`, `celery_broker_url`/
  `celery_result_backend`, `splunk_hec_token`, `sentinel_client_secret`,
  `defender_client_secret`) is typed `SecretStr`. Every `get_secret_value()`
  call site in the repo passes the unwrapped value directly into a real
  client/engine constructor argument (`create_async_engine`, MinIO client,
  OpenSearch client, Celery app, httpx request) — none are interpolated into
  a log message, and no `logger.*` call anywhere in `src/` references
  secret/token/password/api_key/credential in its message.
- **Tenant isolation across all 11 route files.** Every route that reads or
  mutates org-scoped data resolves `org_id` from the authenticated
  `TenantContext` (never a client-supplied body/query/path parameter used
  directly in a lookup); 404 (not 403) is consistently used where confirming
  resource existence to an unauthorized caller would itself leak information
  (`detections.py`, `cases.py`); step-up (AAL2) + one-time ticket gating is
  correctly required before `DELETE /api/evidence/{id}` and the admin
  user-management mutation routes; `assert_case_lead_or_admin`/
  `assert_case_access` are reused (not duplicated) across `cases.py` and
  `evidence.py`. The one gap found is §1's P1-SEC-1 (SSE), which is scoped
  and documented above, not silently included in this "safe" list.
- **`stream_all_by_state` cross-org query (CLAUDE.md §E.5).** Confirmed via
  `grep` that this repository method's only callers are the four beat tasks
  in `src/external/celery_app.py`; no route or user-request-reachable code
  path calls it.
- **Collector ingest / integration-source push tenant scoping.**
  `POST /api/collector/ingest` and `POST /api/integrations/push/{source_type}`
  both derive `org_id`/`source_id` exclusively from the verified
  authentication artifact (mTLS cert SAN, or the provisioned API key lookup)
  — never from anything in the request body — and the push route additionally
  cross-checks the authenticated `source_type` against the URL path segment,
  rejecting a credential provisioned for one source type from being replayed
  against a different one's route.

---

## §3 Overall risk-posture verdict

No P0 (immediately exploitable, high-impact) findings. One confirmed **P1**
(SSE ticket issuance bypassing per-case access control — real, but bounded to
intra-org metadata leakage, not full evidence content or cross-org access)
and three **P2** hardening items (a non-constant-time API-key comparison with
low real-world exploitability over HTTP; a repository-layer defense-in-depth
gap that is not reachable via any current route; a dependency-pinning
hygiene note whose specific known CVE class is already independently
mitigated at the application layer).

The core security architecture — tenant isolation computed from
authenticated context rather than trusted client input, JWT algorithm-
confusion defenses, parameterized SQL throughout, mTLS-based collector
identity, and audit-on-every-mutation discipline — held up well under
adversarial reading across all 11 route files and the newer Q/R connector
surface. The one real gap found (SSE) is a case of a *newer, smaller*
route module not being built against the same `assert_case_access` checklist
the older, larger route modules (`cases.py`, `evidence.py`) already
established and consistently apply to themselves — a review/consistency gap
rather than a systemic architectural weakness. Recommended next step:
fix P1-SEC-1 (small, well-scoped change — add the same
`case_repo.get_by_id` + `assert_case_access` pair `cases.py` already uses,
to `create_sse_ticket`), then address the P2 items opportunistically.

Not yet reviewed in this pass (see §0's explicit list): `volatility_launcher.py`
and `yara_x_runner.py` line-by-line for command/path injection (only
`firecracker.py` was read in full), and a live-cluster verification of the
actual OpenSearch DLS policy content referenced by
`opensearch_isolation.py`/`query_isolation.py`. Both are reasonable
candidates for a focused follow-up pass.
