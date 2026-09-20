# KronOS — Current Status

**Last updated:** 2026-09-19
**This is the only status document.** It is a living file, edited in
place — not appended to, not superseded by a new dated copy. If you are
about to write `docs/GAP_AUDIT_<date>_MILESTONE_<X>.md`, a new
"HANDOFF"/"PROGRESS"/"PRODUCT_STATUS" doc, or any other dated
current-state snapshot: don't. Update this file's relevant section
instead. See `docs/archive/status-history/README.md` for why this rule
exists — the short version is that the previous approach produced 93
gap-audit docs and three separate, overlapping "the real status" attempts,
none of which superseded the others.

**Companion file:** `DECISIONS.md` — append-only log of *why* things are
the way they are. This file (`STATUS.md`) says what's true now; that file
says why it became true and doesn't need updating when it's still true.

**How to keep this honest:** every claim below should be traceable to
something real — a passing test, a `poc/*/README.md` with captured
output, a real E2E spec, or code actually read in the pass that touched
it — not "should work." When you finish a piece of work, update the
relevant bullet here (move it between sections, add/remove a line) as
part of being done, the same way you'd run tests before calling something
finished. Content below not touched in a given session should be assumed
accurate as of its own last-verified date, not silently re-warranted —
if you're not sure a still-listed item is still true, say so rather than
deleting or keeping it silently.

---

## 1. What's built and verified

### Evidence intake & forensic parsing
Real, resumable, hash-verified upload pipeline (client magic-byte
pre-check → presigned MinIO upload → server-side validate/scan(ClamAV)/
hash/promote → autonomous parse → OpenSearch indexing), fully
server-driven after the client's initial call (`CLAUDE.md` §E). Parsers
with real, verified coverage: evtx-rs (fast EVTX), Plaso (heavy —
Prefetch/registry/journald/SQLite and now the sole EVTX handler, see
`DECISIONS.md`), Suricata EVE JSON, Chrome History, AWS CloudTrail,
nginx/Apache logs, ZIP/tar/EWF container recursion (including nested
containers). `VolatilityModule` (memory forensics) now handles **both
Windows and Linux** images — real OS-family detection
(`VolatilityLauncher.detect_os_family()`, the OS-agnostic `banners.Banners`
plugin) picks the right curated eager plugin set per file automatically,
real-verified end-to-end against both a real Windows sample (`cridex.vmem`)
and a real self-generated Linux sample (Ubuntu 22.04, LiME capture) in the
same run — see `poc/volatility_linux_module/README.md` and
`reviews/Volatility_Linux_Plugin_Research.md`. Two named, real caveats in
§2 below (an ISF-tool compatibility gap for one plugin; no Linux timeline
records yet, artifacts only).

### Timeline & search
OpenSearch, ECS + `kronos.*` schema, per-case-per-month index rollover
under ISM. Dashboards field discovery verified live against real Plaso
output.

### Multi-tenancy, auth, audit
Keycloak 26+ Organizations, JWT + step-up (aal2) auth, per-tenant data
isolation. Append-only, hash-chained audit log
(`row_hash = SHA256(prev_row_hash || canonical_json(event))`) on every
mutation. RBAC trilogy (`assert_case_lead_or_admin` and friends) closed,
including case-member add/remove and mid-session role changes.

### Connector marketplace (`/admin/connectors`) — built 2026-09, this initiative
Per-org, self-service connector configuration replacing single-global
`Settings`-driven config. All 7 phases of the build (Vault wiring →
domain/application layer → Postgres+Vault adapters → Defender POLL
per-org rewiring → sink fan-out (Splunk HEC/CEF syslog/Sentinel) → PUSH
connector UI (Wazuh/Suricata/Zeek) → global-Settings cleanup) are done
and were verified against the real dev stack, not just unit-tested — see
`docs/CONNECTOR_MARKETPLACE_VERIFICATION.md`. Real, working:
- Per-org credential storage in a dedicated Vault KV-v2 mount
  (`kronos-connectors`) + AppRole, never the shared KES token.
- Circuit breaker: 5 consecutive failures auto-disables a connector
  (`auto_disabled_at`, distinct from the user-controlled `enabled` flag).
- Reversible disable/enable vs. permanent delete (see `DECISIONS.md`).
- A real, previously-unverified bug (step-up ticket never minted by the
  marketplace frontend, mutations silently hung) was found and fixed
  2026-09-19 via a real Playwright run — see `DECISIONS.md`'s connector
  marketplace section. Fix: `frontend/src/lib/stepUpTicket.ts`.
- Real Playwright E2E coverage: Suricata PUSH key
  generate/reveal-once/revoke
  (`frontend/e2e/connector-marketplace-suricata-push.spec.ts`) and
  CEF-syslog SINK configure/disable/enable/remove
  (`frontend/e2e/connector-marketplace-cef-syslog-sink.spec.ts`), both
  run live against the dev stack including the real step-up MFA redirect.
- **Not yet covered by a dedicated E2E spec** (built and unit-tested, but
  no live browser run): Wazuh/Zeek PUSH panels (share the same
  `PushConnectorKeyPanel.tsx` component the Suricata spec exercises, so
  risk is low but unconfirmed), Splunk HEC / Sentinel / Defender POLL
  config forms (share `ConnectorConfigForm.tsx` with the CEF spec, same
  caveat).
- A real bug in stream ingestion was found and fixed in the same
  initiative: `StreamSourceNormalizerRegistry` was keyed on a connector
  *instance's* `source_id` (e.g. `wazuh-manager-1`) instead of its
  `source_type` (`wazuh`) — affected both arbitrary-named PUSH instances
  and the Defender POLL rewrite. Fixed with regression tests and a live
  end-to-end re-verification.

### Evidence-upload TLS-origin bug — fixed 2026-09-19
Presigned upload URLs used to point at `https://kronos.local:9444`
(nginx→MinIO), a different browser *origin* than the main app purely
because the port differed — a browser that had only trusted the main
site's cert got a silent, undiagnosable "Network error" on every upload
(real HAR showed `status: 0` on both the CORS preflight and the PUT; the
old repro tooling, curl `-k`/Playwright `ignoreHTTPSErrors`, couldn't
catch it since both bypass cert validation entirely). Fixed by proxying
MinIO's real bucket-prefixed paths (path-style S3 addressing) through the
main `:443` origin itself (`docker/nginx/nginx-lan-https.conf.template`'s
`location ~ ^/kronos-evidence-`) instead of a dedicated port, and pointing
`MINIO_PUBLIC_ENDPOINT`/`MINIO_PUBLIC_URL` at `https://kronos.local` (no
port). Port `9444` is fully retired (nginx server block removed, no
longer published in `docker-compose.dev.yml`). Verified for real: a
Python script logging in through real Keycloak (`https://kronos.local:8443`)
and performing a real presign→PUT→finalize upload with the real step-ca
root CA trusted and **no cert-validation bypass anywhere** (`verify=<real
root_ca.crt>`, not `-k`/`verify=False`) — presigned URL confirmed to carry
no port, PUT returned 200, finalize returned 202. Backend unit tests
(209 relevant) and the real `evidence-upload.spec.ts` Playwright spec both
still pass. See `DECISIONS.md`'s connector/infra section for the full
rationale.

### Frontend E2E (`frontend/e2e/`)
Real browser tests against the live dev stack (`https://kronos.local`),
not mocked — evidence upload through to `COMPLETE` via SSE, admin
quota/invite/role-change step-up flows, connector marketplace (above).
Page-object pattern (`KronosPage` base + per-page subclasses),
`DEV_USERS` fixture for the three static dev accounts. `workers: 1` —
there is a documented Keycloak concurrent-login race, don't parallelize.

### CI / test suite
`~/venv/bin/python3 -m pytest tests/` runs the full unit+integration
suite in-process. As of the last full run this initiative is aware of:
2000+ tests passing, ~90% coverage gate. Python 3.14 works fine on this
host (an older `asyncpg`/`greenlet` deadlock is no longer reproducible).

---

## 2. Known gaps (real, named, not hidden)

- **"Firecracker microVM" isolation is not actually Firecracker.** Heavy
  parsing (Plaso, Volatility) runs as a sandboxed subprocess in a
  container, not inside a real Firecracker microVM, despite naming in
  the code. Functionally correct; the isolation boundary is weaker than
  the documented target.
- **SIEM integrations (Wazuh/Falco/fluent-bit) are configured but not
  wired in.** Each has a standalone compose file; none is referenced by
  any shipped `docker-compose.{dev,test,prod}.yml` profile, and no rule
  has ever fired against a real event. This is a standing product-scope
  decision, not an oversight — see `DECISIONS.md`.
- **No real Kubernetes deployment has been attempted.** `helm lint`/
  `helm template` pass clean; a real `helm install` against a real
  cluster has not been tried.
- **No workflow in this repo has ever executed on GitHub's own
  infrastructure.** All CI-equivalent coverage is real and locally
  verified, but GitHub only evaluates `schedule:`/other triggers from the
  default branch, and this work has never merged to `main`.
- **`linux.malware.hidden_modules.Hidden_modules` may `scan_error` on some
  real orgs' images.** Real, understood cause (`poc/volatility_linux_module/`):
  this plugin checks an ISF metadata field that only `dwarf2json`-produced
  symbol tables set — an org whose Linux ISF was built via `btf2json` (a
  real, valid, faster alternative for kernels with `CONFIG_DEBUG_INFO_BTF=y`)
  will see this one plugin fail while the other 8 in the Linux eager set
  succeed normally (same "one bad plugin doesn't sink the run" handling
  every other multi-plugin outcome already gets). Not urgent, named.
- **Linux memory images produce no dual-emitted `TimelineRecord`s yet.**
  `linux.pstree`/`linux.psscan` carry no per-row wall-clock timestamp in
  this volatility3 version (real, verified against a real sample) — Linux
  findings surface entirely through `StructuredArtifact`s
  (`extract_artifacts()`), never the case timeline. A real fix would
  combine `linux.boottime.Boottime` with each process's boot-relative
  start offset — not yet built, tracked in
  `reviews/Volatility_Linux_Plugin_Research.md`.
- **Dev OpenSearch's shard ceiling was raised (1000 → 2000) as a
  workaround, not fixed.** Root cause (ISM creates a new index per case
  per month, never deleted) is still real; the ceiling will be hit again
  eventually. See `DECISIONS.md`.
- **Vault runs in `-dev` mode (in-memory, unsealed) on the dev stack.**
  Acceptable for dev only. Production deployment of the connector
  marketplace (or KES) is blocked on real sealed/persistent Vault — this
  is a hard requirement, not a nice-to-have.
- **Per-org Vault ACL isolation is application-layer discipline, not
  Vault-enforced.** The connector-secrets Vault policy is static, not
  templated per org-id token claim. The actual collision boundary today
  is "`org_id` always comes from `TenantContext`, never client input" —
  correct and tested, but a compromised backend process could in theory
  read another org's path. Stronger per-org Vault ACLs are a named,
  deferred hardening, not implemented.
- **Track D (third-party/customer-supplied parser modules) has not
  started.** Gated behind first-party modules being solid, per
  `reviews/Extensibility_Architecture_Proposal.md`.
- **A few named, small test-coverage gaps**: `StatusPill`'s transient
  pipeline states have no visual-regression coverage; two-simultaneous-
  dependency-failure fault injection has no coverage (every existing
  fault-injection spec targets exactly one dependency, fully down).

## 3. Explicitly out of scope (standing product decisions — don't re-litigate without a fresh instruction)

- No SIEM wiring for now.
- No v2 features for now (advanced timeline search, case collaboration/
  comments, non-Sigma detection rules, DFIR report generation, broader
  API rate limiting).
- `audit.py`'s export/verify/merkle-proof routes deliberately have no web
  UI — they feed the standalone `kronos-attest` CLI by design.

See `DECISIONS.md` for the reasoning behind each.

---

## 4. Operational facts worth not re-deriving

- Docker Compose commands against the dev stack need `-p docker`
  explicitly (e.g. `docker compose -p docker -f docker/docker-compose.dev.yml
  build nginx`) — the project name doesn't default correctly on this host.
  Container names: `docker-kronos-backend-1`, `docker-nginx-1`, etc.
- `kronos-backend` auto-reloads on source changes (volume-mounted `src/`,
  `uvicorn --reload`) — a backend Python change needs no manual restart.
  A **frontend** change needs a manual `docker compose ... build nginx`
  + `up -d nginx` — it's a static build baked into the nginx image, not
  live-mounted.
- OpenSearch: real, live, 2.11.1, `https://localhost:9200`
  (`admin`/`admin`, self-signed cert). Keycloak: real, live, 26.2,
  `https://kronos.local:8443` externally. Dev users: `case-lead`,
  `analyst`, `admin` (`frontend/e2e/fixtures.ts`'s `DEV_USERS`). `admin`
  requires TOTP for both ordinary login (`CONFIGURE_TOTP` required
  action) and step-up (aal2) — these are different Keycloak flows; a
  normal TOTP login does not imply aal2.
- Step-up (MFA) is a full browser redirect (`keycloak.login({acrValues:
  'aal2', prompt: 'login'})`), not an in-page refresh — the original
  in-flight mutation is abandoned and must be manually retried after
  returning; local form state is stashed/restored via
  `frontend/src/lib/stepUpFormPersistence.ts` but never auto-resubmitted.
  Some routes additionally require a one-time `X-Step-Up-Ticket` on top
  of aal2 (see `DECISIONS.md`) — check which bar a route actually
  enforces before assuming the aal2-only pattern.
- The dev-seeded `admin` user's TOTP secret lives in
  `poc/auth_flow/dev_totp_secrets.py` and `frontend/e2e/stepup.ts` — both
  must be updated together if the credential is ever re-registered (see
  `DECISIONS.md`).
