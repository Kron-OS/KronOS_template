# Gap Audit — Milestone GGG (2026-08-28)

**Scope:** continuation of the frontend↔backend connectivity initiative.
Following Milestone FFF's recommendation, investigated the
`docker-compose.test.yml` "CI-capability gap" this whole initiative's
plan doc had carried as an open item since its first research pass.
**Finding: that claim was already stale before this initiative even
started** — a prior, unrelated session had already closed the substantial
part of it. This cycle is a correction pass, re-verifying and precisely
re-scoping what's actually still true, not new implementation.

---

## What was found

`docs/PLAYWRIGHT_E2E_TEST_PLAN.md` (and, downstream, `PROGRESS.md`) said
`docker-compose.test.yml` "disables the OpenSearch security plugin and
has no step-ca/kronos.local/keycloak-init scaffolding," citing an earlier
`docs/NEXTGEN_SOC_ROADMAP.md` §I1 investigation, and treated closing this
as a real, unstarted prerequisite (§4) for most of the plan's remaining
E2E scenarios.

Reading the actual current file immediately contradicted this: OpenSearch
security is genuinely enabled (`OPENSEARCH_INITIAL_ADMIN_PASSWORD`, a
real HTTPS healthcheck), real Keycloak org provisioning runs
(`keycloak-init` using the real, unmodified
`scripts/provision_keycloak_org.sh`), and a real `opensearch-init` wires
the openid authc domain + DLS role. `git log` traced this to commit
`ba91a24` (`feat(ci): V3 -- CI-realistic security-enabled test compose
profile`, Gap Audit P1-14) — a session that predates this whole
frontend-connectivity initiative. `poc/ci_security_enabled_stack/`
documents the real, measured resource-fit investigation behind it, and
`.github/workflows/security-integration-tests.yml` already runs this
exact profile against `tests/integration/test_security_enabled_stack.py`
— nightly + manual dispatch, a deliberate, reasoned scoping choice
(documented in that workflow's own comments), not an oversight or a
"never wired up" gap.

**This means every one of this initiative's own prior milestone docs
(the original plan doc's §0/§4, and pointers in Milestones EEE/FFF) has
been citing a stale claim without re-checking it** — exactly the failure
mode CLAUDE.md §F exists to catch, this time inside the initiative's own
research rather than in `src/`.

## Re-verification performed (not just corrected from reading)

Per CLAUDE.md §F, re-ran the real thing rather than trusting either the
old claim or the new discovery on sight:

1. Brought up `docker-compose.test.yml`'s security-enabled profile in a
   fully isolated, port-remapped Compose project (`kronos-test`, ports
   offset by 10000 via a `!override`-tagged override file — Compose
   merges `ports:` lists by concatenation, not replacement, without that
   tag; a real, reproduced gotcha hit and fixed mid-pass). Never touched
   the live running dev stack (`docker-*` project) — confirmed via
   `docker ps` before/after, container count unchanged.
2. `postgres`/`redis`/`minio`/`opensearch`/`keycloak` → all real,
   healthy.
3. `opensearch-init` + `keycloak-init` → both real, clean, successful
   real Admin REST provisioning runs (captured output: real org created,
   real `org_id` attributes set, real openid authc domain + DLS role
   configured).
4. `poc/ci_security_enabled_stack/provision_ci_org_b.py` → real second
   org for isolation proof, still works unmodified.
5. `pytest tests/integration/test_security_enabled_stack.py` → **3/3
   passed**, confirming this profile still works today against the
   *current* codebase — including this initiative's own recent
   `ConcurrentModificationError`/`fastapi_app.py`/`detections.py` changes
   from Milestone EEE, which postdate the original `ba91a24` work and had
   never been checked against this profile until now.
6. Full isolated teardown (`down -v --remove-orphans`), confirmed clean.

## Re-scoped: what's genuinely still missing (more precise than the old claim)

Reading `docker-compose.test.yml`'s `nginx` service directly (not
assumed): it's `image: nginx:alpine` with only `nginx.conf.template`
mounted — **no `Dockerfile.frontend` build, no frontend static assets at
all**. This file's `nginx` is API-reverse-proxy-only, consistent with its
original backend-integration-testing purpose; it was never meant to serve
a browser-facing SPA. Separately, there's no `kronos.local`/step-ca TLS
scaffolding (plain `http://localhost` throughout), and
`VITE_KEYCLOAK_URL` (the frontend's Keycloak origin) is a Vite
**build-time** arg baked into the compiled bundle, not
runtime-configurable.

None of this has ever blocked `tests/integration/test_security_enabled_stack.py`
(backend-only, never touches a browser). All of it blocks running
`frontend/e2e/`'s own Playwright suite against this profile, which is
genuinely still not possible today — but the real remaining work is
narrower and more concrete than "build the missing security/Keycloak
scaffolding": (1) add an actual frontend-building `nginx` service, (2)
decide plain-HTTP-`localhost` vs. TLS/`kronos.local` for this profile
specifically (a real choice — a step-up/cookie-security code path could
behave differently under HTTP vs. HTTPS and needs checking, not
assuming), (3) make `playwright.config.ts`'s base-URL assumption match
whichever is chosen. Not attempted this pass — precisely re-scoping it,
not implementing it, is this cycle's contribution.

## Documentation corrected

- `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §0 and §4 — both rewritten in place
  with dated correction notes (not deleted — the stale claim and its
  correction are both visible, matching this repo's own established
  convention for this class of fix).
- `PROGRESS.md`'s Frontend SPA section — same correction, plus updated
  spec count (six real E2E specs now, not four — the isolation/retry
  specs from Milestones EEE/FFF hadn't been reflected there yet either).

## Status

- E2E delivery-order items 2-4 remain fully complete (Milestones EEE/FFF).
- The `docker-compose.test.yml` CI gap is **not** the large blocking item
  it was described as; what remains is real but smaller (three concrete
  sub-items above).
- Milestone EEE's other findings (suite runtime scaling, TS+Python
  toolchain consolidation, multi-tab session gap) remain open, untouched
  this cycle.

## Recommendation for the next cycle

1. If continuing the CI-wiring thread: the three sub-items above are now
   concretely scoped — start with the plain-HTTP-vs-TLS decision (item 2),
   since it determines whether item 1 (the nginx/frontend-build service)
   needs step-ca or not.
2. Otherwise, return to `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8
   (dashboards embed, resilience, a11y/visual) or Milestone EEE's
   still-open maintainability findings.
3. **Re-read `docs/GAP_AUDIT_2026-08-28_MILESTONE_FFF.md` Part 2 before
   any manual verification against the live dev Keycloak** — this
   cycle's own isolated-stack work followed that lesson (used the
   `!override`-tagged file + a fresh, disposable project name throughout,
   never a bare ad hoc command against the live stack).
