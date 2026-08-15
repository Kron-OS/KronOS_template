# UX / Onboarding Review — Two New-User Walkthroughs

**Task:** #14. **Date:** 2026-08-15. **Branch:** `feat/nextgen-soc-cert-platform`,
tip `bd42ee3` at time of writing.

This is a from-scratch pass (a prior attempt died to a session cutoff before
writing anything; nothing here is inherited from it except one already-noted
lead, re-verified independently below in §2.1).

---

## §0 Method

Read-only assessment, no files modified other than this one, no stack stood
up. For each persona I read the real, currently-committed code/docs a
newcomer would actually encounter — not `roadmap.md`/`IMPROVEMENT_IDEAS.md`
aspirational framing — and traced concrete claims back to file:line. Where a
doc makes a factual claim about the system's current behavior, I
cross-checked it against the actual config/code it describes (Keycloak
realm JSON, Helm `values.yaml`, `docker-compose.dev.yml`, `frontend/.env.example`,
`tailwind`/`index.css`) rather than trusting the doc's own prose.

Persona 1 (SOC analyst) evidence: `frontend/src/App.tsx` (routing),
`frontend/src/pages/*.tsx`, `frontend/src/components/*.tsx`,
`frontend/src/keycloak.ts`, `frontend/src/index.css`.

Persona 2 (operator) evidence: `README.md`, `docs/deployment.md`,
`docs/DATABASE_MIGRATIONS.md`, `docs/lan-dev-access.md`,
`docker/docker-compose.dev.yml`, `docker/keycloak/kronos-realm.json`,
`frontend/.env.example`, `charts/kronos/values.yaml` and templates, `Makefile`,
plus `git log` to establish edit-order between README.md and the files it
describes (this is what turns "incomplete" findings into "actively wrong"
ones — see §2).

---

## §1 Analyst persona walkthrough

### 1.1 Real routes/flows that exist today

`frontend/src/App.tsx:30-95` (TanStack Router, hand-built route tree, no
`routes/` directory): `/login`, `/` → redirect to `/cases`, `/cases`,
`/cases/$caseId`, `/detections`, `/detections/$detectionId`, and (per
`frontend/src/components/Layout.tsx:52-58`, gated on `org-admin` role)
`/admin/org`. Every route except `/login` is wrapped in `AuthGuard`
(`frontend/src/components/AuthGuard.tsx`) which does a hard `<Navigate
to="/login" replace />` if `useAuthStore().isAuthenticated` is false — no
route is reachable unauthenticated, verified by reading the guard, not
assumed.

Case list → case detail → 4 tabs (Evidence / Timeline / Audit Log /
Settings, `frontend/src/pages/CaseDetailPage.tsx:396-403`) → Detections list
→ Detection detail with triage actions. This covers three of the four
Persona-1 flows named in the task (upload evidence, view a case, triage a
detection). **The fourth — "see connector status" — does not exist
anywhere in the frontend.** `grep -rli "connector"` across `frontend/src`
returns zero hits. There is no UI surface for Wazuh/Falco/fluent-bit/SIEM
sink health; this matches the incident-response walkthrough assessment's
finding (`docs/assessments/incident_response_walkthrough.md`, per the task
brief) that the SOAR/streaming layer is unreachable from production — it's
also simply not exposed to a user even if it were reachable.

### 1.2 Empty states — real, and genuinely present (re-verifying, not assuming)

Contrary to a "not audited yet" default assumption, empty states are
actually implemented, consistently, across every list view I checked:

- `CasesPage.tsx:170-174` — `data.items.length === 0` →
  "No cases yet. Create one to get started."
- `CaseDetailPage.tsx` `EvidenceTab`, lines 134-140 — "No evidence uploaded
  yet." (a real `<tr colSpan={5}>`, not a broken/empty table).
- `CaseDetailPage.tsx` `TimelineTab`, lines 176-184 — a genuinely
  domain-aware empty state: "Timeline analysis unavailable — no parsed
  evidence yet. Upload and process evidence to view the forensic
  timeline." This is real in-app guidance, not a generic error.
- `CaseDetailPage.tsx` `AuditLogTab`, lines 268-274 — "No audit events."
- `DetectionsPage.tsx:112-118` — two-branch empty state: a domain-specific
  message when no filter is active ("No detections yet. Detections appear
  here once Security Analytics findings are synced for your organization.")
  vs. a filter-specific one when a triage-state filter yields nothing. This
  is a real, well-thought first-run message — it explains *why* the list
  might be empty (findings sync, not a broken page) without requiring the
  user to already understand the OpenSearch Security Analytics plumbing
  behind it.

**Severity: informational, not a gap.** This item in the Gap Audit's P2
list ("empty states... unaudited") is resolved as "actually built,
verified by direct read" as of this pass — no code change needed.

### 1.3 Error-state handling — also real for the common cases, with one genuine gap

- Every list/detail query in `CasesPage.tsx`, `CaseDetailPage.tsx`,
  `DetectionsPage.tsx`, `DetectionDetailPage.tsx` branches on
  `useQuery`'s `error` and renders `<ErrorBanner>`
  (`frontend/src/components/ErrorBanner.tsx`) instead of leaving a blank
  screen — e.g. `CasesPage.tsx:161-163`, `DetectionDetailPage.tsx:51-53`
  ("Failed to load detection. It may not exist, or belong to another
  organization." — a real multi-tenancy-aware message, not generic).
- Evidence-specific failures get a purpose-built catalogue:
  `frontend/src/components/ErrorCatalogue.tsx:6-56` maps ten real
  backend `reasonCode`s (`upload_timeout`, `virus_detected`,
  `hash_mismatch`, `tsa_unreachable`, etc.) to a title + a plain-language
  hint + whether it's retryable, with an "Unknown error. Contact support."
  fallback (`ErrorCatalogue.tsx:58-64`) for any code not in the table —
  this is genuinely good UX for a forensics tool where evidence-state
  failures are legally meaningful, not just "500 error."
  `UploadDrawer.tsx:258` wires `ErrorBanner` into the upload flow itself.
- **Real gap: there is no React error boundary anywhere in the app.**
  `grep -rln "ErrorBoundary\|componentDidCatch" frontend/src` returns zero
  hits, and `frontend/src/main.tsx:9-26` renders `<App/>` directly with no
  boundary wrapping it. Every error-state above only covers *data-fetch*
  failures (`useQuery`'s `error`) — a genuine render-time exception
  anywhere in the tree (a malformed API response shape, a null-deref in a
  formatter like `formatBytes`/`formatDateTime`, a third-party component
  throwing) unmounts the whole React tree, producing a blank white screen
  with no visible message and no recovery action for the user. For a
  first-time analyst this is a real, if not proven-frequent, failure mode:
  "the page just went blank" with nothing actionable on screen.
  **Severity: P2** — real, not yet hit in the flows I read, but a single
  root-level `<ErrorBoundary>` would close it cheaply.

### 1.4 In-app guidance — none, beyond the empty-state copy in 1.2

`grep -rli "onboard\|tooltip\|walkthrough\|getting.started|\bguide\b"
frontend/src` returns zero hits. There is no help affordance, no
first-run tour, no inline docs link. A new analyst has to already know
what "Case", "Evidence", "Detection", "Audit Log", "org-admin/case-lead/
analyst" roles mean — the UI itself never explains the domain model, it
only reflects it (labels, tabs, role names appear verbatim with no
tooltip/definition anywhere). The empty-state copy noted in 1.2 is the
*only* in-app text that explains "why" rather than just "what," and it
only covers three of the four flows (not admin/user-management, not
detection triage state semantics — `DetectionDetailPage.tsx:143-152` shows
role-gated triage actions with no explanation of what
NEW→INVESTIGATING→TRUE_POSITIVE/FALSE_POSITIVE actually mean operationally).
**Severity: P2**, consistent with the Gap Audit's framing — a real,
un-addressed usability debt, not new.

### 1.5 Dark mode — re-verified, and the real story is more specific (and worse) than "not implemented"

The Gap Audit's P2-8 says "zero `dark:` Tailwind classes… not implemented."
That grep result is still accurate (`grep -rn "dark:" frontend/src | wc -l`
→ `0`), but re-reading the actual UI shows this needs a correction, not
just a re-confirmation:

- `frontend/src/components/Layout.tsx:9-26` (`useDarkMode` hook) and
  `Layout.tsx:70-79` implement a **real, interactive dark/light toggle
  button** in the header (`aria-label="Switch to light/dark mode"`,
  persisted to `localStorage['kronos-theme']`, respects
  `prefers-color-scheme` on first load, toggles a `.dark` class on
  `<html>`). This is a genuine, visible UI control a user can click.
- `frontend/src/index.css:1-2` even has the correct Tailwind v4 plumbing
  for it (`@variant dark (&:where(.dark, .dark *));`).
- But `index.css:14-26` is the *entire* light/dark implementation: two CSS
  rules that only recolor `<body>`'s background/text
  (`#030712`/`#f3f4f6` dark vs. `#f9fafb`/`#111827` light). Every
  component — `CasesPage.tsx`, `CaseDetailPage.tsx`, `DetectionsPage.tsx`,
  `Layout.tsx`'s own header — hardcodes Tailwind utilities like
  `bg-gray-900`, `border-gray-800`, `text-gray-100`, `bg-gray-950` with no
  `dark:` variant anywhere, so they render identically regardless of the
  `.dark` class.

**Net effect: clicking the toggle does not switch to a light theme — it
produces a broken half-themed page** (a light page background with every
card/table/header still rendered in the hardcoded dark palette floating on
top of it). This is materially worse for a first impression than "no
toggle exists": a user who clicks a labeled, seemingly-functional control
and gets a visually broken result reads as a bug, not a missing feature.
**Severity: P2** (cosmetic, not blocking), but the framing should change
from "not implemented" to "implemented at the shell level only, and
visibly broken when exercised" — worth flagging to whoever owns
`IMPROVEMENT_IDEAS.md` §4's "status-color design pass" item since this is
now a regression-shaped bug, not a green-field feature request.

### 1.6 Command palette / other P2-12 items — re-verified, unchanged

`grep -rli "command.?palette\|cmdk\|kbar" frontend/src frontend/package.json`
→ zero hits. No command palette, confirmed still absent, no new evidence
either direction since the Gap Audit. Same for a unified cross-evidence
timeline UI, a detection-health dashboard, and a rule-pack marketplace UI —
none found in `frontend/src/pages` (6 page components total, enumerated in
§1.1; none of these concepts appear). Not re-litigated further since
nothing changed.

---

## §2 Deployment / operator persona walkthrough

### 2.1 The prior attempt's lead, re-confirmed and sharpened: the Helm secrets snippet is broken

`README.md:251-256` (Path B — Kubernetes/Helm, described as
"**recommended**" at `README.md:239`) tells an operator to run:

```bash
kubectl -n kronos create secret generic kronos-secrets \
  --from-literal=database-url='postgresql+asyncpg://...' \
  --from-literal=keycloak-client-secret='...' \
  --from-literal=vault-token='...'        # etc.
```

This is broken on two independent axes, both verified by reading the chart
templates directly, not inferred:

1. **Wrong secret name.** `charts/kronos/templates/backend/deployment.yaml:41-43`
   and the four Celery deployment templates
   (`charts/kronos/templates/celery/deployment-{beat,fast,plaso,index}.yaml`,
   each around line 45-55) all do `envFrom: - secretRef: { name:
   kronos-app-secrets }`. README's command creates a secret literally named
   `kronos-secrets` — a different object. Result: `CreateContainerConfigError:
   secret "kronos-app-secrets" not found`, every backend/celery pod stuck,
   never Ready.
2. **Wrong key casing.** `envFrom.secretRef` maps each secret data key
   directly to an environment variable name. The backend's config
   (`src/config.py`, pydantic-settings, per `README.md:176-194`'s own env
   var table) expects `DATABASE_URL`, `KEYCLOAK_CLIENT_SECRET`,
   `VAULT_TOKEN` (upper-snake-case). README's snippet creates keys
   `database-url`, `keycloak-client-secret`, `vault-token` (kebab-case) —
   even under the right secret name these would never populate the
   settings pydantic reads, and per `README.md:177` "Secrets have no
   defaults — a missing required var fails fast at startup," so the
   backend would exit immediately rather than silently misconfigure.

By contrast, **`docs/deployment.md:123-136`'s "Combined app secrets"
snippet is correct** — right secret name (`kronos-app-secrets`), right
key casing (`DATABASE_URL`, `MINIO_ACCESS_KEY`, `OPENSEARCH_PASSWORD`,
`KEYCLOAK_CLIENT_SECRET`, `VAULT_TOKEN`, `CELERY_BROKER_URL`,
`CELERY_RESULT_BACKEND`, etc.), matching the templates exactly. So this
isn't "the feature is unfinished" — a correct version of this exact
instruction already exists in the repo, in a doc most newcomers are less
likely to read first (`README.md` is the entry point; `docs/deployment.md`
is one click deeper). **Severity: P1 for a newcomer following only the
README** — the chart cannot come up at all with README's literal
instructions.

(Separately, and lower stakes: `docs/deployment.md:96-121` also has the
operator create `kronos-postgres-secret`/`kronos-redis-secret`/
`kronos-keycloak-secret`/`kronos-minio-secret`/`kronos-opensearch-secret`.
I traced `existingSecret:` usage across every template
(`grep -rn existingSecret charts/kronos/templates/`) and only
`kronos-postgres-secret` and `kronos-redis-secret` are actually consumed —
by the bundled Bitnami `postgresql`/`redis` subcharts
(`charts/kronos/values.yaml:222-246`). The keycloak/opensearch/minio
`existingSecret` values in `values.yaml:86,108,153` are not wired into any
template's env/volume — real credentials for those three services flow
entirely through the one combined `kronos-app-secrets`. Creating the three
extra secrets per `deployment.md` is harmless but unnecessary; not a
blocker, just a documentation-vs-implementation drift worth a cleanup PR.)

### 2.2 New, higher-severity finding: the Helm chart has no migration mechanism at all

`docs/DATABASE_MIGRATIONS.md:14-19` states, as the binding current design
(Milestone V4): **"`create_tables()` no longer runs at app/worker boot"** —
Alembic's `db-migrate` one-shot container is now the *only* thing that
creates schema, and it is wired as a `depends_on:
condition: service_completed_successfully` gate in front of every
app/worker container in `docker-compose.dev.yml` (confirmed directly,
`docker/docker-compose.dev.yml:472-482,598-600,674-676,728-730,772-774`)
and, per `DATABASE_MIGRATIONS.md:111-113`, the same pattern in
`docker-compose.test.yml`/`docker-compose.prod.yml`.

**`charts/kronos/templates/` has no equivalent.** I listed every template
file (`find charts/kronos -type f`) and grepped the whole chart for
`migrat|alembic` — zero hits, in templates or `values.yaml`. There is no
Job, no initContainer, nothing that runs `alembic upgrade head` before the
backend/celery Deployments start. `DATABASE_MIGRATIONS.md:113` itself
already flags this as a known gap ("if this deployment ever moves to an
orchestrator without that primitive... that ordering guarantee must be
re-created there — see `charts/kronos/` if/when a Helm migration hook is
added" — it has not been added). `docs/deployment.md`'s own Kubernetes
"Post-Install Checklist" (`docs/deployment.md:161-172`) never mentions
migrations either.

Concretely, for a newcomer following README's "recommended" Helm path: a
fresh install produces an **empty Postgres schema**, and the backend pods
report **Ready** (the liveness/readiness probe hits `/healthz`, which
`charts/kronos/templates/backend/deployment.yaml:44-47`'s own comment
confirms is "deliberately dependency-free — no DB/OpenSearch check" so a
downstream outage never kills a healthy pod) while every real request that
touches Postgres fails. This is worse than a crash-loop: `kubectl get pods`
looks healthy, and the first sign of trouble is a 500 on the first API
call a user makes. **Severity: P0 for the Helm path specifically** — the
chart cannot function at all on a fresh cluster without a manual,
undocumented `kubectl exec`-and-run-Alembic-by-hand workaround that no doc
describes.

### 2.3 Actively WRONG (not just incomplete): README's local frontend-dev instructions no longer match the real dev stack

This is the most severe finding in this whole review, because it's not a
missing step — it directly contradicts what a newcomer would be told to
do, and it's provably stale (not a judgment call).

- `README.md:98-107` ("Service endpoints (dev)") lists **`Keycloak |
  http://localhost:8080`**.
- `README.md:121-127` tells the reader to `cp frontend/.env.example
  frontend/.env` with the inline comment **"points at localhost:8080 /
  :8000"**, then `npm run dev` → `http://localhost:5173`.
- The real, currently-committed `frontend/.env.example` (read directly,
  full contents) is:
  ```
  VITE_KEYCLOAK_URL=https://kronos.local:8443
  VITE_KEYCLOAK_REALM=kronos
  VITE_KEYCLOAK_CLIENT_ID=kronos-frontend
  VITE_API_URL=https://kronos.local
  VITE_OPENSEARCH_DASHBOARDS_ORIGIN=https://kronos.local:5602
  ```
  Not `localhost:8080`/`:8000` — `kronos.local` over HTTPS on non-default
  ports. The README's own inline comment on the exact line it tells you to
  run is wrong about what the file it names actually contains.
- This isn't just a stale comment — the whole stack was changed to make
  `kronos.local` the **only** working origin. `docker/docker-compose.dev.yml:251`
  pins `KC_HOSTNAME: https://kronos.local:8443` on the `keycloak` service
  (no `localhost` alternative — Keycloak issues every login-flow URL,
  including the login form's own POST target, from this single pinned
  value, per the extensive comment at `frontend/src/keycloak.ts:17-45`
  documenting the real, reproduced "Restart login cookie not found" bug
  this fixed). More decisively:
  `docker/keycloak/kronos-realm.json:71-76` — the `kronos-frontend`
  client's `redirectUris` is `["https://kronos.local/*"]` and `webOrigins`
  is `["https://kronos.local"]`. **`http://localhost:5173` is not a
  registered redirect URI or web origin at all** — Keycloak will reject
  the OIDC redirect outright (`invalid_redirect_uri`) regardless of what
  `frontend/.env` says, so even fixing the `.env` comment doesn't rescue
  README's literal instructions; the frontend dev server has to be
  accessed via `https://kronos.local` (which itself requires the separate
  `docker/nginx/nginx-lan-https.conf.template` TLS-termination addon and a
  trusted `step-ca` root, per `docs/lan-dev-access.md`), not
  `localhost:5173` directly.
- **This is provably a regression, not a documentation gap that was never
  filled in.** `git log` shows `README.md` was last touched at `bc77664`
  (2026-07-02), while the commits that introduced this requirement landed
  three weeks later: `06e243939` "feat(docker): LAN HTTPS access via nginx
  TLS termination + reverse proxies" (2026-07-24), `dcf7047` "refactor:
  kronos.local as the sole authorized domain everywhere," and `c173c14`
  "fix(keycloak): allow the LAN HTTPS origin in kronos-frontend's redirect
  URIs" (all after README's last edit). `README.md` never mentions
  `kronos.local` or `docs/lan-dev-access.md` anywhere
  (`grep -n "kronos.local\|lan-dev-access" README.md` → zero hits) — the
  doc simply was not updated when the underlying dev-stack behavior
  changed.

**Severity: P0 for the "try it locally" path.** A newcomer who does
exactly what `README.md`'s "Frontend dev" section says — the *only*
frontend-dev instructions in the primary onboarding doc — gets a frontend
that cannot log in, with no error message pointing at the real cause
(Keycloak just silently rejects the redirect; nothing in the browser UI
says "wrong origin, see docs/lan-dev-access.md"). The correct procedure
exists and is well-documented (`docs/lan-dev-access.md`, itself very
thorough and clearly the product of real, verified work — see its own
`poc/tls_lan_https/` citation), but it is a materially different, more
involved setup (custom DNS entry, TLS cert trust, a `KRONOS_LAN_HOST`
env var, and the `nginx-lan-https` addon) than what the README describes,
and the README does not link to it.

### 2.4 Docker Compose dev path (the actual working path) — mostly accurate, one omission

Separately from the Keycloak-origin issue above: the `db-migrate`
container (§2.2/V4) *is* correctly wired for `make dev`
(`docker-compose.dev.yml`'s `depends_on` chain), so **the plain `docker
compose -f docker/docker-compose.dev.yml up` / `make dev` path itself
still works schema-wise** without any extra step — `db-migrate` runs
automatically as part of `up`, no newcomer action required. Neither
`README.md` nor `docs/deployment.md` mentions `db-migrate` by name at all,
which is a real omission (a newcomer debugging a slow first boot or a
migration failure has no doc pointing them at
`docker compose logs db-migrate` or `make migrate`) but not an *incorrect*
instruction — just an incomplete one. **Severity: P3.**

---

## §3 "10-minute local demo" verdict

**Not realistic today, and the single biggest blocker is §2.3**, not stack
size. The `docker compose up` backend stack itself (14 services) is
heavy but is genuinely automated end-to-end per the docs (env copy →
`make dev` → bucket provisioning script, all three steps documented and,
per §2.4, technically accurate). If evaluation only needs `curl
http://localhost:8000/docs` / the FastAPI OpenAPI UI, or Keycloak's direct
admin console at `http://localhost:8080/admin` (the Keycloak *admin*
console is not origin-restricted the way the application client's login
flow is), a knowledgeable operator could plausibly get *something* running
in 10 minutes.

But for the realistic "evaluator wants to see the actual product UI,"
which is what a SOC/DFIR tool lives or dies on per the task brief: the
browser-facing login path is broken exactly as described in §2.3 unless
the evaluator also, without being told to: (a) discover
`docs/lan-dev-access.md` (not linked from `README.md`), (b) add a
`/etc/hosts` entry, (c) trust a locally-generated `step-ca` root CA in
their browser, and (d) set `KRONOS_LAN_HOST` before bringing the stack up.
None of that is "10 minutes for someone who doesn't already know the
system" — it's a half-day if you start from the README alone, and only
fast if you already know to skip straight to `docs/lan-dev-access.md`
(which itself is clearly written for a "make it available on my LAN"
use case, not framed as "this is now required for local dev too").

**Recommendation (not implemented, out of scope for this assessment):**
either (a) restore a genuinely `localhost`-only dev path (a second Keycloak
client / separate realm config for plain `npm run dev`, if that's judged
safe enough for dev-only use), or (b) rewrite `README.md`'s Quick Start to
make `docs/lan-dev-access.md`'s hosts-file + cert-trust steps the
documented default, not an undocumented prerequisite. Whichever direction
is chosen, the fix is doc/config, not a new feature — the working pieces
already exist in `docs/lan-dev-access.md`.

---

## §4 Re-verified Gap Audit P2 status

| Item | Gap Audit claim | This pass's independent re-verification |
|---|---|---|
| P2-8 (dark mode) | Zero `dark:` classes, not implemented | **Confirmed the grep result, but the finding needs sharpening**: a real, interactive toggle exists (`Layout.tsx:70-79`) and the Tailwind v4 `@variant dark` plumbing is correctly set up (`index.css:1-2`) — but only 2 CSS rules (`index.css:14-26`) actually respond to it, so clicking the toggle produces a visibly broken half-themed page rather than doing nothing. See §1.5. |
| P2-12 (command palette, unified timeline, detection-health dashboard, marketplace UI, usage dashboard, AI-narrative triage) | All confirmed absent via grep | Re-confirmed absent, zero new evidence either direction (`frontend/src/pages` still has exactly the 6 page components enumerated in §1.1). No change. |
| "empty states / first-run experience" (P2 list, flagged unaudited) | Not yet audited | **Now audited (§1.2): substantially implemented and good**, including domain-aware copy on the Timeline and Detections empty states. This is the one item in this table that comes back materially *better* than the Gap Audit's neutral "unaudited" framing suggested it might. |
| Error-boundary / render-crash handling | Not previously called out as a named P2 item | **New finding, not in the Gap Audit**: no `ErrorBoundary` anywhere (§1.3). Recommend adding as a tracked item. |

---

## Summary for the record

- **Analyst persona:** the built flows (cases, evidence upload, detections,
  triage) are more solid than a "PoC-hardening pass, unaudited UX" prior
  might suggest — real empty states, real per-error-code guidance, RBAC-aware
  messaging. The two real gaps are a missing root error boundary (§1.3) and
  a broken-not-absent dark-mode toggle (§1.5); both P2, both cheap to fix.
  No in-app onboarding/guidance exists at all (§1.4).
- **Operator persona:** two P0-severity, actively-wrong (not just
  incomplete) findings: (1) `README.md`'s "recommended" Helm path's own
  secret-creation snippet targets the wrong secret name and wrong key
  casing versus what the chart's templates actually consume (§2.1) — a
  correct version already exists in `docs/deployment.md` but isn't
  README's version; (2) `README.md`'s local frontend-dev instructions are
  now stale by three weeks of real infra changes (`kronos.local`-only
  Keycloak origin) and will not produce a working login if followed
  literally (§2.3) — this is the single biggest blocker to the "10-minute
  local demo" story (§3). A third, P0-for-the-Helm-path-only finding: the
  Helm chart has no migration mechanism at all post-V4's `create_tables()`
  removal, so a fresh Helm install reports healthy pods with an empty,
  broken schema (§2.2).

Document written to `docs/assessments/ux_onboarding_review.md`. No other
files modified.
