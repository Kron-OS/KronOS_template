# C6 · Detection API + triage UI — backend PoC

Verifies `src/external/routes/detections.py` (`GET /api/detections`,
`GET /api/detections/{id}`, `POST /api/detections/{id}/triage`) against the
REAL, already-running dev-stack backend (`docker-kronos-backend-1`, reached
directly at `http://localhost:8000`) using REAL Keycloak-issued JWTs from
REAL PKCE browser logins — never an in-process `TestClient` standing in for
the HTTP boundary, never a hand-minted token.

## Versions pinned

Same live dev stack as C1-C5: PostgreSQL and Keycloak 26.2 as pinned in
`docker-compose.dev.yml`; `fastapi`/`httpx` as pinned in `pyproject.toml`.
No OpenSearch calls at all in this item — by design (see A3 gate).

## Real data used (pre-existing, not created by this PoC)

10 real `Detection` rows in Postgres, left by `poc/detection_finding_sync/`'s
own real run (confirmed directly before writing any route code):

```
docker exec docker-postgres-1 psql -U kronos -d kronos -c \
  "SELECT detection_id, org_id, case_id, triage_state, detector_name FROM detections;"
```

org `kronos-dev` (`482072f5-8086-4815-be03-879cc2eaecb5`), case_id
`1a49dcd0-b6a6-4410-83aa-def7ffc9f9fa`, detector
`kronos-kronos-dev-network-detector`, real rule `1fc0809e-06bf-4de3-ad52-
25e5263b7623` (t1021.001) — one row already `TRUE_POSITIVE` from C4's own
triage exercise, the rest `NEW`. This item builds only the API/UI surface on
top of these — no sync trigger was added (out of scope per the brief: "not
touching OpenSearch/SA at all").

## Real users

Seeded dev users (`docker/keycloak/kronos-realm.json`, org `kronos-dev`):
`case-lead` / `DevCaseLead#2026`, `analyst` / `DevAnalyst#2026`.

Two throwaway users + one throwaway org, created via this repo's own
`scripts/provision_keycloak_org.sh` (the same idempotent script dev/prod/
Helm use) purely to exercise real cross-org isolation and the read-only RBAC
boundary — **created and deleted within this session**, not left behind:

- org `kronos-poc-c6` (`825f35fc-c8f4-4fc0-bc40-f457deb178b6`) + member
  `poc-c6-analyst` / `PocC6Analyst#2026` (role `analyst`) — proves cross-org
  isolation.
- `poc-c6-readonly` / `PocC6ReadOnly#2026` (role `read-only`, org
  `kronos-dev`) — no read-only dev user is seeded by the realm import, so
  one was minted here to prove the triage route's RBAC split for real
  (rather than asserting it from reading `requires_role(...)`'s arguments).

Cleanup commands used (real, run at the end of this session):
```
DELETE /admin/realms/kronos/organizations/825f35fc-c8f4-4fc0-bc40-f457deb178b6  -> 204
DELETE /admin/realms/kronos/users/7a04c4da-116e-4ea7-8c92-4b4f3c460527          -> 204  (poc-c6-analyst)
DELETE /admin/realms/kronos/users/95543648-db4f-4a69-b2ed-18d90103306e         -> 204  (poc-c6-readonly)
```
Confirmed afterward: `GET /admin/realms/kronos/organizations` lists only
`kronos-dev` again. Re-running `run_poc.py` as committed will therefore fail
at the `poc-c6-analyst`/`poc-c6-readonly` logins unless that throwaway
setup is re-created first — this mirrors `poc/multi_tenancy/run_poc.sh`'s
own documented convention ("a record of the exact steps actually run... not
necessarily idempotent re-run automation"), not a bug in this script.

## How the real login works

`poc/auth_flow/auth_helpers.py` (shared with `poc/security_analytics_tenant_
isolation/` and others) does a real PKCE authorization-code login against
the real `kronos-frontend` public SPA client through real `kronos.local`
nginx + Keycloak — the exact client/flow the real browser frontend uses.
`kronos-frontend`'s own `oidc-audience-mapper` (`kronos-backend-audience` in
`docker/keycloak/kronos-realm.json`) puts `kronos-backend` in the token's
`aud`, so the resulting real JWT validates against the backend's real
`KeycloakTokenValidator` unmodified.

Requires the dev stack's step-ca leaf cert for `kronos.local` to be fresh
(24h TTL, no auto-renew — a known, documented operational fact, not a code
bug). Confirmed fresh for this run: `notBefore=2026-07-31T05:08:19Z`.

## Run

```
source ~/venv/bin/activate
python poc/detection_api_triage_ui/run_poc.py
```

## Result: 25 passed, 0 failed (see `output.txt` for the full real captured run)

## What each part proves

- **Part 1 (list + filters)** — real `GET /api/detections` returns the 10
  real rows for `case-lead`'s own org; `triageState=NEW` and `caseId=...`
  query filters are applied for real (not just accepted and ignored);
  `analyst` (a read-tier role) can list too, matching the §1 permission
  matrix's "Search timeline (OS)" row (all four roles read).
- **Part 2 (detail)** — single-detection detail carries the real rule id and
  real ATT&CK tag `attack.t1021.001`; a nonexistent id is a real 404.
- **Part 3 (cross-org isolation, roadmap invariant #3)** — a real second
  login, from a real second org, sees **zero** of `kronos-dev`'s detections
  in the list, gets a real 404 (not 403) reading one by id, and gets a real
  404 (not 403) attempting to triage one — org existence is never leaked,
  and the attempt provably did not mutate the target's state.
- **Part 4 (real triage transitions, roadmap invariant #4)** — a real
  `NEW -> INVESTIGATING` transition via the HTTP API, re-read from a fresh
  `GET` to confirm real persistence (not just the mutation response); an
  illegal `NEW -> TRUE_POSITIVE` (skipping `INVESTIGATING`) is a real 409 —
  not the framework's generic 500 — and provably does not mutate state; a
  terminal `TRUE_POSITIVE` detection rejects re-transition (no reopen
  loophole), also 409.
- **Part 5 (RBAC split)** — a real `read-only` login can list and read
  detail (200) but gets a real 403 attempting to triage — the route split
  decided for this item (read: all four roles; triage: org-admin/case-lead/
  analyst, mirroring the §1 matrix's "Upload evidence" row) is proven
  against the real dependency, not just asserted from the route source.

## Design decisions and why

- **No sync-trigger endpoint added.** The brief scopes this item to the API/
  UI surface over C4's already-synced `Detection` rows ("building on top of
  C4's Postgres-backed Detection entity, not touching OpenSearch/SA at all,
  which is the whole point of the A3-gate-driven design"). Triggering
  `DetectionSyncService` (e.g. a beat task or an admin endpoint) is a real,
  open gap for a future item — flagged here, not silently filled in-scope.
- **Filtering/pagination done in the route, not the repository.** Mirrors
  `cases.py`'s `list_case_evidence` idiom exactly: stream all matching rows
  from `DetectionRepository` (`stream_by_org`/`stream_by_case`, both
  already-existing ABC methods — no repository change needed), filter by
  `triage_state` in Python, then slice for pagination. Adding a new filter
  dimension later (e.g. `attack_tags`) is one more predicate in the list
  comprehension — additive, no schema/ABC change.
- **404, not 403, for cross-org/nonexistent.** `get_detection` and
  `DetectionTriageService.transition` both scope their own lookup by
  `tenant.org_id`; a miss (wrong org or truly nonexistent) is indistinguishable
  by design, matching `cases.py`/`evidence.py`'s existing idiom and roadmap
  invariant #3's non-leaking requirement.
- **Read routes: all four roles. Triage: org-admin/case-lead/analyst only.**
  Detections are read-scoped like OpenSearch timeline search (§1 matrix: all
  four roles read), but triage is a real analytical judgment call — treated
  like "Upload evidence" (org-admin/case-lead/analyst, not read-only), not
  like case management (which excludes analyst too). Verified for real in
  Part 5, not assumed.
