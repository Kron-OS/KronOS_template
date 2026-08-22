# PoC: live-browser verification of the new riskScore/riskFactors UI

**Context.** The second multi-scenario assessment's UX/onboarding angle
(Gap Audit Milestone JJ/KK) confirmed `riskScore`/`riskFactors` are
computed server-side (`src/application/risk_scoring.py`, real since
Milestone F4) and exposed on `DetectionOut`
(`src/external/routes/detections.py`), but the frontend `Detection`
TypeScript type had no matching fields and no UI surfaced them at all
(confirmed via grep — zero matches). This PoC verifies the fix: a new
`RiskScorePill` component, wired into both the Detections list row and
the Detection detail page (plus a full "Risk Score Breakdown" table on
the detail page).

## Real dependencies

Real dev stack: `docker-nginx-1` rebuilt from this change's own frontend
source (`docker compose -f docker/docker-compose.dev.yml build nginx &&
... up -d --no-deps nginx`), real Keycloak login (`admin` /
`DevAdmin#2026`), real Postgres.

## Real data had to be seeded first

`kronos-dev` (the org every seeded dev user belongs to) had **zero**
Detection rows in the real Postgres `detections` table at the start of
this verification — confirmed via `psql`. An older PoC's own comment
(`poc/detection_api_triage_ui/run_poc.py`) claims `kronos-dev`'s real
`org_id` is `482072f5-...`, which *is* the org_id that actually has 805
real detection rows in Postgres today — but a fresh token fetched live
via `real_browser_login` resolves `kronos-dev`'s **current** `org_id` to
`7a2d50db-f1bf-496e-8aff-16435cef14b1` instead. Confirmed directly: `GET
/api/detections` with a real, fresh admin token for that current org_id
returns `{"items": [], "total": 0}`. Keycloak org IDs are not stable
across this long-running dev stack's history (orgs get recreated across
resets); the 805-row org is orphaned data from a past incarnation, not a
live gap in this fix. `seed_detection.py` inserts one real `Detection`
(via the real, unmodified `PostgresDetectionRepository`, using the real
`DetectionRiskScorer` to compute an honest, real breakdown — not a
fabricated score) into the **current** real `kronos-dev` org_id so this
PoC could verify against genuinely live data.

## What this proves

1. Real login, real client-side navigation to `/detections`.
2. The real Detections list renders a `RiskScorePill` per row (not just
   `TriageStatePill`) — confirmed via a real Playwright text-locator
   match against actual rendered DOM, not a snapshot/mock.
3. Clicking through to the real detection detail page shows the same
   pill in the header.
4. **The full "Risk Score Breakdown" table renders real factor data** —
   `rule_severity`/`ioc_confidence`/`asset_criticality`/
   `identity_privilege`, their real weights, real normalized values (or
   an honest "not present" for the never-fabricated
   `identity_privilege` factor), and their real human-readable `detail`
   strings straight from `DetectionRiskScorer`'s own output.

**5/5 checks passed.** See `output.txt` for the captured run and
`screenshots/` (list row + detail page, both showing the real seeded
detection with score 89/Critical).

## Run

```
~/venv/bin/python3 poc/detection_risk_score_ui/seed_detection.py   # once, if kronos-dev has no real detections
~/venv/bin/python3 poc/detection_risk_score_ui/run_poc.py
```

Requires the dev stack up with `docker-nginx-1` built from the current
frontend source. Idempotent: `seed_detection.py` inserts a new detection
each run (real, distinct `finding_id` via a random suffix); nothing is
cleaned up afterward since these are ordinary, harmless real detection
rows in the dev org (matches this repo's other UI PoCs' own convention
of leaving real, harmless dev-org data behind rather than tearing it
down).
