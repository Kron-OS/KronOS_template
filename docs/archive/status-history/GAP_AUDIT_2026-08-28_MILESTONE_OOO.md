# Gap Audit — Milestone OOO (2026-08-29)

**Scope:** Milestone NNN's own recommendation — give
`cross-tenant-isolation.spec.ts` the same run-it-first treatment before
wiring it into CI. This is a real, cautionary account of how a phantom
Keycloak bug can look completely convincing before the actual (much
simpler) cause is found — worth reading in full before repeating any of
this debugging, not just the summary.

---

## What actually happened

Running `cross-tenant-isolation.spec.ts` against a freshly-built isolated
test-stack (same technique as every prior milestone) produced a real
failure: org B's fresh throwaway user, seeded by `SecondOrgSeeder`
(→ `seed_second_org.py`), failed to log in with "Invalid username or
password" — even though the script's own log showed the user being
created successfully seconds earlier.

**The investigation that followed (documented so it isn't repeated):**
direct Admin REST queries confirmed the user was genuinely absent
moments after creation. A tight polling loop showed it vanishing within
~1 second. A faithful, byte-for-byte reproduction script (same
`httpx.Client`, same call sequence, same timing) — run standalone —
**did not** reproduce it; the user persisted through 2.5s of polling
with no issue. Five real, back-to-back runs of the *actual*
`seed_second_org.py` script, however, showed the "vanishing" 5/5 times.
Admin event logging was enabled to try to catch a deletion event in real
time — none was ever recorded, for either the creation or any
deletion. A version of the reproduction that explicitly closed the
`httpx.Client` before a separate process checked (matching the real
script's structure exactly) *still* did not reproduce it.

**The actual cause, found by printing the module's own resolved
constant**: `seed_second_org.py` never received the
`KRONOS_E2E_KEYCLOAK_URL` override its sibling script
(`seed_detection.py`) got in Milestone NNN. Every invocation during this
investigation was silently hitting `http://localhost:8080` — the **real,
live dev stack's** Keycloak, not the isolated test-stack instance on
`:18080` the env var was supposed to redirect it to. Every "creation"
succeeded, for real, against the wrong Keycloak instance; every
"verification check" queried the *right* (isolated) instance, which
never had the entity — indistinguishable, from the outside, from
"Keycloak silently deletes users it just created." There was no
Keycloak bug, no race condition, no async cache-invalidation quirk —
just one script missing an override its own sibling already had.

**Real, unplanned consequence**: this cost several real writes (orgs +
throwaway users) on the **live dev stack's Keycloak** — a shared
resource this initiative has a standing rule never to touch with
unscoped ad hoc commands. Cleaned up correctly: not via a fresh delete
command, but by importing `seed_second_org.py`'s own
`cleanup_stale_fixtures()` function and calling it against the dev
stack directly — the real, scoped mechanism the script itself already
provides for exactly this cleanup, per this initiative's own established
rule (Cycle 4 lesson). Confirmed clean afterward: only `admin`/`analyst`/
`case-lead` and the real `kronos-dev` org remain.

## The fix

One line, matching the exact pattern already used in `seed_detection.py`:

```python
KEYCLOAK_INTERNAL_URL = os.environ.get("KRONOS_E2E_KEYCLOAK_URL", "http://localhost:8080")
```

No behavior change for any existing dev-stack run (default unchanged).

## Verification (CLAUDE.md §F)

With the fix applied and the env var correctly taking effect (confirmed
by importing the module and printing the resolved constant before
trusting it again):

1. `cross-tenant-isolation.spec.ts` alone against the isolated
   test-stack — **passed** (real fresh org + user created on the
   *correct* instance, real 404 enforcement confirmed, org A's case
   title confirmed absent from org B's rendered DOM).
2. All five now-relevant specs together (`login`, `evidence-upload`,
   `detection-triage`, `detection-triage-race`,
   `cross-tenant-isolation`) — **5 passed**. (First combined attempt
   caught a second, unrelated, self-inflicted gap: this milestone's own
   local verification override file hadn't published Postgres's host
   port, since the prior cycle's override — reused as a starting point —
   only needed Keycloak published. Fixed the override, not the product;
   noted here only because it's a real trap when reusing a prior
   cycle's local-verification file instead of building one fresh for
   what the current cycle actually needs.)

Isolated stack torn down (`down -v --remove-orphans` + built-image
cleanup); live dev stack confirmed clean of fixture debris (Keycloak
realm state checked directly) and its containers confirmed untouched
throughout (`docker ps`, 15 containers, unchanged before/after).

## Status

All five of `frontend/e2e/`'s specs that don't require dev-stack-only
tooling are now wired into `frontend-e2e-smoke`, CI-verified together.
Only `evidence-retry.spec.ts` remains unwired, for the real, previously
documented reason (Milestone LLL): it uses `DevStackFaultInjector`,
deliberately hardened to only ever target the real dev stack's own
container.

## The actual lesson (worth repeating, not just filing away)

**When local multi-stack-host verification behavior looks exactly like
a bug in a third-party system (Keycloak, in this case), check your own
environment/config plumbing — especially anything env-var-driven added
recently to a *sibling* file — before spending real time investigating
the third party.** The single fastest diagnostic in this entire
investigation, and the one that should have been reached for first, was
`python3 -c "import seed_second_org; print(seed_second_org.KEYCLOAK_INTERNAL_URL)"`
— confirming what URL a script is *actually* about to use, before
trusting any environment variable was applied. Everything before that
point (admin event log inspection, faithful reproduction scripts,
tight polling loops) was real, honest debugging effort, but aimed at
the wrong system.

## Recommendation for the next cycle

1. `evidence-retry.spec.ts` needs a real design decision for
   test-stack-aware fault injection (carried over from Milestone LLL/NNN
   — not yet started).
2. Otherwise, `security-stack` also booting `kronos-backend`, a
   permanent concurrent-`/auth/refresh` regression spec, or
   `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain open per Milestone
   LLL's own still-standing recommendations. With all viable existing
   specs now CI-wired, the next cycle may be a good point to shift from
   "wire the next spec" to one of these broader items, or to a fresh
   multi-scenario subagent assessment (per this initiative's own cycle
   instructions) now that a meaningful chunk of new implementation has
   landed across Milestones JJJ-OOO.
